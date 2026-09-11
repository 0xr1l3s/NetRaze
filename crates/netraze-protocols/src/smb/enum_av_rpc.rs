//! AV/EDR enumeration via SCM service probes and named pipe detection —
//! pure Rust.
//!
//! Phase F of the cross-platform portage plan. Replaces the Windows-only
//! `OpenSCManagerW`/`OpenServiceW` + `FindFirstFileW` implementation (and
//! its `stubs/enum_av.rs` `NOT_PORTED` stub) with the same two-phase
//! detection over DCE/RPC SCMR and SMB2 `query_directory` on IPC$:
//!
//! 1. **SCM phase** — for every product × service name in the database,
//!    `ROpenServiceW(SERVICE_QUERY_STATUS)`: error 1060 means absent, other
//!    errors are skipped, success means the service is installed. On a
//!    successful open, `RQueryServiceStatus` additionally reports `running`
//!    (the Windows impl only checked existence — the RPC path gets the
//!    state for free).
//! 2. **Pipe phase** — SMB2 `query_directory` on `\\host\IPC$` with pattern
//!    `*` (exactly what the Windows impl's `FindFirstFileW` did under the
//!    hood) matched against the database's pipe globs. Any failure skips
//!    the phase silently — pipe listing is best-effort on every platform.
//!
//! Inspired by NetExec's enum_av module (credit: @an0n_r0, @mpgn_x64).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use netraze_dcerpc::channel::RpcChannel;
use netraze_dcerpc::interfaces::scmr;

use super::connection::SmbCredential;
use super::rpc::{bind_svcctl_over_smb, connect_session, host_only};
use super::smb2::Smb2Session;

/// Result for a single detected AV/EDR product.
#[derive(Debug, Clone)]
pub struct AvProduct {
    pub name: String,
    pub installed: bool,
    pub running: bool,
}

impl AvProduct {
    pub fn status_label(&self) -> &'static str {
        match (self.installed, self.running) {
            (true, true) => "INSTALLED and RUNNING",
            (true, false) => "INSTALLED",
            (false, true) => "RUNNING",
            (false, false) => "",
        }
    }

    /// Format as "Name|STATUS" for serialization.
    pub fn to_line(&self) -> String {
        format!("{}|{}", self.name, self.status_label())
    }
}

/// Full result of an AV enumeration.
pub struct EnumAvResult {
    pub products: Vec<AvProduct>,
    pub errors: Vec<String>,
}

/// Enumerate AV/EDR products on a remote host.
///
/// The RPC path authenticates itself — no shared IPC$ mount. `None`
/// credentials can't drive the NTLMSSP bind, so they surface as an error
/// entry instead of a silent empty result.
pub async fn enum_av(target: &str, credential: Option<&SmbCredential>) -> EnumAvResult {
    let mut errors = Vec::new();

    let cred = match credential {
        Some(c) => c,
        None => {
            return EnumAvResult {
                products: Vec::new(),
                errors: vec!["enum_av requires a credential".into()],
            };
        }
    };

    let host = host_only(target);
    let session = match connect_session(target, cred) {
        Ok(s) => s,
        Err(e) => {
            return EnumAvResult {
                products: Vec::new(),
                errors: vec![format!("session setup: {e}")],
            };
        }
    };
    let session = Arc::new(Mutex::new(session));
    let tree = match session.lock() {
        Ok(mut s) => s.tree_connect(&host, "IPC$"),
        Err(e) => {
            return EnumAvResult {
                products: Vec::new(),
                errors: vec![format!("session mutex poisoned: {e}")],
            };
        }
    };
    let ipc = match tree {
        Ok(tid) => tid,
        Err(e) => {
            return EnumAvResult {
                products: Vec::new(),
                errors: vec![format!("tree_connect IPC$: {e}")],
            };
        }
    };

    let mut product_map: HashMap<String, AvProduct> = HashMap::new();

    // Phase 1: service existence probes via SCMR.
    match bind_svcctl_over_smb(session.clone(), ipc, cred).await {
        Ok(mut ch) => match query_services_on_channel(&mut ch).await {
            Ok(found) => {
                for (product_name, _svc_name, running) in found {
                    let entry = product_map
                        .entry(product_name.clone())
                        .or_insert(AvProduct {
                            name: product_name,
                            installed: false,
                            running: false,
                        });
                    entry.installed = true;
                    entry.running |= running;
                }
            }
            Err(e) => errors.push(format!("SCM query: {e}")),
        },
        Err(e) => errors.push(format!("SCMR bind: {e}")),
    }

    // Phase 2: running detection via named pipes on IPC$.
    // Directory listing on IPC$ is not supported by every server (Samba
    // refuses it) — best-effort, skip silently, exactly like the Windows
    // impl's FindFirstFileW fallback.
    match list_pipes(&session, &host).await {
        Ok(pipes) => {
            for (product_name, _pipe) in match_pipes(&pipes) {
                let entry = product_map
                    .entry(product_name.clone())
                    .or_insert(AvProduct {
                        name: product_name,
                        installed: false,
                        running: false,
                    });
                entry.running = true;
            }
        }
        Err(_) => { /* Pipe listing not supported on this target — skip */ }
    }

    if let Ok(mut s) = session.lock() {
        s.logoff();
    }

    let mut products: Vec<AvProduct> = product_map.into_values().collect();
    products.sort_by(|a, b| a.name.cmp(&b.name));

    EnumAvResult { products, errors }
}

// ---------- Service detection via SCMR ----------

/// Probe every database service name with `ROpenServiceW` on an already
/// bound svcctl channel.
///
/// Returns `(product, service, running)` triples; `running` comes from
/// `RQueryServiceStatus` on the open handle (service exists ⇒ at least
/// installed). Error 1060 (does not exist) is the expected "absent" answer;
/// every other error skips the probe silently — same tolerance as the
/// Windows impl's `OpenServiceW` ignore arm.
async fn query_services_on_channel(
    ch: &mut RpcChannel,
) -> Result<Vec<(String, String, bool)>, String> {
    // ROpenSCManagerW — Impacket 'DUMMY\0' machine name (same precedent as
    // the other SCMR orchestrators).
    let stub = scmr::encode_ropen_sc_manager_w_request(
        Some("DUMMY\0"),
        Some("ServicesActive\0"),
        scmr::SC_MANAGER_ACCESS,
    );
    let resp = ch
        .call(scmr::Opnum::ROpenSCManagerW as u16, &stub)
        .await
        .map_err(|e| format!("ROpenSCManagerW: {e}"))?;
    let (scm, status) = scmr::decode_ropen_sc_manager_w_response(&resp)
        .map_err(|e| format!("decode ROpenSCManagerW: {e}"))?;
    if status != 0 {
        return Err(format!("ROpenSCManagerW failed with status 0x{status:08x}"));
    }

    let mut found = Vec::new();
    for product in AV_PRODUCTS {
        for svc_name in product.services {
            let stub = scmr::encode_ropen_service_w_request(
                &scm,
                &format!("{svc_name}\0"),
                scmr::SERVICE_QUERY_STATUS,
            );
            let resp = match ch.call(scmr::Opnum::ROpenServiceW as u16, &stub).await {
                Ok(r) => r,
                Err(_) => continue, // transport hiccup — skip this probe
            };
            let (svc, status) = match scmr::decode_ropen_service_w_response(&resp) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if status != 0 {
                // 1060 = ERROR_SERVICE_DOES_NOT_EXIST (the expected
                // "absent"); anything else (access denied, …) — skip.
                continue;
            }

            // Exists → installed; query its state for `running`.
            let mut running = false;
            let stub = scmr::encode_rquery_service_status_request(&svc);
            if let Ok(resp) = ch
                .call(scmr::Opnum::RQueryServiceStatus as u16, &stub)
                .await
            {
                if let Ok((info, 0)) = scmr::decode_rquery_service_status_response(&resp) {
                    running = info.current_state == scmr::SERVICE_RUNNING;
                }
            }

            found.push((product.name.to_string(), svc_name.to_string(), running));

            let stub = scmr::encode_rclose_service_handle_request(&svc);
            let _ = ch
                .call(scmr::Opnum::RCloseServiceHandle as u16, &stub)
                .await;
        }
    }

    let stub = scmr::encode_rclose_service_handle_request(&scm);
    let _ = ch
        .call(scmr::Opnum::RCloseServiceHandle as u16, &stub)
        .await;

    Ok(found)
}

// ---------- Named pipe detection ----------

/// List every pipe on IPC$ via SMB2 query_directory — the wire equivalent
/// of the Windows impl's `FindFirstFileW(\\host\IPC$\*)`.
async fn list_pipes(session: &Arc<Mutex<Smb2Session>>, host: &str) -> Result<Vec<String>, String> {
    let session = Arc::clone(session);
    let host = host.to_owned();
    let pipes = tokio::task::spawn_blocking(move || {
        let mut s = session
            .lock()
            .map_err(|e| format!("session mutex poisoned: {e}"))?;
        s.query_directory(&host, "IPC$", "", "*")
            .map_err(|e| e.as_str())
    })
    .await
    .map_err(|e| format!("pipe listing task: {e}"))?;
    Ok(pipes?.into_iter().map(|e| e.name).collect())
}

/// Match collected pipe names against known AV/EDR pipe patterns.
fn match_pipes(pipes: &[String]) -> Vec<(String, String)> {
    let mut found = Vec::new();
    for product in AV_PRODUCTS {
        for pattern in product.pipes {
            for pipe in pipes {
                if pipe_matches(pipe, pattern) {
                    found.push((product.name.to_string(), pipe.clone()));
                    break; // one match per pattern is enough
                }
            }
        }
    }
    found
}

/// Simple glob match: supports * as wildcard.
fn pipe_matches(pipe: &str, pattern: &str) -> bool {
    if !pattern.contains('*') {
        return pipe.eq_ignore_ascii_case(pattern);
    }
    // Split on * and check prefix/suffix or contains
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 2 {
        let prefix = parts[0];
        let suffix = parts[1];
        let pipe_lower = pipe.to_ascii_lowercase();
        let prefix_lower = prefix.to_ascii_lowercase();
        let suffix_lower = suffix.to_ascii_lowercase();
        pipe_lower.starts_with(&prefix_lower) && pipe_lower.ends_with(&suffix_lower)
    } else {
        // Fallback: just check if all parts appear in order
        let pipe_lower = pipe.to_ascii_lowercase();
        let mut pos = 0;
        for part in &parts {
            let part_lower = part.to_ascii_lowercase();
            if let Some(idx) = pipe_lower[pos..].find(&part_lower) {
                pos += idx + part_lower.len();
            } else {
                return false;
            }
        }
        true
    }
}

// ---------- AV/EDR product database ----------

struct AvProductDef {
    name: &'static str,
    services: &'static [&'static str],
    pipes: &'static [&'static str],
}

static AV_PRODUCTS: &[AvProductDef] = &[
    AvProductDef {
        name: "Acronis Cyber Protect",
        services: &["AcronisActiveProtectionService"],
        pipes: &[],
    },
    AvProductDef {
        name: "Avast / AVG",
        services: &[
            "AvastWscReporter",
            "aswbIDSAgent",
            "AVGWscReporter",
            "avgbIDSAgent",
        ],
        pipes: &["aswCallbackPipe*", "avgCallbackPipe*"],
    },
    AvProductDef {
        name: "Bitdefender",
        services: &[
            "bdredline_agent",
            "BDAuxSrv",
            "UPDATESRV",
            "VSSERV",
            "bdredline",
            "EPRedline",
            "EPUpdateService",
            "EPSecurityService",
            "EPProtectedService",
            "EPIntegrationService",
        ],
        pipes: &[
            "etw_sensor_pipe_ppl",
            "local\\msgbus\\bd.process.broker.pipe",
        ],
    },
    AvProductDef {
        name: "Carbon Black",
        services: &["Parity"],
        pipes: &[],
    },
    AvProductDef {
        name: "Check Point Endpoint",
        services: &["CPDA", "vsmon", "CPFileAnlyz", "EPClientUIService"],
        pipes: &[],
    },
    AvProductDef {
        name: "Cortex XDR",
        services: &["xdrhealth", "cyserver"],
        pipes: &[],
    },
    AvProductDef {
        name: "CrowdStrike Falcon",
        services: &["CSFalconService"],
        pipes: &["CrowdStrike\\{*"],
    },
    AvProductDef {
        name: "Cybereason",
        services: &["CybereasonActiveProbe", "CybereasonCRS", "CybereasonBlocki"],
        pipes: &[
            "CybereasonAPConsoleMinionHostIpc_*",
            "CybereasonAPServerProxyIpc_*",
        ],
    },
    AvProductDef {
        name: "Elastic EDR",
        services: &["Elastic Agent", "ElasticEndpoint"],
        pipes: &["ElasticEndpointServiceComms-*", "elastic-agent-system"],
    },
    AvProductDef {
        name: "ESET",
        services: &[
            "ekm",
            "epfw",
            "epfwlwf",
            "epfwwfp",
            "EraAgentSvc",
            "ERAAgent",
            "efwd",
            "ehttpsrv",
        ],
        pipes: &["nod_scriptmon_pipe"],
    },
    AvProductDef {
        name: "FortiClient",
        services: &["FA_Scheduler", "FCT_SecSvr"],
        pipes: &["FortiClient_DBLogDaemon", "FC_*"],
    },
    AvProductDef {
        name: "FortiEDR",
        services: &["FortiEDR Collector Service"],
        pipes: &[],
    },
    AvProductDef {
        name: "G DATA Security",
        services: &["AVKWCtl", "AVKProxy", "GDScan"],
        pipes: &["exploitProtectionIPC"],
    },
    AvProductDef {
        name: "HarfangLab EDR",
        services: &[
            "hurukai",
            "Hurukai agent",
            "HarfangLab Hurukai agent",
            "hurukai-av",
            "hurukai-ui",
        ],
        pipes: &["hurukai-control", "hurukai-servicing", "hurukai-amsi"],
    },
    AvProductDef {
        name: "Ivanti Security",
        services: &["STAgent$Shavlik Protect", "STDispatch$Shavlik Protect"],
        pipes: &[],
    },
    AvProductDef {
        name: "Kaseya Agent",
        services: &["KAENDKSAASC*", "KAKSAASC*"],
        pipes: &["kaseyaUserKSA*", "kaseyaAgentKSA*"],
    },
    AvProductDef {
        name: "Kaspersky",
        services: &["kavfsslp", "KAVFS", "KAVFSGT", "klnagent"],
        pipes: &["Exploit_Blocker"],
    },
    AvProductDef {
        name: "Malwarebytes",
        services: &["MBAMService", "MBEndpointAgent"],
        pipes: &["MBLG", "MBEA2_R", "MBEA2_W"],
    },
    AvProductDef {
        name: "Panda Adaptive Defense",
        services: &["PandaAetherAgent", "PSUAService", "NanoServiceMain"],
        pipes: &["NNS_API_IPC_SRV_ENDPOINT", "PSANMSrvcPpal"],
    },
    AvProductDef {
        name: "Rapid7 Insight",
        services: &["ir_agent"],
        pipes: &[],
    },
    AvProductDef {
        name: "SentinelOne",
        services: &[
            "SentinelAgent",
            "SentinelStaticEngine",
            "LogProcessorService",
        ],
        pipes: &[
            "SentinelAgentWorkerCert.*",
            "DFIScanner.Etw.*",
            "DFIScanner.Inline.*",
        ],
    },
    AvProductDef {
        name: "Sophos Intercept X",
        services: &[
            "SntpService",
            "Sophos Endpoint Defense Service",
            "Sophos File Scanner Service",
            "Sophos Health Service",
            "Sophos Live Query",
            "Sophos Managed Threat Response",
            "Sophos MCS Agent",
            "Sophos MCS Client",
            "Sophos System Protection Service",
        ],
        pipes: &[
            "SophosUI",
            "SophosEventStore",
            "sophos_deviceencryption",
            "sophoslivequery_*",
        ],
    },
    AvProductDef {
        name: "Symantec Endpoint Protection",
        services: &["SepMasterService", "SepScanService", "SNAC"],
        pipes: &[],
    },
    AvProductDef {
        name: "Trellix / McAfee EDR",
        services: &[
            "McAfee Endpoint Security Platform Service",
            "mfemactl",
            "mfemms",
            "mfefire",
            "masvc",
            "macmnsvc",
            "mfetp",
            "mfewc",
            "mfeaack",
        ],
        pipes: &[
            "TrellixEDR_Pipe_*",
            "mfemactl_*",
            "mfefire_*",
            "McAfeeAgent_Pipe_*",
            "mfetp_*",
        ],
    },
    AvProductDef {
        name: "Trend Micro",
        services: &[
            "Trend Micro Endpoint Basecamp",
            "TMBMServer",
            "Trend Micro Web Service Communicator",
            "TMiACAgentSvc",
            "CETASvc",
            "iVPAgent",
            "ds_agent",
            "ds_monitor",
            "ds_notifier",
        ],
        pipes: &[
            "IPC_XBC_XBC_AGENT_PIPE_*",
            "iacagent_*",
            "OIPC_LWCS_PIPE_*",
            "Log_ServerNamePipe",
            "OIPC_NTRTSCAN_PIPE_*",
        ],
    },
    AvProductDef {
        name: "Windows Defender",
        services: &["WinDefend", "Sense", "WdNisSvc"],
        pipes: &[],
    },
    AvProductDef {
        name: "WithSecure Elements",
        services: &[
            "fsdevcon",
            "fshoster",
            "fsnethoster",
            "fsulhoster",
            "fsulnethoster",
            "fsulprothoster",
            "wsulavprohoster",
        ],
        pipes: &["FS_CCFIPC_*"],
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_exact_match_is_case_insensitive() {
        assert!(pipe_matches("etw_sensor_pipe_ppl", "etw_sensor_pipe_ppl"));
        assert!(pipe_matches("ETW_Sensor_Pipe_PPL", "etw_sensor_pipe_ppl"));
        assert!(!pipe_matches("etw_sensor_pipe_pplx", "etw_sensor_pipe_ppl"));
    }

    #[test]
    fn glob_single_star_prefix_suffix() {
        // CrowdStrike's backslash pattern, the trickiest entry.
        assert!(pipe_matches("CrowdStrike\\{abc-123}", "CrowdStrike\\{*"));
        assert!(pipe_matches("crowdstrike\\{xyz}", "CrowdStrike\\{*"));
        assert!(!pipe_matches("CrowdStrike", "CrowdStrike\\{*"));
        assert!(!pipe_matches("FooCrowdStrike\\{x}", "CrowdStrike\\{*"));
    }

    #[test]
    fn glob_star_only_matches_anything() {
        assert!(pipe_matches("anything", "*"));
    }

    #[test]
    fn glob_middle_star() {
        // Two '*'s → the in-order-contains fallback path.
        assert!(pipe_matches(
            "CybereasonAPConsoleMinionHostIpc_42",
            "CybereasonAPConsole*_*"
        ));
        assert!(pipe_matches("a-b-c", "a*b*c"));
        assert!(!pipe_matches("a-c", "a*b*c"));
    }

    #[test]
    fn match_pipes_finds_products_from_pipe_list() {
        let pipes: Vec<String> = vec![
            "srvsvc".into(),
            "CrowdStrike\\{deadbeef}".into(),
            "sophoslivequery_agent1".into(),
            "lsarpc".into(),
        ];
        let found = match_pipes(&pipes);
        let names: Vec<&str> = found.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"CrowdStrike Falcon"));
        assert!(names.contains(&"Sophos Intercept X"));
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn product_db_is_wellformed() {
        for p in AV_PRODUCTS {
            assert!(!p.name.is_empty());
        }
        // Windows Defender must stay in the DB — the common case.
        assert!(AV_PRODUCTS.iter().any(|p| p.name == "Windows Defender"));
    }
}

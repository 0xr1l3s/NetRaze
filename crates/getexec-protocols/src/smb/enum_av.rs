//! AV/EDR enumeration via Windows SCM service queries and named pipe detection.
//!
//! Inspired by NetExec's enum_av module (credit: @an0n_r0, @mpgn_x64).
//! Detects installed and running endpoint protection by:
//! 1. Querying service existence/status via Service Control Manager
//! 2. Listing named pipes on IPC$ to detect running processes

use windows::Win32::Storage::FileSystem::{
    FindClose, FindFirstFileW, FindNextFileW, WIN32_FIND_DATAW,
};
use windows::Win32::System::Services::*;
use windows::core::PCWSTR;

use super::connection::{SmbCredential, connect_ipc};

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn from_wide(s: &[u16]) -> String {
    let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    String::from_utf16_lossy(&s[..end])
}

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
/// Establishes an IPC$ session using the provided credential before querying.
pub fn enum_av(target: &str, credential: Option<&SmbCredential>) -> EnumAvResult {
    let mut errors = Vec::new();

    // Establish WNet session so SCM + pipe listing work
    if let Err(e) = connect_ipc(target, credential) {
        errors.push(format!("IPC$ connect: {e}"));
    }

    let mut product_map: std::collections::HashMap<String, AvProduct> =
        std::collections::HashMap::new();

    // Phase 1: Query services via SCM
    match query_services(target) {
        Ok(found) => {
            for (product_name, _svc_name) in found {
                let entry = product_map
                    .entry(product_name.clone())
                    .or_insert(AvProduct {
                        name: product_name,
                        installed: false,
                        running: false,
                    });
                entry.installed = true;
            }
        }
        Err(e) => errors.push(format!("SCM query: {e}")),
    }

    // Phase 2: Detect running via named pipes on IPC$
    // Note: FindFirstFileW on IPC$ may not work on all targets — this is best-effort.
    match list_pipes(target) {
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
        Err(_) => { /* Pipe listing not supported on this target — skip silently */ }
    }

    let mut products: Vec<AvProduct> = product_map.into_values().collect();
    products.sort_by(|a, b| a.name.cmp(&b.name));

    EnumAvResult { products, errors }
}

// ---------- Service detection via SCM ----------

fn query_services(target: &str) -> Result<Vec<(String, String)>, String> {
    let target_w = wide(&format!("\\\\{target}"));
    let scm = unsafe { OpenSCManagerW(PCWSTR(target_w.as_ptr()), None, SC_MANAGER_CONNECT) }
        .map_err(|e| format!("OpenSCManager: {e}"))?;

    let mut found = Vec::new();

    for product in AV_PRODUCTS {
        for svc_name in product.services {
            let svc_w = wide(svc_name);
            let svc = unsafe { OpenServiceW(scm, PCWSTR(svc_w.as_ptr()), SERVICE_QUERY_STATUS) };
            match svc {
                Ok(handle) => {
                    // Service exists → installed
                    found.push((product.name.to_string(), svc_name.to_string()));
                    unsafe {
                        let _ = CloseServiceHandle(handle);
                    }
                }
                Err(_) => {
                    // Service doesn't exist or access denied — skip
                }
            }
        }
    }

    unsafe {
        let _ = CloseServiceHandle(scm);
    }
    Ok(found)
}

// ---------- Named pipe detection ----------

fn list_pipes(target: &str) -> Result<Vec<String>, String> {
    let search_path = format!("\\\\{}\\IPC$\\*", target);
    let search_w = wide(&search_path);
    let mut find_data = WIN32_FIND_DATAW::default();

    let handle = unsafe { FindFirstFileW(PCWSTR(search_w.as_ptr()), &mut find_data) };
    let handle = match handle {
        Ok(h) => h,
        Err(e) => return Err(format!("FindFirstFileW IPC$: {e}")),
    };

    let mut pipes = Vec::new();
    loop {
        let name = from_wide(&find_data.cFileName);
        if !name.is_empty() && name != "." && name != ".." {
            pipes.push(name);
        }
        if unsafe { FindNextFileW(handle, &mut find_data) }.is_err() {
            break;
        }
    }
    unsafe {
        let _ = FindClose(handle);
    }
    Ok(pipes)
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

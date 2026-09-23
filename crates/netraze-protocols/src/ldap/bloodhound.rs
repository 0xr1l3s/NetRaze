//! BloodHound Community Edition collection over NetRaze's LDAP transport.
//!
//! RustHound-CE owns the CE object model and relationship parser. NetRaze owns
//! connection establishment, NTLM SASL protection, LDAP framing, paging, and
//! referral policy. This module is the narrow adapter between those layers.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use rusthound_ce::api::ADResults;
use rusthound_ce::args::{CollectionMethod, Options};
use rusthound_ce::json::maker::common::{make_a_zip, write_json_files};
use rusthound_ce::prepare_results_from_source;
use rusthound_ce::transport::ldap::LdapSearchEntry;
use rusthound_ce::utils::date::return_current_fulldate;
use thiserror::Error;

use super::controls::{security_descriptor_flags_control, show_deleted_control};
use super::{
    LdapAuthentication, LdapClient, LdapClientConfig, LdapEntry, LdapError, SearchOutcome,
};

const BLOODHOUND_ATTRIBUTES: &[&str] = &[
    "*",
    "nTSecurityDescriptor",
    "msDS-User-Account-Control-Computed",
];
const SCHEMA_ATTRIBUTES: &[&str] = &["objectClass", "name", "schemaIDGUID"];

/// Ordered LDAP records ready for the RustHound-CE parser.
///
/// Schema records precede the domain object because ACE parsing resolves
/// property GUIDs through the schema map and principal parsing needs the
/// domain SID before processing other objects.
struct EntryCollection {
    entries: Vec<LdapSearchEntry>,
    referrals: Vec<String>,
    domain: String,
}

/// Files produced by a BloodHound Community Edition collection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BloodHoundCeArtifacts {
    /// DNS domain discovered from RootDSE.
    pub domain: String,
    /// Number of LDAP records presented to the CE parser, including schema records.
    pub ldap_entry_count: usize,
    /// Number of graph objects written across all JSON collections.
    pub exported_object_count: usize,
    /// Per-collection object counts, including collections with zero objects.
    pub collection_counts: BTreeMap<String, usize>,
    /// Loose schema-v6 JSON documents. Empty collections do not create files.
    pub json_files: Vec<PathBuf>,
    /// ZIP archive containing the same non-empty JSON collections.
    pub zip_file: PathBuf,
    /// Referrals reported by the LDAP server. NetRaze never follows them automatically.
    pub referrals: Vec<String>,
}

/// Output settings for a BloodHound Community Edition export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BloodHoundCeExportOptions {
    pub output_directory: PathBuf,
}

impl BloodHoundCeExportOptions {
    #[must_use]
    pub fn new(output_directory: impl Into<PathBuf>) -> Self {
        Self {
            output_directory: output_directory.into(),
        }
    }
}

/// Coarse-grained progress updates suitable for CLI and desktop front ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BloodHoundCeProgress {
    Connecting,
    Binding,
    Collecting,
    Parsing { ldap_entries: usize },
    Writing { graph_objects: usize },
    Complete { json_files: usize },
}

#[derive(Debug, Error)]
pub enum BloodHoundCeError {
    #[error(transparent)]
    Ldap(#[from] LdapError),
    #[error("BloodHound CE parser failed: {0}")]
    Parser(String),
    #[error("BloodHound CE output failed: {0}")]
    Output(String),
    #[error("BloodHound CE worker failed: {0}")]
    Worker(String),
    #[error("BloodHound CE output path is not valid Unicode: {0}")]
    NonUnicodeOutputPath(PathBuf),
}

/// Collect LDAP graph data and write both loose JSON and a ZIP archive.
pub async fn collect_and_export_ce(
    config: LdapClientConfig,
    authentication: LdapAuthentication,
    options: BloodHoundCeExportOptions,
) -> Result<BloodHoundCeArtifacts, BloodHoundCeError> {
    collect_and_export_ce_with_progress(config, authentication, options, |_| {}).await
}

/// Collect and export while reporting non-secret progress milestones.
pub async fn collect_and_export_ce_with_progress<F>(
    config: LdapClientConfig,
    authentication: LdapAuthentication,
    options: BloodHoundCeExportOptions,
    mut progress: F,
) -> Result<BloodHoundCeArtifacts, BloodHoundCeError>
where
    F: FnMut(BloodHoundCeProgress) + Send,
{
    progress(BloodHoundCeProgress::Connecting);
    let mut client = LdapClient::connect(config).await?;

    progress(BloodHoundCeProgress::Binding);
    let bind_result = match authentication {
        LdapAuthentication::Anonymous => client.bind_anonymous().await,
        LdapAuthentication::Ntlm {
            username,
            domain,
            credential,
        } => client.bind_ntlm(&username, &domain, credential).await,
    };
    if let Err(error) = bind_result {
        let _ = client.unbind().await;
        return Err(error.into());
    }

    progress(BloodHoundCeProgress::Collecting);
    let collection = collect_entries(&mut client).await;
    let _ = client.unbind().await;
    let collection = collection?;
    let ldap_entry_count = collection.entries.len();
    let parser_options = parser_options(&collection.domain, &options.output_directory)?;

    progress(BloodHoundCeProgress::Parsing {
        ldap_entries: ldap_entry_count,
    });
    let parser_options_for_worker = parser_options.clone();
    let runtime = tokio::runtime::Handle::current();
    let results = tokio::task::spawn_blocking(move || {
        runtime
            .block_on(prepare_results_from_source(
                collection.entries,
                &parser_options_for_worker,
                Some(ldap_entry_count),
            ))
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| BloodHoundCeError::Worker(error.to_string()))?
    .map_err(BloodHoundCeError::Parser)?;

    let exported_object_count = exported_object_count(&results);
    progress(BloodHoundCeProgress::Writing {
        graph_objects: exported_object_count,
    });
    let domain = collection.domain;
    let referrals = collection.referrals;
    let artifacts = tokio::task::spawn_blocking(move || {
        write_results(
            results,
            &parser_options,
            domain,
            referrals,
            ldap_entry_count,
        )
    })
    .await
    .map_err(|error| BloodHoundCeError::Worker(error.to_string()))??;

    progress(BloodHoundCeProgress::Complete {
        json_files: artifacts.json_files.len(),
    });
    Ok(artifacts)
}

/// Collect the schema, default domain, and Configuration naming contexts.
///
/// RustHound parses Configuration objects into container ACL relationships and,
/// when present, AD CS graph objects. Schema records must remain first and the
/// domain root must precede every other principal-bearing object.
async fn collect_entries(client: &mut LdapClient) -> Result<EntryCollection, LdapError> {
    let root = client.root_dse().await?;
    let default_context = required_root_attribute(&root, "defaultNamingContext")?;
    let schema_context = required_root_attribute(&root, "schemaNamingContext")?;
    let configuration_context = required_root_attribute(&root, "configurationNamingContext")?;
    let controls = [security_descriptor_flags_control(), show_deleted_control()];

    let schema = client
        .search_with_controls(
            &schema_context,
            "(|(objectClass=attributeSchema)(objectClass=classSchema))",
            SCHEMA_ATTRIBUTES,
            &controls,
        )
        .await?;
    let directory = client
        .search_with_controls(
            &default_context,
            "(objectClass=*)",
            BLOODHOUND_ATTRIBUTES,
            &controls,
        )
        .await?;
    let configuration = client
        .search_with_controls(
            &configuration_context,
            "(objectClass=*)",
            BLOODHOUND_ATTRIBUTES,
            &controls,
        )
        .await?;

    assemble_entries(&default_context, schema, directory, configuration)
}

fn assemble_entries(
    default_context: &str,
    schema: SearchOutcome,
    directory: SearchOutcome,
    configuration: SearchOutcome,
) -> Result<EntryCollection, LdapError> {
    let mut domain_entry = None;
    let mut remaining = Vec::with_capacity(directory.entries.len().saturating_sub(1));
    for entry in directory.entries {
        if domain_entry.is_none() && entry.dn.eq_ignore_ascii_case(default_context) {
            domain_entry = Some(entry);
        } else {
            remaining.push(entry);
        }
    }
    let domain_entry = domain_entry.ok_or_else(|| {
        LdapError::UnexpectedOperation(format!(
            "BloodHound collection omitted the domain root {default_context}"
        ))
    })?;

    let mut entries = Vec::with_capacity(
        schema.entries.len() + remaining.len() + configuration.entries.len() + 1,
    );
    entries.extend(schema.entries.into_iter().map(adapt_entry));
    entries.push(adapt_entry(domain_entry));
    entries.extend(remaining.into_iter().map(adapt_entry));
    entries.extend(configuration.entries.into_iter().map(adapt_entry));

    let mut referrals = schema.referrals;
    referrals.extend(directory.referrals);
    referrals.extend(configuration.referrals);
    referrals.sort();
    referrals.dedup();

    Ok(EntryCollection {
        entries,
        referrals,
        domain: domain_from_naming_context(default_context)?,
    })
}

fn parser_options(domain: &str, output_directory: &Path) -> Result<Options, BloodHoundCeError> {
    let path = output_directory
        .to_str()
        .ok_or_else(|| BloodHoundCeError::NonUnicodeOutputPath(output_directory.to_path_buf()))?;
    Ok(Options {
        domain: domain.to_owned(),
        username: None,
        password: None,
        ldapfqdn: None,
        ip: None,
        port: None,
        name_server: String::new(),
        path: path.to_owned(),
        collection_method: CollectionMethod::LdapOnly,
        ldaps: false,
        dns_tcp: false,
        fqdn_resolver: false,
        hashes: None,
        kerberos: false,
        pfx: None,
        pfx_pass: None,
        crt: None,
        key: None,
        zip: true,
        verbose: log::LevelFilter::Info,
        ldap_filter: "(objectClass=*)".to_owned(),
        cache: false,
        cache_buffer_size: 1000,
        resume: false,
    })
}

fn write_results(
    results: ADResults,
    parser_options: &Options,
    domain: String,
    referrals: Vec<String>,
    ldap_entry_count: usize,
) -> Result<BloodHoundCeArtifacts, BloodHoundCeError> {
    let timestamp = return_current_fulldate();
    let filename_domain = filename_domain(&domain);
    let output_directory = PathBuf::from(&parser_options.path);
    let collection_counts = collection_counts(&results);
    let exported_object_count = collection_counts.values().sum();
    let json_files = collection_counts
        .iter()
        .filter(|(_, count)| **count > 0)
        .map(|(kind, _)| {
            output_directory.join(format!("{timestamp}_{filename_domain}_{kind}.json"))
        })
        .collect();

    write_json_files(&timestamp, &filename_domain, parser_options, &results)
        .map_err(|error| BloodHoundCeError::Output(error.to_string()))?;
    let zip_file = make_a_zip(&timestamp, &filename_domain, &parser_options.path, &results)
        .map(PathBuf::from)
        .map_err(|error| BloodHoundCeError::Output(error.to_string()))?;

    Ok(BloodHoundCeArtifacts {
        domain,
        ldap_entry_count,
        exported_object_count,
        collection_counts,
        json_files,
        zip_file,
        referrals,
    })
}

fn collection_counts(results: &ADResults) -> BTreeMap<String, usize> {
    BTreeMap::from([
        ("aiacas".to_owned(), results.aiacas.len()),
        ("certtemplates".to_owned(), results.certtemplates.len()),
        ("computers".to_owned(), results.computers.len()),
        ("containers".to_owned(), results.containers.len()),
        ("domains".to_owned(), results.domains.len()),
        ("enterprisecas".to_owned(), results.enterprisecas.len()),
        ("gpos".to_owned(), results.gpos.len()),
        ("groups".to_owned(), results.groups.len()),
        (
            "issuancepolicies".to_owned(),
            results.issuancepolicies.len(),
        ),
        ("ntauthstores".to_owned(), results.ntauthstores.len()),
        ("ous".to_owned(), results.ous.len()),
        ("rootcas".to_owned(), results.rootcas.len()),
        ("users".to_owned(), results.users.len()),
    ])
}

fn exported_object_count(results: &ADResults) -> usize {
    collection_counts(results).values().sum()
}

fn filename_domain(domain: &str) -> String {
    let sanitized = domain
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    sanitized.trim_matches('-').to_owned()
}

fn required_root_attribute(root: &LdapEntry, name: &str) -> Result<String, LdapError> {
    root.first_utf8(name)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| LdapError::UnexpectedOperation(format!("RootDSE omitted required {name}")))
}

fn domain_from_naming_context(context: &str) -> Result<String, LdapError> {
    let labels = context
        .split(',')
        .filter_map(|component| {
            let (kind, value) = component.trim().split_once('=')?;
            kind.eq_ignore_ascii_case("DC")
                .then(|| value.trim().to_owned())
        })
        .filter(|label| !label.is_empty())
        .collect::<Vec<_>>();
    if labels.is_empty() {
        return Err(LdapError::UnexpectedOperation(format!(
            "cannot derive a DNS domain from naming context {context}"
        )));
    }
    Ok(labels.join("."))
}

fn adapt_entry(entry: LdapEntry) -> LdapSearchEntry {
    let mut attrs = HashMap::new();
    let mut bin_attrs = HashMap::new();
    for (name, values) in entry.attributes {
        if is_binary_attribute(&name) {
            bin_attrs.insert(name, values);
            continue;
        }

        let mut text = Vec::with_capacity(values.len());
        let mut binary = Vec::new();
        for value in values {
            match String::from_utf8(value) {
                Ok(value) => text.push(value),
                Err(error) => binary.push(error.into_bytes()),
            }
        }
        if !text.is_empty() {
            attrs.insert(name.clone(), text);
        }
        if !binary.is_empty() {
            bin_attrs.insert(name, binary);
        }
    }
    LdapSearchEntry {
        dn: entry.dn,
        attrs,
        bin_attrs,
    }
}

fn is_binary_attribute(name: &str) -> bool {
    [
        "objectGUID",
        "objectSid",
        "nTSecurityDescriptor",
        "sIDHistory",
        "securityIdentifier",
        "schemaIDGUID",
        "msDS-AllowedToActOnBehalfOfOtherIdentity",
        "msDS-GroupMSAMembership",
        "userCertificate",
        "cACertificate",
    ]
    .iter()
    .any(|binary| name.eq_ignore_ascii_case(binary))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn derives_dns_domain_from_default_naming_context() {
        assert_eq!(
            domain_from_naming_context("DC=example,DC=test").unwrap(),
            "example.test"
        );
        assert!(domain_from_naming_context("CN=Configuration").is_err());
    }

    #[test]
    fn adapter_preserves_required_binary_attributes() {
        let entry = LdapEntry {
            dn: "CN=Alice,DC=example,DC=test".to_owned(),
            attributes: BTreeMap::from([
                ("sAMAccountName".to_owned(), vec![b"alice".to_vec()]),
                ("objectSid".to_owned(), vec![vec![1, 2, 3, 4]]),
                ("objectGUID".to_owned(), vec![b"valid utf8 bytes".to_vec()]),
            ]),
        };
        let adapted = adapt_entry(entry);
        assert_eq!(adapted.attrs["sAMAccountName"], ["alice"]);
        assert_eq!(adapted.bin_attrs["objectSid"], [vec![1, 2, 3, 4]]);
        assert_eq!(
            adapted.bin_attrs["objectGUID"],
            [b"valid utf8 bytes".to_vec()]
        );
    }

    #[test]
    fn invalid_unknown_values_remain_binary() {
        let entry = LdapEntry {
            dn: String::new(),
            attributes: BTreeMap::from([("custom".to_owned(), vec![vec![0xff, 0x00]])]),
        };
        let adapted = adapt_entry(entry);
        assert!(!adapted.attrs.contains_key("custom"));
        assert_eq!(adapted.bin_attrs["custom"], [vec![0xff, 0x00]]);
    }

    #[test]
    fn parser_is_restricted_to_ldap_only_collection() {
        let options = parser_options("example.test", Path::new("output")).unwrap();
        assert_eq!(options.domain, "example.test");
        assert_eq!(options.collection_method, CollectionMethod::LdapOnly);
        assert!(!options.ldaps);
        assert!(!options.kerberos);
        assert!(options.username.is_none());
        assert!(options.password.is_none());
    }

    #[test]
    fn assembly_keeps_parser_order_and_configuration_objects() {
        fn entry(dn: &str) -> LdapEntry {
            LdapEntry {
                dn: dn.to_owned(),
                attributes: BTreeMap::new(),
            }
        }

        let default_context = "DC=example,DC=test";
        let collection = assemble_entries(
            default_context,
            SearchOutcome {
                entries: vec![entry(
                    "CN=User,CN=Schema,CN=Configuration,DC=example,DC=test",
                )],
                referrals: vec!["ldap://schema".to_owned()],
            },
            SearchOutcome {
                entries: vec![entry("CN=Alice,DC=example,DC=test"), entry(default_context)],
                referrals: vec!["ldap://domain".to_owned()],
            },
            SearchOutcome {
                entries: vec![entry(
                    "CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=test",
                )],
                referrals: vec![
                    "ldap://configuration".to_owned(),
                    "ldap://domain".to_owned(),
                ],
            },
        )
        .unwrap();

        assert_eq!(
            collection
                .entries
                .iter()
                .map(|entry| entry.dn.as_str())
                .collect::<Vec<_>>(),
            [
                "CN=User,CN=Schema,CN=Configuration,DC=example,DC=test",
                default_context,
                "CN=Alice,DC=example,DC=test",
                "CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=test",
            ]
        );
        assert_eq!(
            collection.referrals,
            ["ldap://configuration", "ldap://domain", "ldap://schema"]
        );
    }

    #[test]
    fn output_names_cannot_escape_the_selected_directory() {
        assert_eq!(filename_domain("EXAMPLE.TEST"), "example-test");
        assert_eq!(filename_domain("../Example/Test"), "example-test");
    }

    #[test]
    fn collection_manifest_tracks_ce_schema_types() {
        let mut results = ADResults::default();
        results.users.push(Default::default());
        results.groups.push(Default::default());
        let counts = collection_counts(&results);
        assert_eq!(counts["users"], 1);
        assert_eq!(counts["groups"], 1);
        assert_eq!(counts["computers"], 0);
        assert_eq!(counts.len(), 13);
        assert_eq!(exported_object_count(&results), 2);
    }

    #[test]
    fn writer_emits_schema_v6_json_and_zip() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let output = std::env::temp_dir().join(format!(
            "netraze-bloodhound-ce-{}-{nonce}",
            std::process::id()
        ));
        let options = parser_options("example.test", &output).unwrap();
        let mut results = ADResults::default();
        results.users.push(Default::default());

        let artifacts =
            write_results(results, &options, "example.test".to_owned(), Vec::new(), 1).unwrap();

        assert_eq!(artifacts.json_files.len(), 1);
        let json = std::fs::read_to_string(&artifacts.json_files[0]).unwrap();
        assert!(json.contains("\"type\":\"users\""));
        assert!(json.contains("\"version\":6"));
        assert!(artifacts.zip_file.is_file());
        assert!(std::fs::metadata(&artifacts.zip_file).unwrap().len() > 0);
        std::fs::remove_dir_all(output).unwrap();
    }
}

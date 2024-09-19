use std::str::FromStr;

use packageurl::PackageUrl;

use crate::common::guac_url;
use guac::client::intrinsic::certify_vuln::{CertifyVulnSpec, ScanMetadata};
use guac::client::intrinsic::package::IDorPkgInput;
use guac::client::intrinsic::vulnerability::{IDorVulnerabilityInput, VulnerabilityInputSpec, VulnerabilitySpec};
use guac::client::GuacClient;

mod common;

#[tokio::test]
async fn certify_vuln() -> Result<(), anyhow::Error> {
    let client = GuacClient::new(&guac_url());

    let pkg = PackageUrl::from_str("pkg:rpm/trustification-NOT-certify-vuln@0.3.0")?;

    let _ = client.intrinsic().ingest_package(&pkg.clone().into()).await?;

    let pkg = PackageUrl::from_str("pkg:rpm/trustification-certify-vuln@0.3.0")?;

    let _ = client.intrinsic().ingest_package(&pkg.clone().into()).await?;

    client
        .intrinsic()
        .ingest_vulnerability(&IDorVulnerabilityInput {
            vulnerability_input: Some(VulnerabilityInputSpec {
                r#type: "osv".to_string(),
                vulnerability_id: "ghsa-eieio-42".to_string(),
            }),
            vulnerability_type_id: None,
            vulnerability_node_id: None,
        })
        .await?;

    client
        .intrinsic()
        .ingest_certify_vuln(
            &IDorPkgInput {
                package_type_id: None,
                package_namespace_id: None,
                package_name_id: None,
                package_version_id: None,
                package_input: Some(pkg.clone().into()),
            },
            &IDorVulnerabilityInput {
                vulnerability_input: Some(VulnerabilityInputSpec {
                    r#type: "osv".to_string(),
                    vulnerability_id: "ghsa-eieio-42".to_string(),
                }),
                vulnerability_type_id: None,
                vulnerability_node_id: None,
            },
            &ScanMetadata {
                db_uri: "test-db-uri".to_string(),
                db_version: "test-db-version".to_string(),
                scanner_uri: "test-scanner-uri".to_string(),
                scanner_version: "test-scanner-version".to_string(),
                time_scanned: Default::default(),
                origin: "test-vuln-origin".to_string(),
                collector: "test-vuln-collector".to_string(),
                document_ref: "test-document-ref".to_string(),
            },
        )
        .await?;

    let result = client
        .intrinsic()
        .certify_vuln(&CertifyVulnSpec {
            vulnerability: Some(VulnerabilitySpec {
                vulnerability_id: Some("ghsa-eieio-42".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        })
        .await?;

    assert_eq!(1, result.len());

    Ok(())
}

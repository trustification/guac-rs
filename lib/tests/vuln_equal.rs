use guac::client::intrinsic::vuln_equal::{VulnEqualInputSpec, VulnEqualSpec};
use guac::client::intrinsic::vulnerability::{VulnerabilityInputSpec, VulnerabilitySpec};
use guac::client::GuacClient;

use crate::common::guac_url;

mod common;

#[tokio::test]
async fn vuln_equal() -> Result<(), anyhow::Error> {
    let client = GuacClient::new(&guac_url());

    let vuln_ghsa = VulnerabilityInputSpec {
        r#type: "test-vuln-equal".to_string(),
        vulnerability_id: "GHSA-7rjr-3q55-vv33".to_string(),
    };

    client.intrinsic().ingest_vulnerability(&vuln_ghsa).await?;

    let vuln_cve = VulnerabilityInputSpec {
        r#type: "test-vuln-equal".to_string(),
        vulnerability_id: "CVE-2021-45046".to_string(),
    };

    client.intrinsic().ingest_vulnerability(&vuln_cve).await?;

    let vuln_osv = VulnerabilityInputSpec {
        r#type: "test-vuln-equal".to_string(),
        vulnerability_id: "OSV-2021-45046".to_string(),
    };

    client.intrinsic().ingest_vulnerability(&vuln_osv).await?;

    client
        .intrinsic()
        .ingest_vuln_equal(
            &vuln_ghsa,
            &vuln_cve,
            &VulnEqualInputSpec {
                justification: "test-justification".to_string(),
                origin: "test-origin".to_string(),
                collector: "test-collector".to_string(),
            },
        )
        .await?;

    client
        .intrinsic()
        .ingest_vuln_equal(
            &vuln_osv,
            &vuln_cve,
            &VulnEqualInputSpec {
                justification: "test-justification".to_string(),
                origin: "test-origin".to_string(),
                collector: "test-collector".to_string(),
            },
        )
        .await?;

    let _found_vulns = client
        .intrinsic()
        .vuln_equal(&VulnEqualSpec {
            vulnerabilities: Some(vec![VulnerabilitySpec {
                vulnerability_id: Some("OSV-2021-45046".to_string()),
                ..Default::default()
            }]),
            ..Default::default()
        })
        .await?;

    let _found_vulns = client
        .intrinsic()
        .vuln_equal(&VulnEqualSpec {
            vulnerabilities: Some(vec![VulnerabilitySpec {
                vulnerability_id: Some("CVE-2021-45046".to_string()),
                ..Default::default()
            }]),
            ..Default::default()
        })
        .await?;

    let found_vulns = client.semantic().vulnerabilities("OSV-2021-45046").await?;

    assert_eq!(3, found_vulns.len());

    Ok(())
}

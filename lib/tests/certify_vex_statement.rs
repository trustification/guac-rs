use std::str::FromStr;

use packageurl::PackageUrl;

use guac::client::intrinsic::certify_vex_statement::{
    CertifyVexStatementSpec, VexJustification, VexStatementInputSpec, VexStatus,
};
use guac::client::intrinsic::vulnerability::VulnerabilityInputSpec;
use guac::client::GuacClient;

use crate::common::guac_url;

mod common;

#[tokio::test]
async fn certify_vex_statement() -> Result<(), anyhow::Error> {
    let client = GuacClient::new(&guac_url());

    let package = PackageUrl::from_str("pkg:maven/com/foo/vexed@1.2.3")?;

    client.intrinsic().ingest_package(&package.clone().into()).await?;

    let vuln = VulnerabilityInputSpec {
        r#type: "cve".to_string(),
        vulnerability_id: "CVE-123".to_string(),
    };

    client.intrinsic().ingest_vulnerability(&vuln).await?;

    let vex = VexStatementInputSpec {
        status: VexStatus::Affected,
        vex_justification: VexJustification::NotProvided,
        statement: "it's affected".to_string(),
        status_notes: "according to OSV".to_string(),
        known_since: Default::default(),
        origin: "test-vex-origin".to_string(),
        collector: "test-vex-collector".to_string(),
    };

    client
        .intrinsic()
        .ingest_certify_vex_statement(&package.clone().into(), &vuln, &vex)
        .await?;

    let results = client
        .intrinsic()
        .certify_vex_statement(&CertifyVexStatementSpec {
            subject: Some(package.clone().into()),
            ..Default::default()
        })
        .await?;

    assert_eq!(1, results.len());

    Ok(())
}

use guac::client::intrinsic::vuln_metadata::{
    VulnerabilityMetadataInputSpec, VulnerabilityMetadataSpec, VulnerabilityScoreType,
};
use guac::client::intrinsic::vulnerability::VulnerabilityInputSpec;
use guac::client::GuacClient;

use crate::common::guac_url;

mod common;

#[tokio::test]
async fn vuln_metadata() -> Result<(), anyhow::Error> {
    let client = GuacClient::new(&guac_url());

    let vuln = VulnerabilityInputSpec {
        r#type: "test-vuln".to_string(),
        vulnerability_id: "ghsa-osv-cve-44".to_string(),
    };

    client.intrinsic().ingest_vulnerability(&vuln).await?;

    let metadata = VulnerabilityMetadataInputSpec {
        score_type: VulnerabilityScoreType::CVSSv3,
        score_value: 4.2,
        timestamp: Default::default(),
        origin: "test-origin".to_string(),
        collector: "test-collector".to_string(),
    };

    client
        .intrinsic()
        .ingest_vuln_metadata(&vuln, &metadata)
        .await?;

    let result = client
        .intrinsic()
        .vuln_metadata(&VulnerabilityMetadataSpec {
            vulnerability: Some((&vuln).into()),
            ..Default::default()
        })
        .await?;

    assert_eq!(1, result.len());

    println!("{:#?}", result);

    Ok(())
}

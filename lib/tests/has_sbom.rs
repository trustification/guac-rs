mod common;

use common::GUAC_URL;
use guac::client::intrinsic::has_sbom::HasSBOMInputSpec;
use guac::client::GuacClient;
use packageurl::PackageUrl;
use std::str::FromStr;

#[tokio::test]
async fn has_sbom() -> Result<(), anyhow::Error> {
    let client = GuacClient::new(GUAC_URL);

    let pkg = PackageUrl::from_str("pkg:rpm/trustification-has-sbom@0.3.0")?;

    client
        .intrinsic()
        .ingest_package(&pkg.clone().into())
        .await?;

    client
        .intrinsic()
        .ingest_has_sbom(
            &pkg.clone().into(),
            &HasSBOMInputSpec {
                uri: "test-uri".to_string(),
                algorithm: "test-algo".to_string(),
                digest: "8675309".to_string(),
                download_location: "http://example.com/test-sbom".to_string(),
                origin: "test-origin".to_string(),
                collector: "test-collector".to_string(),
            },
        )
        .await?;

    let result = client.intrinsic().has_sbom(&pkg.into()).await?;

    assert_eq!(1, result.len());
    assert_eq!("8675309", result[0].digest);

    Ok(())
}

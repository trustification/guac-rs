use std::str::FromStr;

use packageurl::PackageUrl;

use guac::client::intrinsic::certify_good::{CertifyGoodInputSpec, CertifyGoodSpec};
use guac::client::intrinsic::PackageSourceOrArtifact;
use guac::client::intrinsic::PkgMatchType;
use guac::client::GuacClient;

use crate::common::guac_url;

mod common;

#[tokio::test]
async fn certify_good() -> Result<(), anyhow::Error> {
    let client = GuacClient::new(&guac_url());

    let pkg = PackageUrl::from_str("pkg:rpm/trustification-NOT-certify-good@0.3.0")?;

    let _ = client.intrinsic().ingest_package(&pkg.clone().into()).await?;

    let pkg = PackageUrl::from_str("pkg:rpm/trustification-certify-good@0.3.0")?;

    let _ = client.intrinsic().ingest_package(&pkg.clone().into()).await?;

    let _ = client
        .intrinsic()
        .ingest_certify_good(
            &pkg.clone().into(),
            PkgMatchType::SpecificVersion,
            &CertifyGoodInputSpec {
                justification: "test-justification".to_string(),
                origin: "test-origin".to_string(),
                collector: "test-collector".to_string(),
                known_since: Default::default(),
            },
        )
        .await?;

    let result = client
        .intrinsic()
        .certify_good(&CertifyGoodSpec {
            subject: Some(pkg.clone().into()),
            ..Default::default()
        })
        .await?;

    assert_eq!(1, result.len());

    let certify_good = &result[0];

    assert!(matches!(
        certify_good.subject,
        PackageSourceOrArtifact::Package( ref inner )
        if inner.matches_exact(pkg)
    ));

    assert_eq!("test-justification", certify_good.justification);
    assert_eq!("test-origin", certify_good.origin);
    assert_eq!("test-collector", certify_good.collector);

    Ok(())
}

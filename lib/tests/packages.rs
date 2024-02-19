use std::str::FromStr;

use packageurl::PackageUrl;

use guac::client::GuacClient;

use crate::common::guac_url;

mod common;

#[tokio::test]
async fn ingest_packages() -> Result<(), anyhow::Error> {
    let client = GuacClient::new(&guac_url());

    let pkg_030 = PackageUrl::from_str("pkg:rpm/trustification-test@0.3.0")?;

    let _ = client.intrinsic().ingest_package(&pkg_030.clone().into()).await?;

    let result = client.intrinsic().packages(&pkg_030.clone().into()).await?;
    assert_eq!(1, result.len());
    let purls = result[0].try_as_purls()?;
    assert!(purls.contains(&pkg_030));

    let pkg_031 = PackageUrl::from_str("pkg:rpm/trustification-test@0.3.1")?;

    let _ = client.intrinsic().ingest_package(&pkg_031.clone().into()).await?;

    let result = client.intrinsic().packages(&pkg_031.clone().into()).await?;
    assert_eq!(1, result.len());

    let purls = result[0].try_as_purls()?;
    assert!(purls.contains(&pkg_031));

    Ok(())
}

#[tokio::test]
async fn query_packages() -> Result<(), anyhow::Error> {
    let client = GuacClient::new(&guac_url());

    // ingest 29 versions of the same package.
    for i in 1..30 {
        let pkg = PackageUrl::from_str(format!("pkg:rpm/trustification-test-query@0.3.{}", i).as_str())?;

        let _ = client.intrinsic().ingest_package(&pkg.clone().into()).await?;
    }

    // query packages without a version
    let packages = client
        .intrinsic()
        .packages(&PackageUrl::from_str("pkg:rpm/trustification-test-query")?.into())
        .await?;

    let mut purls = vec![];

    for package in packages {
        for purl in package.try_as_purls()? {
            purls.push(purl)
        }
    }

    // ensure the 29 versions are collected
    assert_eq!(29, purls.len());

    for i in 1..30 {
        let purl = PackageUrl::from_str(format!("pkg:rpm/trustification-test-query@0.3.{}", i).as_str())?;

        // ensure each purl is present
        assert!(purls.contains(&purl))
    }

    Ok(())
}

use std::str::FromStr;

use packageurl::PackageUrl;

use guac::client::intrinsic::is_dependency::{DependencyType, IsDependencyInputSpec, IsDependencySpec};
use guac::client::intrinsic::PkgMatchType;
use guac::client::semantic::ingest::HasDependency;
use guac::client::GuacClient;

use crate::common::guac_url;

mod common;

#[tokio::test]
async fn is_dependency() -> Result<(), anyhow::Error> {
    let client = GuacClient::new(&guac_url());

    let pkg_a = PackageUrl::from_str("pkg:rpm/trustification-pkg-is-dep-A@0.3.0")?;

    let _ = client.intrinsic().ingest_package(&pkg_a.clone().into()).await?;

    let pkg_b = PackageUrl::from_str("pkg:rpm/trustification-pkg-is-dep-B@0.3.0")?;

    let _ = client.intrinsic().ingest_package(&pkg_b.clone().into()).await?;

    let pkg_c = PackageUrl::from_str("pkg:rpm/trustification-pkg-is-dep-C@0.3.0")?;

    let _ = client.intrinsic().ingest_package(&pkg_c.clone().into()).await?;

    client
        .intrinsic()
        .ingest_is_dependency(
            &pkg_a.clone().into(),
            &pkg_b.clone().into(),
            PkgMatchType::SpecificVersion,
            &IsDependencyInputSpec {
                version_range: "".to_string(),
                dependency_type: DependencyType::Direct,
                justification: "dep-justification".to_string(),
                origin: "dep-origin".to_string(),
                collector: "dep-collector".to_string(),
            },
        )
        .await?;

    let result = client
        .intrinsic()
        .is_dependency(&IsDependencySpec {
            package: Some(pkg_a.clone().into()),
            ..Default::default()
        })
        .await?;

    assert_eq!(1, result.len());

    assert!(result[0].package.matches_exact(pkg_a));
    assert!(result[0].dependent_package.matches_exact(pkg_b));

    Ok(())
}

#[tokio::test]
async fn ingest_has_dependency() -> Result<(), anyhow::Error> {
    let client = GuacClient::new(&guac_url());

    let pkg_a = PackageUrl::from_str("pkg:rpm/trustification-semantic-pkg-A@0.3.0")?;
    let pkg_b = PackageUrl::from_str("pkg:rpm/trustification-semantic-pkg-B@0.3.0")?;

    client.semantic().ingest(&pkg_a, &HasDependency::new(&pkg_b)).await?;

    let dependencies = client.semantic().dependencies_of(&pkg_a).await?;

    assert_eq!(1, dependencies.len());
    assert!(dependencies.contains(&pkg_b));

    Ok(())
}

#[tokio::test]
async fn dependencies_of() -> Result<(), anyhow::Error> {
    let client = GuacClient::new(&guac_url());

    let pkg_a = PackageUrl::from_str("pkg:rpm/trustification-pkg-A@0.3.0")?;

    let _ = client.intrinsic().ingest_package(&pkg_a.clone().into()).await?;

    let pkg_b = PackageUrl::from_str("pkg:rpm/trustification-pkg-B@0.3.0")?;

    let _ = client.intrinsic().ingest_package(&pkg_b.clone().into()).await?;

    let pkg_c = PackageUrl::from_str("pkg:rpm/trustification-pkg-C@0.3.0")?;

    let _ = client.intrinsic().ingest_package(&pkg_c.clone().into()).await?;

    client
        .intrinsic()
        .ingest_is_dependency(
            &pkg_a.clone().into(),
            &pkg_b.clone().into(),
            PkgMatchType::SpecificVersion,
            &IsDependencyInputSpec {
                version_range: "".to_string(),
                dependency_type: DependencyType::Direct,
                justification: "dep-justification".to_string(),
                origin: "dep-origin".to_string(),
                collector: "dep-collector".to_string(),
            },
        )
        .await?;

    let dependencies = client.semantic().dependencies_of(&pkg_a).await?;
    assert_eq!(1, dependencies.len());
    assert!(dependencies.contains(&pkg_b));

    let dependents = client.semantic().dependents_of(&pkg_b).await?;
    assert_eq!(1, dependents.len());
    assert!(dependents.contains(&pkg_a));

    Ok(())
}

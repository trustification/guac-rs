use std::str::FromStr;

use packageurl::PackageUrl;

use common::GUAC_URL;
use guac::client::graph::Edge;
use guac::client::intrinsic::certify_vuln::ScanMetadata;
use guac::client::intrinsic::is_dependency::{DependencyType, IsDependencyInputSpec};
use guac::client::intrinsic::vulnerability::VulnerabilityInputSpec;
use guac::client::intrinsic::PkgMatchType;
use guac::client::GuacClient;

mod common;

#[tokio::test]
async fn neighbor() -> Result<(), anyhow::Error> {
    let client = GuacClient::new(GUAC_URL);

    let pkg_a = PackageUrl::from_str("pkg:rpm/trustification-neighbor-a@11.1")?;
    let pkg_b = PackageUrl::from_str("pkg:rpm/trustification-neighbor-b@022.2")?;
    let pkg_c = PackageUrl::from_str("pkg:rpm/trustification-neighbor-c@33.3")?;
    let pkg_d = PackageUrl::from_str("pkg:rpm/trustification-neighbor-d@044.4")?;

    let pkg_a_id = client
        .intrinsic()
        .ingest_package(&pkg_a.clone().into())
        .await?;
    let pkg_b_id = client
        .intrinsic()
        .ingest_package(&pkg_b.clone().into())
        .await?;
    let pkg_c_id = client
        .intrinsic()
        .ingest_package(&pkg_c.clone().into())
        .await?;
    let pkg_d_id = client
        .intrinsic()
        .ingest_package(&pkg_d.clone().into())
        .await?;

    // A -> B
    //   -> C -> D

    let dep_a_b_id = client
        .intrinsic()
        .ingest_is_dependency(
            &pkg_a.clone().into(),
            &pkg_b.clone().into(),
            PkgMatchType::SpecificVersion,
            &IsDependencyInputSpec {
                version_range: "".to_string(),
                dependency_type: DependencyType::Direct,
                justification: "a-b justification".to_string(),
                origin: "test-origin".to_string(),
                collector: "test-collector".to_string(),
            },
        )
        .await?;

    println!("A-B {}", dep_a_b_id);

    let dep_a_c_id = client
        .intrinsic()
        .ingest_is_dependency(
            &pkg_a.clone().into(),
            &pkg_c.clone().into(),
            PkgMatchType::SpecificVersion,
            &IsDependencyInputSpec {
                version_range: "".to_string(),
                dependency_type: DependencyType::Direct,
                justification: "a-c justification".to_string(),
                origin: "test-origin".to_string(),
                collector: "test-collector".to_string(),
            },
        )
        .await?;

    println!("A-C {}", dep_a_c_id);

    let dep_c_d_id = client
        .intrinsic()
        .ingest_is_dependency(
            &pkg_c.clone().into(),
            &pkg_d.clone().into(),
            PkgMatchType::SpecificVersion,
            &IsDependencyInputSpec {
                version_range: "".to_string(),
                dependency_type: DependencyType::Direct,
                justification: "c-d justification".to_string(),
                origin: "test-origin".to_string(),
                collector: "test-collector".to_string(),
            },
        )
        .await?;

    println!("C-D {}", dep_c_d_id);

    client
        .intrinsic()
        .ingest_vulnerability(&VulnerabilityInputSpec {
            r#type: "osv".to_string(),
            vulnerability_id: "ghsa-vuln-a".to_string(),
        })
        .await?;

    let vuln_a = client
        .intrinsic()
        .ingest_certify_vuln(
            &pkg_a.clone().into(),
            &VulnerabilityInputSpec {
                r#type: "osv".to_string(),
                vulnerability_id: "ghsa-vuln-a".to_string(),
            },
            &ScanMetadata {
                db_uri: "test-db-uri".to_string(),
                db_version: "test-db-version".to_string(),
                scanner_uri: "test-scanner-uri".to_string(),
                scanner_version: "test-scanner-version".to_string(),
                time_scanned: Default::default(),
                origin: "test-vuln-origin".to_string(),
                collector: "test-vuln-collector".to_string(),
            },
        )
        .await?;

    client
        .intrinsic()
        .ingest_vulnerability(&VulnerabilityInputSpec {
            r#type: "osv".to_string(),
            vulnerability_id: "ghsa-vuln-d".to_string(),
        })
        .await?;

    let vuln_d = client
        .intrinsic()
        .ingest_certify_vuln(
            &pkg_d.clone().into(),
            &VulnerabilityInputSpec {
                r#type: "osv".to_string(),
                vulnerability_id: "ghsa-vuln-d".to_string(),
            },
            &ScanMetadata {
                db_uri: "test-db-uri".to_string(),
                db_version: "test-db-version".to_string(),
                scanner_uri: "test-scanner-uri".to_string(),
                scanner_version: "test-scanner-version".to_string(),
                time_scanned: Default::default(),
                origin: "test-vuln-origin".to_string(),
                collector: "test-vuln-collector".to_string(),
            },
        )
        .await?;

    //println!("start {}", pkg_a_id);
    let result = client
        .intrinsic()
        .neighbors(
            &pkg_a_id,
            //vec![]
            vec![Edge::PackageIsDependency],
        )
        .await?;

    //println!("{:#?}", result);

    let result = client
        .intrinsic()
        .neighbors(
            &pkg_a_id,
            //vec![]
            vec![Edge::PackageCertifyVuln],
        )
        .await?;

    println!("{:#?}", result);

    Ok(())
}

#[tokio::test]
async fn transitive_dependents() -> Result<(), anyhow::Error> {
    macro_rules! add_dep {
        ($client: ident, $a: literal, $b:literal) => {
            let pkg_a = PackageUrl::from_str($a)?;

            $client
                .intrinsic()
                .ingest_package(&pkg_a.clone().into())
                .await?;

            let pkg_b = PackageUrl::from_str($b)?;

            $client
                .intrinsic()
                .ingest_package(&pkg_b.clone().into())
                .await?;

            $client
                .intrinsic()
                .ingest_is_dependency(
                    &pkg_a.clone().into(),
                    &pkg_b.clone().into(),
                    PkgMatchType::SpecificVersion,
                    &IsDependencyInputSpec {
                        version_range: "".to_string(),
                        dependency_type: DependencyType::Direct,
                        justification: "justification".to_string(),
                        origin: "test-origin".to_string(),
                        collector: "test-collector".to_string(),
                    },
                )
                .await?;
        };
    }

    let client = GuacClient::new(GUAC_URL);

    add_dep!(client, "pkg:rpm/your-app@1.0", "pkg:rpm/log4j@1.0");
    add_dep!(client, "pkg:rpm/myapp@1.0", "pkg:rpm/component-a@1.0");
    add_dep!(client, "pkg:rpm/myapp@1.0", "pkg:rpm/component-b@1.0");
    add_dep!(client, "pkg:rpm/myapp@1.0", "pkg:rpm/component-c@1.0");

    add_dep!(client, "pkg:rpm/component-a@1.0", "pkg:rpm/component-c@1.0");
    add_dep!(client, "pkg:rpm/component-c@1.0", "pkg:rpm/component-d@1.0");
    add_dep!(client, "pkg:rpm/component-a@1.0", "pkg:rpm/component-d@1.0");
    add_dep!(client, "pkg:rpm/component-d@1.0", "pkg:rpm/component-e@1.0");
    add_dep!(client, "pkg:rpm/component-e@1.0", "pkg:rpm/log4j@1.0");

    let paths = client
        .semantic()
        .transitive_dependents_of(&PackageUrl::from_str("pkg:rpm/log4j@1.0")?)
        .await?;

    for path in paths {
        for segment in path {
            print!("{} ", segment.to_string());
        }
        println!()
    }

    Ok(())
}

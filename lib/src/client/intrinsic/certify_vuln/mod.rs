use anyhow::Context;
use chrono::Utc;
use graphql_client::reqwest::post_graphql;

use serde::{Deserialize, Serialize};
use crate::client::Error;
use crate::client::intrinsic::{Id, IntrinsicGuacClient};
use crate::client::intrinsic::package::{Package, PkgInputSpec, PkgSpec};
use crate::client::intrinsic::vulnerability::{Vulnerability, VulnerabilityInputSpec, VulnerabilitySpec};
use self::ingest::IngestCertifyVuln;

pub mod ingest;
pub mod query;

//#[derive(Debug, Serialize, Deserialize)]
type Time = chrono::DateTime<Utc>;

impl IntrinsicGuacClient<'_> {
    pub async fn ingest_certify_vuln(
        &self,
        package: &PkgInputSpec,
        vulnerability: &VulnerabilityInputSpec,
        meta: &ScanMetadataInput,
    ) -> Result<Id, Error> {
        use self::ingest::ingest_certify_vuln;

        let variables = ingest_certify_vuln::Variables {
            package: package.into(),
            vulnerability: vulnerability.into(),
            meta: meta.into(),
        };

        let response_body =
            post_graphql::<IngestCertifyVuln, _>(self.client(), self.url(), variables)
                .await?;

        if let Some(errors) = response_body.errors {
            return Err(Error::GraphQL(errors))
        }

        let data = response_body
            .data
            .ok_or( Error::GraphQL(vec![]))?;

        Ok( data.ingest_certify_vuln.id )
    }


    /*
    pub async fn certify_vuln(
        &self,
        purl: &str,
    ) -> Result<Vec<VulnerabilityResult>, anyhow::Error> {
        use self::query::query_certify_vuln_by_package;

        let pkg = query_certify_vuln_by_package::PkgSpec::try_from(purl)?;
        let variables = query_certify_vuln_by_package::Variables { package: Some(pkg) };
        let response_body = post_graphql::<QueryCertifyVulnByPackage, _>(
            self.client(),
            self.url(),
            variables,
        )
        .await?;
        let response_data = response_body
            .data
            .with_context(|| "No data found in response");
        Ok(response_data?
            .certify_vuln
            .iter()
            .map(|entry| {
                let vulnerability = Vulnerability {
                    //id: entry.id.clone(),
                    ty: entry.vulnerability.type_.clone(),
                    vulnerability_id: entry.vulnerability.vulnerability_i_ds[0].vulnerability_id.clone(),
                };

                let packages = package::vuln2purls(&entry.package);

                VulnerabilityResult {
                    vulnerability,
                    packages,
                }
            })
            .collect())
    }

     */

    /*
    pub async fn get_vulnerabilities(
        &self,
        vuln_id: &str,
    ) -> Result<Vec<VulnerabilityResult>, anyhow::Error> {
        use self::query::query_certify_vuln_by_id;

        let variables = query_certify_vuln_by_id::Variables {
            id: vuln_id.to_string(),
        };
        let response_body =
            post_graphql::<QueryCertifyVulnById, _>(&self.client, self.url.to_owned(), variables)
                .await?;
        let response_data = response_body
            .data
            .with_context(|| "No data found in response");
        Ok(response_data?
            .certify_vuln
            .iter()
            .map(|entry| {
                let vulnerability = Vulnerability {
                    //id: entry.vulnerability.id.clone(),
                    ty: entry.vulnerability.type_.clone(),
                    vulnerability_id: entry.vulnerability.vulnerability_i_ds[0].vulnerability_id.clone(),
                };

                let packages = cve::vuln2purls(&entry.package);
                VulnerabilityResult {
                    vulnerability,
                    packages,
                }
            })
            .collect())
    }
     */
}
/*

pub mod package {

    pub fn vuln2purls(
        pkg: &super::query::query_certify_vuln_by_package::AllCertifyVulnTreePackage,
    ) -> Vec<String> {
        let mut purls = Vec::new();
        let t = &pkg.type_;
        for namespace in pkg.namespaces.iter() {
            for name in namespace.names.iter() {
                for version in name.versions.iter() {
                    let qualifiers = if version.qualifiers.is_empty() {
                        String::new()
                    } else {
                        let mut data: Vec<String> = Vec::new();
                        for entry in version.qualifiers.iter() {
                            data.push(format!("{}={}", entry.key, entry.value));
                        }
                        let data = data.join("&");
                        format!("?{}", data)
                    };
                    let purl = format!(
                        "pkg:{}/{}/{}@{}{}",
                        t, namespace.namespace, name.name, version.version, qualifiers
                    );
                    purls.push(purl);
                }
            }
        }
        purls
    }
}

 */

/*
pub mod cve {
    pub fn vuln2purls(
        pkg: &super::query::query_certify_vuln_by_id::AllCertifyVulnTreePackage,
    ) -> Vec<String> {
        let mut purls = Vec::new();
        let t = &pkg.type_;
        for namespace in pkg.namespaces.iter() {
            for name in namespace.names.iter() {
                for version in name.versions.iter() {
                    let qualifiers = if version.qualifiers.is_empty() {
                        String::new()
                    } else {
                        let mut data: Vec<String> = Vec::new();
                        for entry in version.qualifiers.iter() {
                            data.push(format!("{}={}", entry.key, entry.value));
                        }
                        let data = data.join("&");
                        format!("?{}", data)
                    };
                    let purl = format!(
                        "pkg:{}/{}/{}@{}{}",
                        t, namespace.namespace, name.name, version.version, qualifiers
                    );
                    purls.push(purl);
                }
            }
        }
        purls
    }
}

 */

struct CertifyVuln {
    pub id: String,
    pub package: Package,
    pub vulnerability: Vulnerability,
    pub metadata: ScanMetadata,
}

#[derive(Serialize, Deserialize)]
pub struct ScanMetadata {
    pub db_uri: String,
    pub db_version: String,
    pub scanner_uri: String,
    pub scanner_version: String,
    pub time_scanned: Time,
    pub origin: String,
    pub collector: String,
}

type ScanMetadataInput = ScanMetadata;

struct CertifyVulnSpec {
    pub id: Option<String>,
    pub package: Option<PkgSpec>,
    pub vulnerability: Option<VulnerabilitySpec>,
    pub timeScanned: Option<Time>,
    pub dbUri: Option<String>,
    pub dbVersion: Option<String>,
    pub scannerUri: Option<String>,
    pub scannerVersion: Option<String>,
    pub origin: Option<String>,
    pub collector: Option<String>,

}
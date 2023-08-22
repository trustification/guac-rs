use anyhow::Context;
use chrono::Utc;
use graphql_client::reqwest::post_graphql;

use crate::client::certify_vuln::ingest::IngestCertifyVuln;
use crate::client::certify_vuln::query::{QueryCertifyVulnByPackage};
use crate::client::GuacClient;

use serde::{Deserialize, Serialize};
use crate::client::vulnerability::Vulnerability;

pub mod ingest;
pub mod query;

//#[derive(Debug, Serialize, Deserialize)]
type Time = chrono::DateTime<Utc>;

#[derive(Serialize, Deserialize)]
pub struct VulnerabilityResult {
    pub vulnerability: Vulnerability,
    pub packages: Vec<String>,
}

impl VulnerabilityResult {
    pub fn id(&self) -> String {
        self.vulnerability.id()
    }
}

#[derive(Serialize, Deserialize)]
pub struct Metadata {
    pub db_uri: String,
    pub db_version: String,
    pub scanner_uri: String,
    pub scanner_version: String,
    pub time_scanned: Time,
    pub origin: String,
    pub collector: String,
}

impl GuacClient {
    pub async fn ingest_certify_vuln(
        &self,
        purl: &str,
        vulnerability: Vulnerability,
        meta: Metadata,
    ) -> Result<(), anyhow::Error> {
        use self::ingest::ingest_certify_vuln;

        let pkg = ingest_certify_vuln::PkgInputSpec::try_from(purl)?;
        let variables = ingest_certify_vuln::Variables {
            package: pkg,
            meta: meta.try_into()?,
            vulnerability: vulnerability.try_into()?,
        };

        let response_body =
            post_graphql::<IngestCertifyVuln, _>(&self.client, self.url.to_owned(), variables)
                .await;

        let _ = response_body?
            .data
            .with_context(|| "No data found in response")?;

        Ok(())
    }

    pub async fn certify_vuln(
        &self,
        purl: &str,
    ) -> Result<Vec<VulnerabilityResult>, anyhow::Error> {
        use self::query::query_certify_vuln_by_package;

        let pkg = query_certify_vuln_by_package::PkgSpec::try_from(purl)?;
        let variables = query_certify_vuln_by_package::Variables { package: Some(pkg) };
        let response_body = post_graphql::<QueryCertifyVulnByPackage, _>(
            &self.client,
            self.url.to_owned(),
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

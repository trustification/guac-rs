use std::collections::HashSet;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use anyhow::*;
use chrono::Utc;
use graphql_client::reqwest::post_graphql;
use openvex::Metadata;
use openvex::OpenVex;
use openvex::Statement;
use openvex::Status;
use serde::Deserialize;
use serde::Serialize;

use crate::graphql::dependency::get_dependencies::PkgSpec as DepPkgSpec;
use crate::graphql::dependency::get_dependencies::Variables as DepVariables;
use crate::graphql::mutation::certify_bad::CertifyBadM1;
use crate::graphql::mutation::certify_good::CertifyGoodM1;
use crate::graphql::packages::get_packages::PkgSpec as PkgPkgSpec;
use crate::graphql::packages::get_packages::Variables as PkgVariables;
use crate::graphql::query::certify_bad::CertifyBad;
use crate::graphql::query::certify_good::CertifyGood;
use crate::graphql::{
    cve::{self, certify_vuln_q2, CertifyVulnQ2},
    dependency::{self, GetDependencies},
    dependent::{self, is_dependent::Variables as IsDepVariables, IsDependent},
    mutation::certify_bad::certify_bad_m1,
    mutation::certify_good::certify_good_m1,
    packages::{self, GetPackages},
    query::certify_bad::{certify_bad_q1, CertifyBadQ1},
    query::certify_good::{certify_good_q1, CertifyGoodQ1},
    vuln::{self, certify_vuln_q1, CertifyVulnQ1},
};

#[derive(Clone)]
pub struct GuacClient {
    client: reqwest::Client,
    url: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vulnerability {
    pub cve: Option<String>,
    pub osv: Option<String>,
    pub ghsa: Option<String>,
    pub no_vuln: Option<String>,
    pub packages: Vec<String>,
}

impl GuacClient {
    pub fn new(url: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            url,
        }
    }

    pub async fn certify_vuln(&self, purl: &str) -> Result<Vec<Vulnerability>, anyhow::Error> {
        let pkg = certify_vuln_q1::PkgSpec::try_from(purl)?;
        let variables = certify_vuln_q1::Variables { package: Some(pkg) };
        let response_body =
            post_graphql::<CertifyVulnQ1, _>(&self.client, self.url.to_owned(), variables).await?;
        let response_data = response_body
            .data
            .with_context(|| "No data found in response");
        Ok(response_data?
            .certify_vuln
            .iter()
            .map(|entry| {
                let (cve, osv, ghsa, no_vuln) = match &entry.vulnerability {
                    certify_vuln_q1::AllCertifyVulnTreeVulnerability::CVE(id) => {
                        (Some(id.cve_id.clone()), None, None, None)
                    }
                    certify_vuln_q1::AllCertifyVulnTreeVulnerability::OSV(id) => {
                        (None, Some(id.osv_id.clone()), None, None)
                    }
                    certify_vuln_q1::AllCertifyVulnTreeVulnerability::GHSA(id) => {
                        (None, None, Some(id.ghsa_id.clone()), None)
                    }
                    certify_vuln_q1::AllCertifyVulnTreeVulnerability::NoVuln(id) => {
                        (None, None, None, Some(id.id.clone()))
                    }
                };

                let packages = vuln::vuln2purls(&entry.package);
                Vulnerability {
                    cve,
                    osv,
                    ghsa,
                    no_vuln,
                    packages,
                }
            })
            .collect())
    }

    pub async fn certify_good(&self, purl: &str) -> Result<Vec<CertifyGood>, anyhow::Error> {
        let pkg = certify_good_q1::PkgSpec::try_from(purl)?;
        let variables = certify_good_q1::Variables { package: Some(pkg) };
        let response_body =
            post_graphql::<CertifyGoodQ1, _>(&self.client, self.url.to_owned(), variables).await?;
        let response_data = response_body
            .data
            .with_context(|| "No data found in response");

        let mut certified = Vec::new();

        for entry in response_data?.certify_good {
            certified.push(CertifyGood {
                justification: entry.justification,
                origin: entry.origin,
                collector: entry.collector,
            });
        }

        Ok(certified)
    }

    pub async fn ingest_certify_good(
        &self,
        purl: &str,
        origin: String,
        collector: String,
        justification: String,
    ) -> Result<(), anyhow::Error> {
        let pkg = certify_good_m1::PkgInputSpec::try_from(purl)?;
        let variables = certify_good_m1::Variables {
            package: pkg,
            justification,
            collector,
            origin,
        };
        let response_body =
            post_graphql::<CertifyGoodM1, _>(&self.client, self.url.to_owned(), variables).await?;

        let _ = response_body
            .data
            .with_context(|| "No data found in response")?;

        Ok(())
    }

    pub async fn certify_bad(&self, purl: &str) -> Result<Vec<CertifyBad>, anyhow::Error> {
        let pkg = certify_bad_q1::PkgSpec::try_from(purl)?;
        let variables = certify_bad_q1::Variables { package: Some(pkg) };
        let response_body =
            post_graphql::<CertifyBadQ1, _>(&self.client, self.url.to_owned(), variables).await?;
        let response_data = response_body
            .data
            .with_context(|| "No data found in response");

        let mut certified = Vec::new();

        for entry in response_data?.certify_bad {
            certified.push(CertifyBad {
                justification: entry.justification,
                origin: entry.origin,
                collector: entry.collector,
            });
        }

        Ok(certified)
    }

    pub async fn ingest_certify_bad(
        &self,
        purl: &str,
        origin: String,
        collector: String,
        justification: String,
    ) -> Result<(), anyhow::Error> {
        let pkg = certify_bad_m1::PkgInputSpec::try_from(purl)?;
        let variables = certify_bad_m1::Variables {
            package: pkg,
            justification,
            collector,
            origin,
        };
        let response_body =
            post_graphql::<CertifyBadM1, _>(&self.client, self.url.to_owned(), variables).await?;

        let _ = response_body
            .data
            .with_context(|| "No data found in response")?;

        Ok(())
    }

    pub async fn get_vulnerabilities(
        &self,
        cve: &str,
    ) -> Result<Vec<Vulnerability>, anyhow::Error> {
        let variables = certify_vuln_q2::Variables {
            cve: Some(certify_vuln_q2::CVESpec {
                cve_id: Some(cve.to_string()),
                id: None,
                year: None,
            }),
        };
        let response_body =
            post_graphql::<CertifyVulnQ2, _>(&self.client, self.url.to_owned(), variables).await?;
        let response_data = response_body
            .data
            .with_context(|| "No data found in response");
        Ok(response_data?
            .certify_vuln
            .iter()
            .map(|entry| {
                let (cve, osv, ghsa, no_vuln) = match &entry.vulnerability {
                    certify_vuln_q2::AllCertifyVulnTreeVulnerability::CVE(id) => {
                        (Some(id.cve_id.clone()), None, None, None)
                    }
                    certify_vuln_q2::AllCertifyVulnTreeVulnerability::OSV(id) => {
                        (None, Some(id.osv_id.clone()), None, None)
                    }
                    certify_vuln_q2::AllCertifyVulnTreeVulnerability::GHSA(id) => {
                        (None, None, Some(id.ghsa_id.clone()), None)
                    }
                    certify_vuln_q2::AllCertifyVulnTreeVulnerability::NoVuln(id) => {
                        (None, None, None, Some(id.id.clone()))
                    }
                };

                let packages = cve::vuln2purls(&entry.package);
                Vulnerability {
                    cve,
                    osv,
                    ghsa,
                    no_vuln,
                    packages,
                }
            })
            .collect())
    }

    pub async fn get_dependencies(&self, purl: &str) -> Result<Vec<String>, anyhow::Error> {
        let pkg = DepPkgSpec::try_from(purl)?;
        let variables = DepVariables { package: Some(pkg) };
        let response_body =
            post_graphql::<GetDependencies, _>(&self.client, self.url.to_owned(), variables)
                .await?;
        let response_data = response_body
            .data
            .with_context(|| "No data found in response");
        Ok(response_data?
            .is_dependency
            .iter()
            .flat_map(|entry| {
                dependency::deps2purls(&entry.dependent_package, &entry.version_range)
            })
            .collect())
    }

    pub async fn is_dependent(&self, purl: &str) -> Result<Vec<String>, anyhow::Error> {
        let variables = IsDepVariables::try_from(purl)?;
        let response_body =
            post_graphql::<IsDependent, _>(&self.client, self.url.to_owned(), variables).await?;
        let response_data = response_body
            .data
            .with_context(|| "No data found in response");
        Ok(response_data?
            .is_dependency
            .iter()
            .flat_map(|entry| dependent::deps2purls(&entry.package))
            .collect())
    }

    pub async fn get_all_packages(&self) -> Result<Vec<String>, anyhow::Error> {
        let variables = PkgVariables { package: None };
        let response_body =
            post_graphql::<GetPackages, _>(&self.client, self.url.to_owned(), variables).await?;
        let response_data = response_body
            .data
            .with_context(|| "No data found in response");
        Ok(response_data?
            .packages
            .iter()
            .flat_map(packages::pkg2purls)
            .collect())
    }

    pub async fn get_packages(&self, purl: &str) -> Result<Vec<String>, anyhow::Error> {
        let pkg = PkgPkgSpec::try_from(purl)?;

        let variables = PkgVariables { package: Some(pkg) };
        let response_body =
            post_graphql::<GetPackages, _>(&self.client, self.url.to_owned(), variables).await?;
        let response_data = response_body
            .data
            .with_context(|| "No data found in response");
        Ok(response_data?
            .packages
            .iter()
            .flat_map(packages::pkg2purls)
            .collect())
    }
}

static VERSION: AtomicU64 = AtomicU64::new(1);
fn openvex() -> OpenVex {
    OpenVex {
        metadata: Metadata {
            context: "https://openvex.dev/ns".to_string(),
            id: format!(
                "https://seedwing.io/ROOT/generated/{}",
                uuid::Uuid::new_v4()
            ),
            author: "Seedwing Policy Engine".to_string(),
            role: "Document Creator".to_string(),
            timestamp: Some(Utc::now()),
            version: format!("{}", VERSION.fetch_add(1, Ordering::Relaxed)),
            tooling: Some("Seedwing Policy Engine".to_string()),
            supplier: Some("seedwing.io".to_string()),
        },
        statements: Vec::new(),
    }
}

pub fn vulns2vex(vulns: Vec<Vulnerability>) -> OpenVex {
    let mut vex = openvex();

    for vuln in vulns {
        let mut products = HashSet::new();
        let status = Status::Affected;
        let justification = None;
        // TODO consider all products?
        products.insert(vuln.packages[0].clone());

        let id = match (&vuln.cve, &vuln.osv) {
            (None, Some(osv)) => osv.clone(),
            (Some(cve_id), None) => cve_id.clone(),
            _ => String::from("NOT_SET"),
        };

        //let now_parsed = DateTime::parse_from_rfc3339(&vuln.time_scanned).unwrap();
        let now_parsed = Utc::now(); //TODO fix time problem

        let statement = Statement {
            vulnerability: Some(id.clone()),
            vuln_description: None,
            timestamp: Some(now_parsed),
            products: products.drain().collect(),
            subcomponents: Vec::new(),
            status,
            status_notes: Some("Vulnerabilities reported by Guac".into()),
            justification,
            impact_statement: None,
            action_statement: Some(format!(
                "Review {} for details on the appropriate action",
                id.clone()
            )),
            action_statement_timestamp: Some(Utc::now()),
        };
        vex.statements.push(statement);
    }

    vex
}

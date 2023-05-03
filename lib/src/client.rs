use anyhow::*;
use graphql_client::reqwest::post_graphql;

use crate::dependency::get_dependencies::PkgSpec as DepPkgSpec;
use crate::dependency::get_dependencies::Variables as DepVariables;
use crate::packages::get_packages::PkgSpec as PkgPkgSpec;
use crate::packages::get_packages::Variables as PkgVariables;
use crate::{
    dependency::{self, GetDependencies},
    packages::{self, GetPackages},
    dependent::{self, IsDependent, is_dependent::Variables as IsDepVariables},
    vuln::{
        self,
        certify_vuln_q1,
        CertifyVulnQ1,
    },
    cve::{
        self,
        certify_vuln_q2,
        CertifyVulnQ2,
    }
};


#[derive(Clone)]
pub struct GuacClient {
    client: reqwest::Client,
    url: String,
}

#[derive(Clone)]
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
        Ok(response_data?.certify_vuln.iter().map(|entry| {
            let (cve, osv, ghsa, no_vuln) = match &entry.vulnerability {
                certify_vuln_q1::AllCertifyVulnTreeVulnerability::CVE(id) => (Some(id.cve_id.clone()), None, None, None),
                certify_vuln_q1::AllCertifyVulnTreeVulnerability::OSV(id) => (None, Some(id.osv_id.clone()), None, None),
                certify_vuln_q1::AllCertifyVulnTreeVulnerability::GHSA(id) => (None, None, Some(id.ghsa_id.clone()), None),
                certify_vuln_q1::AllCertifyVulnTreeVulnerability::NoVuln(id) => (None, None, None, Some(id.id.clone())),
            };

            let packages = vuln::vuln2purls(&entry.package);
            Vulnerability { cve, osv, ghsa, no_vuln, packages }
        }).collect())
    }

    pub async fn get_vulnerabilities(&self, cve: &str) -> Result<Vec<Vulnerability>, anyhow::Error> {
        let variables = certify_vuln_q2::Variables { cve: Some(certify_vuln_q2::CVESpec {
            cve_id: Some(cve.to_string()),
            id: None,
            year: None,
        })};
        let response_body =
            post_graphql::<CertifyVulnQ2, _>(&self.client, self.url.to_owned(), variables).await?;
        let response_data = response_body
            .data
            .with_context(|| "No data found in response");
        Ok(response_data?.certify_vuln.iter().map(|entry| {

            let (cve, osv, ghsa, no_vuln) = match &entry.vulnerability {
                certify_vuln_q2::AllCertifyVulnTreeVulnerability::CVE(id) => (Some(id.cve_id.clone()), None, None, None),
                certify_vuln_q2::AllCertifyVulnTreeVulnerability::OSV(id) => (None, Some(id.osv_id.clone()), None, None),
                certify_vuln_q2::AllCertifyVulnTreeVulnerability::GHSA(id) => (None, None, Some(id.ghsa_id.clone()), None),
                certify_vuln_q2::AllCertifyVulnTreeVulnerability::NoVuln(id) => (None, None, None, Some(id.id.clone())),
            };

            let packages = cve::vuln2purls(&entry.package);
            Vulnerability { cve, osv, ghsa, no_vuln, packages }
        }).collect())
    }

    pub async fn get_dependencies(
        &self,
        purl: &str,
    ) -> Result<Vec<String>, anyhow::Error> {
        let pkg = DepPkgSpec::try_from(purl)?;
        let variables = DepVariables { package: Some(pkg) };
        let response_body =
            post_graphql::<GetDependencies, _>(&self.client, self.url.to_owned(), variables)
                .await?;
        let response_data = response_body
            .data
            .with_context(|| "No data found in response");
        Ok(response_data?.is_dependency.iter().flat_map(|entry| {
            dependency::deps2purls(&entry.package)
        }).collect())
    }

    pub async fn is_dependent(&self, purl: &str) -> Result<Vec<String>, anyhow::Error> {
        let variables = IsDepVariables::try_from(purl)?;
        let response_body =
            post_graphql::<IsDependent, _>(&self.client, self.url.to_owned(), variables).await?;
        let response_data = response_body
            .data
            .with_context(|| "No data found in response");
        Ok(response_data?.is_dependency.iter().flat_map(|entry| {
            dependent::deps2purls(&entry.package)
        }).collect())
    }

    pub async fn get_all_packages(&self) -> Result<Vec<String>, anyhow::Error> {
        let variables = PkgVariables {
            package: None
        };
        let response_body =
            post_graphql::<GetPackages, _>(&self.client, self.url.to_owned(), variables).await?;
        let response_data = response_body
            .data
            .with_context(|| "No data found in response");
        Ok(response_data?.packages.iter().flat_map(|entry| {
            packages::pkg2purls(entry)
        }).collect())
    }

    pub async fn get_packages(&self, purl: &str) -> Result<Vec<String>, anyhow::Error> {
        let pkg = PkgPkgSpec::try_from(purl)?;

        let variables = PkgVariables { package: Some(pkg) };
        let response_body =
            post_graphql::<GetPackages, _>(&self.client, self.url.to_owned(), variables).await?;
        let response_data = response_body
            .data
            .with_context(|| "No data found in response");
        Ok(response_data?.packages.iter().flat_map(|entry| {
            packages::pkg2purls(entry)
        }).collect())
    }
}

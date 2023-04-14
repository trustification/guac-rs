use anyhow::*;
use graphql_client::reqwest::post_graphql;

use crate::dependency::get_dependencies::allIsDependencyTree as GetDependenciesDeps;
use crate::dependency::get_dependencies::PkgSpec as DepPkgSpec;
use crate::dependency::get_dependencies::Variables as DepVariables;
use crate::dependency::is_dependent::allIsDependencyTree as IsDependentDeps;
use crate::dependency::is_dependent::Variables as IsDepVariables;
use crate::packages::get_packages::PkgSpec as PkgPkgSpec;
use crate::packages::get_packages::Variables as PkgVariables;
use crate::{
    dependency::{is_dependent::PkgNameSpec, GetDependencies, IsDependent},
    packages::{get_packages::allPkgTree, GetPackages},
    vuln::{
        certify_vuln_q1,
        CertifyVulnQ1,
    },
    cve::{
        certify_vuln_q2,
        CertifyVulnQ2,
    }
};

pub struct GuacClient {
    client: reqwest::Client,
    url: String,
}

impl GuacClient {
    pub fn new(url: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            url,
        }
    }

    pub async fn certify_vuln(&self, purl: &str) -> Result<Vec<certify_vuln_q1::allCertifyVulnTree>, anyhow::Error> {
        let pkg = certify_vuln_q1::PkgSpec::try_from(purl)?;
        let variables = certify_vuln_q1::Variables { package: Some(pkg) };
        let response_body =
            post_graphql::<CertifyVulnQ1, _>(&self.client, self.url.to_owned(), variables).await?;
        let response_data = response_body
            .data
            .with_context(|| "No data found in response");
        Ok(response_data?.certify_vuln)
    }

    pub async fn get_vulnerabilities(&self, cve: &str) -> Result<Vec<certify_vuln_q2::allCertifyVulnTree>, anyhow::Error> {
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
        Ok(response_data?.certify_vuln)
    }

    pub async fn get_dependencies(
        &self,
        purl: &str,
    ) -> Result<Vec<GetDependenciesDeps>, anyhow::Error> {
        let pkg = DepPkgSpec::try_from(purl)?;
        let variables = DepVariables { package: Some(pkg) };
        let response_body =
            post_graphql::<GetDependencies, _>(&self.client, self.url.to_owned(), variables)
                .await?;
        let response_data = response_body
            .data
            .with_context(|| "No data found in response");
        Ok(response_data?.is_dependency)
    }

    pub async fn is_dependent(&self, purl: &str) -> Result<Vec<IsDependentDeps>, anyhow::Error> {
        let pkg = PkgNameSpec::try_from(purl)?;
        let variables = IsDepVariables { package: Some(pkg) };
        let response_body =
            post_graphql::<IsDependent, _>(&self.client, self.url.to_owned(), variables).await?;
        let response_data = response_body
            .data
            .with_context(|| "No data found in response");
        Ok(response_data?.is_dependency)
    }

    pub async fn get_all_packages(&self) -> Result<Vec<allPkgTree>, anyhow::Error> {
        let variables = PkgVariables {
            package: None
        };
        let response_body =
            post_graphql::<GetPackages, _>(&self.client, self.url.to_owned(), variables).await?;
        let response_data = response_body
            .data
            .with_context(|| "No data found in response");
        Ok(response_data?.packages)
    }

    pub async fn get_packages(&self, purl: &str) -> Result<Vec<allPkgTree>, anyhow::Error> {
        let pkg = PkgPkgSpec::try_from(purl)?;
        let variables = PkgVariables { package: Some(pkg) };
        let response_body =
            post_graphql::<GetPackages, _>(&self.client, self.url.to_owned(), variables).await?;
        let response_data = response_body
            .data
            .with_context(|| "No data found in response");
        Ok(response_data?.packages)
    }
}

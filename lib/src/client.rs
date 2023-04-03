use graphql_client::reqwest::post_graphql;
use anyhow::*;

use crate::{vuln::{certify_vuln::{allCertifyVuln, PkgSpec as VulnPkgSpec, self}, CertifyVuln}, dependency::{GetDependencies, IsDependent, is_dependent::PkgNameSpec}};
use crate::dependency::get_dependencies::Variables as DepVariables;
use crate::dependency::is_dependent::Variables as IsDepVariables;
use crate::dependency::get_dependencies::PkgSpec as DepPkgSpec;
use crate::dependency::get_dependencies::allIsDependencyTree as GetDependenciesDeps;
use crate::dependency::is_dependent::allIsDependencyTree as IsDependentDeps;

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

    pub async fn certify_vuln(&self, purl: &str) -> Result<Vec<allCertifyVuln>, anyhow::Error> {
        let pkg = VulnPkgSpec::try_from(purl)?;
        let variables = certify_vuln::Variables {
            package: Some(pkg)
        };
        let response_body = post_graphql::<CertifyVuln, _>(&self.client, self.url.to_owned(), variables).await?;
        let response_data = response_body.data.with_context(|| "No data found in response");
        Ok(response_data?.certify_vuln)
    }

    pub async fn get_dependencies(&self, purl: &str) -> Result<Vec<GetDependenciesDeps>, anyhow::Error> {
        let pkg = DepPkgSpec::try_from(purl)?;
        let variables = DepVariables {
            package: Some(pkg)
        };
        let response_body = post_graphql::<GetDependencies, _>(&self.client, self.url.to_owned(), variables).await?;
        let response_data = response_body.data.with_context(|| "No data found in response");
        Ok(response_data?.is_dependency)
    }

    pub async fn is_dependent(&self, purl: &str) -> Result<Vec<IsDependentDeps>, anyhow::Error> {
        let pkg = PkgNameSpec::try_from(purl)?;
        let variables = IsDepVariables {
            package: Some(pkg)
        };
        let response_body = post_graphql::<IsDependent, _>(&self.client, self.url.to_owned(), variables).await?;
        let response_data = response_body.data.with_context(|| "No data found in response");
        Ok(response_data?.is_dependency)
    }

}

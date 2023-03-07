use crate::{CertifyVuln, certify_vuln::{PkgSpec, self, allCertifyVuln}};
use graphql_client::{GraphQLQuery, reqwest::post_graphql};
use anyhow::*;


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

    pub async fn certify_vuln(&self, pkg: PkgSpec) -> Result<Vec<allCertifyVuln>, anyhow::Error> {
        let variables = certify_vuln::Variables {
            package: Some(pkg)
        };        
        let response_body = post_graphql::<CertifyVuln, _>(&self.client, self.url.to_owned(), variables).await?;
        let response_data = response_body.data.with_context(|| "No data found in response");
        Ok(response_data?.certify_vuln)
    }

}
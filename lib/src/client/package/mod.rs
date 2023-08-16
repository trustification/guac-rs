use crate::client::package::ingest::IngestPackage;
use crate::client::package::query::QueryPackage;
use crate::client::GuacClient;
use graphql_client::reqwest::post_graphql;

use super::Error;

pub mod ingest;
pub mod query;

impl GuacClient {
    pub async fn ingest_package(&self, purl: &str) -> Result<(), Error> {
        use self::ingest::ingest_package;
        let pkg = ingest_package::PkgInputSpec::try_from(purl)?;
        let variables = ingest_package::Variables { package: pkg };
        let response_body =
            post_graphql::<IngestPackage, _>(&self.client, self.url.to_owned(), variables).await?;

        println!("{:?}", response_body);

        let _ = response_body
            .data
            .ok_or(Error::GraphQL("No data found in response".to_string()));

        Ok(())
    }

    pub async fn get_packages(&self, purl: &str) -> Result<Vec<String>, Error> {
        use self::query::query_package;
        let pkg = query_package::PkgSpec::try_from(purl)?;

        let variables = query_package::Variables { package: pkg };
        let response_body =
            post_graphql::<QueryPackage, _>(&self.client, self.url.to_owned(), variables).await?;
        let response_data = response_body
            .data
            .ok_or(Error::GraphQL("No data found in response".to_string()));
        Ok(response_data?
            .packages
            .iter()
            .flat_map(query::pkg2purls)
            .collect())
    }
}

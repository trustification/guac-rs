use crate::client::intrinsic::is_dependency::query::is_dependency::QueryDependencies;
use crate::client::intrinsic::is_dependency::query::is_dependent::QueryDependents;
use crate::client::GuacClient;
use graphql_client::reqwest::post_graphql;
use packageurl::PackageUrl;
use std::str::FromStr;

use crate::client::Error;
use crate::client::intrinsic::IntrinsicGuacClient;

mod query;

impl IntrinsicGuacClient<'_> {
    /*
    pub async fn is_dependency(&self, purl: &str) -> Result<Vec<String>, Error> {
        use self::query::is_dependency;

        let pkg = is_dependency::query_dependencies::PkgSpec::try_from(purl)?;
        let variables = is_dependency::query_dependencies::Variables { package: Some(pkg) };
        let response_body =
            post_graphql::<QueryDependencies, _>(&self.client, self.url.to_owned(), variables)
                .await?;
        let response_data = response_body
            .data
            .ok_or(Error::GraphQL("No data found in response".to_string()));
        Ok(response_data?
            .is_dependency
            .iter()
            .flat_map(|entry| {
                is_dependency::deps2purls(&entry.dependent_package, &entry.version_range)
            })
            .collect())
    }

    pub async fn is_dependent(&self, purl: &str) -> Result<Vec<String>, Error> {
        use self::query::is_dependent;

        let pkg = is_dependent::query_dependents::PkgSpec::try_from(purl.clone())?;
        let purl = PackageUrl::from_str(purl)?;

        let variables = is_dependent::query_dependents::Variables {
            package: Some(pkg),
            version: purl.version().map(|s| s.to_string()),
        };

        let response_body =
            post_graphql::<QueryDependents, _>(&self.client, self.url.to_owned(), variables)
                .await?;
        let response_data = response_body
            .data
            .ok_or(Error::GraphQL("No data found in response".to_string()));
        Ok(response_data?
            .is_dependency
            .iter()
            .flat_map(|entry| is_dependent::deps2purls(&entry.package))
            .collect())
    }


     */
}

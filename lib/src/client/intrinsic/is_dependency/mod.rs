use std::str::FromStr;
use graphql_client::reqwest::post_graphql;

use crate::client::intrinsic::package::{Package, PkgInputSpec, PkgSpec};
use crate::client::intrinsic::{Id, IntrinsicGuacClient, MatchFlags};
use crate::client::Error;
use crate::client::intrinsic::is_dependency::ingest::IngestDependency;
use crate::client::intrinsic::is_dependency::query::QueryIsDependency;

pub mod ingest;
pub mod query;

impl IntrinsicGuacClient<'_> {
    pub async fn ingest_is_dependency(
        &self,
        pkg: &PkgInputSpec,
        dep_pkg: &PkgInputSpec,
        dep_pkg_match_type: &MatchFlags,
        dependency: &IsDependencyInputSpec,
    ) -> Result<Id, Error> {
        use self::ingest::ingest_dependency;

        let variables = ingest_dependency::Variables {
            pkg: pkg.into(),
            dep_pkg: dep_pkg.into(),
            dep_pkg_match_type: dep_pkg_match_type.into(),
            dependency: dependency.into(),
        };

        let response_body =
            post_graphql::<IngestDependency, _>(self.client(), self.url(), variables)
                .await?;

        if let Some(errors) = response_body.errors {
            return Err(Error::GraphQL(errors))
        }

        let data = response_body
            .data
            .ok_or( Error::GraphQL(vec![]))?;

        Ok( data.ingest_dependency.id )

    }

    pub async fn is_dependency(
        &self,
        is_dependency_spec: &IsDependencySpec,
    ) -> Result<Id, Error> {
        use self::query::query_is_dependency;

        let variables = query_is_dependency::Variables {
            is_dependency_spec: is_dependency_spec.into()
        };

        let response_body =
            post_graphql::<QueryIsDependency, _>(self.client(), self.url(), variables)
                .await?;

        if let Some(errors) = response_body.errors {
            return Err(Error::GraphQL(errors))
        }

        let data = response_body
            .data
            .ok_or( Error::GraphQL(vec![]))?;

        todo!()

        //Ok( data.ingest_dependency.id )

    }

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

pub enum DependencyType {
    Direct,
    Indirect,
    Unknown,
}

pub struct IsDependency {
    id: Id,
    package: Package,
    dependent_package: Package,
    version_range: String,
    dependency_type: DependencyType,
    justification: String,
    origin: String,
    collector: String,
}

pub struct IsDependencySpec {
    id: Option<Id>,
    package: Option<PkgSpec>,
    dependent_package: Option<PkgSpec>,
    version_range: Option<String>,
    dependency_type: Option<DependencyType>,
    justification: Option<String>,
    origin: Option<String>,
    collector: Option<String>,
}

pub struct IsDependencyInputSpec {
    version_range: String,
    dependency_type: DependencyType,
    justification: String,
    origin: String,
    collector: String,
}

use graphql_client::reqwest::post_graphql;
use std::str::FromStr;

use crate::client::intrinsic::is_dependency::ingest::IngestDependency;
use crate::client::intrinsic::is_dependency::query::QueryIsDependency;
use crate::client::intrinsic::package::{IDorPkgInput, Package, PkgInputSpec, PkgSpec};
use crate::client::intrinsic::{IntrinsicGuacClient, MatchFlags};
use crate::client::{Error, Id};

pub mod ingest;
pub mod query;

impl IntrinsicGuacClient {
    pub async fn ingest_is_dependency<MF: Into<MatchFlags>>(
        &self,
        pkg: &IDorPkgInput,
        dep_pkg: &IDorPkgInput,
        dep_pkg_match_type: MF,
        dependency: &IsDependencyInputSpec,
    ) -> Result<Id, Error> {
        use self::ingest::ingest_dependency;

        let variables = ingest_dependency::Variables {
            pkg: pkg.into(),
            dep_pkg: dep_pkg.into(),
            dep_pkg_match_type: dep_pkg_match_type.into().into(),
            dependency: dependency.into(),
        };

        let response_body = post_graphql::<IngestDependency, _>(self.client(), self.url(), variables).await?;

        if let Some(errors) = response_body.errors {
            return Err(Error::GraphQL(errors));
        }

        let data = response_body.data.ok_or(Error::GraphQL(vec![]))?;

        Ok(data.ingest_dependency)
    }

    pub async fn is_dependency(&self, is_dependency_spec: &IsDependencySpec) -> Result<Vec<IsDependency>, Error> {
        use self::query::query_is_dependency;

        let variables = query_is_dependency::Variables {
            is_dependency_spec: is_dependency_spec.into(),
        };

        let response_body = post_graphql::<QueryIsDependency, _>(self.client(), self.url(), variables).await?;

        if let Some(errors) = response_body.errors {
            return Err(Error::GraphQL(errors));
        }

        let data = response_body.data.ok_or(Error::GraphQL(vec![]))?;

        Ok(data.is_dependency.iter().map(|e| e.into()).collect())
    }
}

#[derive(Debug, Clone)]
pub enum DependencyType {
    Direct,
    Indirect,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct IsDependency {
    pub id: Id,
    pub package: Package,
    pub dependent_package: Package,
    pub version_range: String,
    pub dependency_type: DependencyType,
    pub justification: String,
    pub origin: String,
    pub collector: String,
}

#[derive(Default, Debug, Clone)]
pub struct IsDependencySpec {
    pub id: Option<Id>,
    pub package: Option<PkgSpec>,
    pub dependent_package: Option<PkgSpec>,
    pub version_range: Option<String>,
    pub dependency_type: Option<DependencyType>,
    pub justification: Option<String>,
    pub origin: Option<String>,
    pub collector: Option<String>,
    pub document_ref: Option<String>,
}

#[derive(Debug, Clone)]
pub struct IsDependencyInputSpec {
    pub version_range: String,
    pub dependency_type: DependencyType,
    pub justification: String,
    pub origin: String,
    pub collector: String,
    pub document_ref: String,
}

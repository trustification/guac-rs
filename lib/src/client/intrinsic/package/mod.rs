use crate::client::intrinsic::package::ingest::IngestPackage;
use graphql_client::reqwest::post_graphql;

use crate::client::Error;
use crate::client::intrinsic::{Id, IntrinsicGuacClient};
use crate::client::intrinsic::package::query::QueryPackages;
//use crate::client::intrinsic::package::query::query_package::PackageQualifierSpec;

pub mod ingest;
pub mod query;

impl IntrinsicGuacClient<'_> {

    pub async fn ingest_package(&self, package: &PkgInputSpec) -> Result<Id, Error> {
        use self::ingest::ingest_package;
        let variables = ingest_package::Variables { package: package.into() };
        let response_body =
            post_graphql::<IngestPackage, _>(self.client(), self.url(), variables).await?;

        if let Some(errors) = response_body.errors {
            return Err( Error::GraphQL(errors));
        }

        let data = response_body
            .data
            .ok_or( Error::GraphQL(vec![]))?;

        Ok( data.ingest_package.id )
    }

    pub async fn packages(&self, package: &PkgSpec) -> Result<Vec<Package>, Error> {
        use self::query::query_packages;
        let variables = query_packages::Variables {
            package: package.into(),
        };

        let response_body =
            post_graphql::<QueryPackages, _>(self.client(), self.url(), variables).await?;

        if let Some(errors) = response_body.errors {
            return Err( Error::GraphQL(errors));
        }

        let data = response_body
            .data
            .ok_or( Error::GraphQL(vec![]))?;

        let packages = data.packages.iter().map(|e| {
            e.into()
        } ).collect();

        Ok(packages)

    }
}

pub struct Package {
    pub id: String,
    pub r#type: String,
    pub namespaces: Vec<PackageNamespace>,
}

pub struct PackageNamespace {
    pub id: String,
    pub namespace: String,
    pub names: Vec<PackageName>,
}

pub struct PackageName {
    pub id: String,
    pub name: String,
    pub versions: Vec<PackageVersion>,
}

pub struct PackageVersion {
    pub id: String,
    pub version: String,
    pub qualifiers: Vec<PackageQualifier>,
    pub subpath: String,

}
pub struct PackageQualifier {
    pub key: String,
    pub value: String,
}

pub struct PkgSpec {
    pub id: Option<String>,
    pub r#type: Option<String>,
    pub namespace: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
    pub qualifiers: Option<Vec<PackageQualifierSpec>>,
    pub match_only_empty_qualifiers: Option<bool>,
    pub subpath: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PackageQualifierSpec {
    pub key: String,
    pub value: Option<String>,
}


pub struct PkgInputSpec {
    pub r#type: String,
    pub namespace: Option<String>,
    pub name: String,
    pub version: Option<String>,
    pub qualifiers: Option<Vec<PackageQualifierInputSpec>>,
    pub subpath: Option<String>,
}


#[derive(Debug, Clone)]
pub struct PackageQualifierInputSpec {
    pub key: String,
    pub value: String,
}

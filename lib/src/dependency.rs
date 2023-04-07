use graphql_client::GraphQLQuery;

use get_dependencies::PkgSpec;
use is_dependent::PkgNameSpec;
use packageurl::PackageUrl;
use std::str::FromStr;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/schema.json",
    query_path = "src/query/is_dependency.gql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct GetDependencies;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/schema.json",
    query_path = "src/query/is_dependency.gql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct IsDependent;

impl TryFrom<&str> for PkgSpec {
    type Error = anyhow::Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let purl = PackageUrl::from_str(s)?;

        Ok(PkgSpec {
            id: None,
            type_: Some(purl.ty().to_string()),
            namespace: purl.namespace().map(|s| s.to_string()),
            name: Some(purl.name().to_string()),
            subpath: purl.subpath().map(|s| s.to_string()),
            version: purl.version().map(|s| s.to_string()),
            qualifiers: None, //TODO fix qualifiers
            match_only_empty_qualifiers: Some(false),
        })
    }
}

impl TryFrom<&str> for PkgNameSpec {
    type Error = anyhow::Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let purl = PackageUrl::from_str(s)?;

        Ok(PkgNameSpec {
            id: None,
            type_: Some(purl.ty().to_string()),
            namespace: purl.namespace().map(|s| s.to_string()),
            name: Some(purl.name().to_string()),
        })
    }
}

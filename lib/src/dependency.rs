use graphql_client::GraphQLQuery;

use get_dependencies::PackageQualifierSpec;
use get_dependencies::PkgSpec;
use is_dependent::PkgNameSpec;
use is_dependent::Variables as IsDepVariables;
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
        let mut qualifiers = Vec::new();
        for (key, value) in purl.qualifiers().iter() {
            qualifiers.push(PackageQualifierSpec {
                key: key.to_string(),
                value: Some(value.to_string()),
            })
        }

        Ok(PkgSpec {
            id: None,
            type_: Some(purl.ty().to_string()),
            namespace: purl.namespace().map(|s| s.to_string()),
            name: Some(purl.name().to_string()),
            subpath: purl.subpath().map(|s| s.to_string()),
            version: purl.version().map(|s| s.to_string()),
            qualifiers: if qualifiers.is_empty() {
                None
            } else {
                Some(qualifiers)
            },
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

impl TryFrom<&str> for IsDepVariables {
    type Error = anyhow::Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let purl = PackageUrl::from_str(s)?;
        let pkg = PkgNameSpec::try_from(s)?;
        Ok(IsDepVariables {
            package: Some(pkg),
            version: purl.version().map(|s| s.to_string()),
        })
    }
}

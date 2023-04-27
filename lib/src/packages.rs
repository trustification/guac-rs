use graphql_client::GraphQLQuery;
use packageurl::PackageUrl;
use std::str::FromStr;

use self::get_packages::PackageQualifierSpec;

use self::get_packages::PkgSpec;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/schema.json",
    query_path = "src/query/packages.gql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct GetPackages;

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

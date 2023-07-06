use self::certify_bad_q1::{PackageQualifierSpec, PkgSpec};
use graphql_client::GraphQLQuery;
use packageurl::PackageUrl;
use serde::Serialize;
use std::str::FromStr;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/schema.json",
    query_path = "src/graphql/query/certify_bad.gql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct CertifyBadQ1;

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

#[derive(Serialize)]
pub struct CertifyBad {
    pub justification: String,
    pub origin: String,
    pub collector: String,
}

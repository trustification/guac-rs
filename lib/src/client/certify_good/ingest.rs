use graphql_client::GraphQLQuery;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/client/schema.json",
    query_path = "src/client/certify_good/certify_good.gql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct IngestCertifyGood;

use self::ingest_certify_good::{PackageQualifierInputSpec, PkgInputSpec};
use packageurl::PackageUrl;
use std::str::FromStr;

impl TryFrom<&str> for PkgInputSpec {
    type Error = anyhow::Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let purl = PackageUrl::from_str(s)?;
        let mut qualifiers = Vec::new();
        for (key, value) in purl.qualifiers().iter() {
            qualifiers.push(PackageQualifierInputSpec {
                key: key.to_string(),
                value: value.to_string(),
            })
        }

        Ok(PkgInputSpec {
            type_: purl.ty().to_string(),
            namespace: purl.namespace().map(|s| s.to_string()),
            name: purl.name().to_string(),
            subpath: purl.subpath().map(|s| s.to_string()),
            version: purl.version().map(|s| s.to_string()),
            qualifiers: if qualifiers.is_empty() {
                None
            } else {
                Some(qualifiers)
            },
        })
    }
}

use std::str::FromStr;
use chrono::Utc;

use graphql_client::GraphQLQuery;
use packageurl::PackageUrl;

use crate::client::certify_vuln::Metadata;
use crate::client::vulnerability::Vulnerability;

use self::ingest_certify_vuln::{
    PackageQualifierInputSpec, PkgInputSpec, ScanMetadataInput, VulnerabilityInputSpec,
};

type Time = chrono::DateTime<Utc>;


#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/client/schema.json",
    query_path = "src/client/certify_vuln/certify_vuln.gql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct IngestCertifyVuln;

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

impl TryFrom<Vulnerability> for VulnerabilityInputSpec {
    type Error = anyhow::Error;

    fn try_from(vuln: Vulnerability) -> Result<Self, Self::Error> {
        Ok(VulnerabilityInputSpec {
            type_: vuln.ty,
            vulnerability_id: vuln.vulnerability_id,
        })
    }
}

impl TryFrom<Metadata> for ScanMetadataInput {
    type Error = anyhow::Error;

    fn try_from(meta: Metadata) -> Result<Self, Self::Error> {
        Ok(ScanMetadataInput {
            db_uri: meta.db_uri,
            db_version: meta.db_version,
            scanner_uri: meta.scanner_uri,
            scanner_version: meta.scanner_version,
            time_scanned: meta.time_scanned,
            collector: meta.collector,
            origin: meta.origin,
        })
    }
}

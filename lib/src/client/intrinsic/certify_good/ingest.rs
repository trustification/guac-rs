use chrono::Utc;
use graphql_client::GraphQLQuery;

use crate::client::intrinsic::certify_good::CertifyGoodInputSpec;
use crate::client::intrinsic::package::{PackageQualifierInputSpec, PkgInputSpec};
use crate::client::intrinsic::{MatchFlags, PackageSourceOrArtifactInput, PkgMatchType};

type Time = chrono::DateTime<Utc>;
#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/client/intrinsic/schema.json",
    query_path = "src/client/intrinsic/certify_good/certify_good.gql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct IngestCertifyGood;

impl From<&PackageSourceOrArtifactInput> for ingest_certify_good::PackageSourceOrArtifactInput {
    fn from(value: &PackageSourceOrArtifactInput) -> Self {
        Self {
            package: value.package.as_ref().map(|inner| inner.into()),
            artifact: None,
            source: None,
        }
    }
}

impl From<MatchFlags> for ingest_certify_good::MatchFlags {
    fn from(value: MatchFlags) -> Self {
        Self {
            pkg: (&value.pkg).into(),
        }
    }
}

impl From<&CertifyGoodInputSpec> for ingest_certify_good::CertifyGoodInputSpec {
    fn from(value: &CertifyGoodInputSpec) -> Self {
        Self {
            justification: value.justification.clone(),
            origin: value.origin.clone(),
            collector: value.collector.clone(),
            known_since: value.known_since,
        }
    }
}

impl From<&PkgInputSpec> for ingest_certify_good::PkgInputSpec {
    fn from(value: &PkgInputSpec) -> Self {
        Self {
            type_: value.r#type.clone(),
            namespace: value.namespace.clone(),
            name: value.name.clone(),
            version: value.version.clone(),
            qualifiers: value.qualifiers.as_ref().map(|e| e.iter().map(|e| e.into()).collect()),
            subpath: value.subpath.clone(),
        }
    }
}

impl From<&PackageQualifierInputSpec> for ingest_certify_good::PackageQualifierInputSpec {
    fn from(value: &PackageQualifierInputSpec) -> Self {
        Self {
            key: value.key.clone(),
            value: value.value.clone(),
        }
    }
}

impl From<&PkgMatchType> for ingest_certify_good::PkgMatchType {
    fn from(value: &PkgMatchType) -> Self {
        match value {
            PkgMatchType::AllVersions => Self::ALL_VERSIONS,
            PkgMatchType::SpecificVersion => Self::SPECIFIC_VERSION,
        }
    }
}

use crate::client::intrinsic::certify_bad::CertifyBadInputSpec;
use crate::client::intrinsic::package::{PackageQualifierInputSpec, PkgInputSpec};
use crate::client::intrinsic::{MatchFlags, PackageSourceOrArtifactInput, PkgMatchType};
use chrono::Utc;
use graphql_client::GraphQLQuery;

type Time = chrono::DateTime<Utc>;
#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/client/intrinsic/schema.json",
    query_path = "src/client/intrinsic/certify_bad/certify_bad.gql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct IngestCertifyBad;

impl From<&PackageSourceOrArtifactInput> for ingest_certify_bad::PackageSourceOrArtifactInput {
    fn from(value: &PackageSourceOrArtifactInput) -> Self {
        Self {
            package: value.package.as_ref().map(|inner| inner.into()),
            artifact: None,
            source: None,
        }
    }
}

impl From<MatchFlags> for ingest_certify_bad::MatchFlags {
    fn from(value: MatchFlags) -> Self {
        Self {
            pkg: (&value.pkg).into(),
        }
    }
}

impl From<&CertifyBadInputSpec> for ingest_certify_bad::CertifyBadInputSpec {
    fn from(value: &CertifyBadInputSpec) -> Self {
        Self {
            justification: value.justification.clone(),
            origin: value.origin.clone(),
            collector: value.collector.clone(),
            known_since: value.known_since,
        }
    }
}

impl From<&PkgInputSpec> for ingest_certify_bad::PkgInputSpec {
    fn from(value: &PkgInputSpec) -> Self {
        Self {
            type_: value.r#type.clone(),
            namespace: value.namespace.clone(),
            name: value.name.clone(),
            version: value.version.clone(),
            qualifiers: value
                .qualifiers
                .as_ref()
                .map(|e| e.iter().map(|e| e.into()).collect()),
            subpath: value.subpath.clone(),
        }
    }
}

impl From<&PackageQualifierInputSpec> for ingest_certify_bad::PackageQualifierInputSpec {
    fn from(value: &PackageQualifierInputSpec) -> Self {
        Self {
            key: value.key.clone(),
            value: value.value.clone(),
        }
    }
}

impl From<&PkgMatchType> for ingest_certify_bad::PkgMatchType {
    fn from(value: &PkgMatchType) -> Self {
        match value {
            PkgMatchType::AllVersions => Self::ALL_VERSIONS,
            PkgMatchType::SpecificVersion => Self::SPECIFIC_VERSION,
        }
    }
}

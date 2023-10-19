use chrono::Utc;
use graphql_client::GraphQLQuery;
use crate::client::intrinsic::certify_vex_statement::{VexJustification, VexStatementInputSpec, VexStatus};
use crate::client::intrinsic::package::{PackageQualifierInputSpec, PkgInputSpec};
use crate::client::intrinsic::PackageOrArtifactInput;
use crate::client::intrinsic::vulnerability::{Vulnerability, VulnerabilityInputSpec};

type Time = chrono::DateTime<Utc>;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/client/intrinsic/schema.json",
    query_path = "src/client/intrinsic/certify_vex_statement/certify_vex_statement.gql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct IngestCertifyVexStatement;

impl From<&PackageOrArtifactInput> for ingest_certify_vex_statement::PackageOrArtifactInput {
    fn from(value: &PackageOrArtifactInput) -> Self {
        Self {
            package: value.package.as_ref().map(|inner| inner.into()),
            artifact: None
        }
    }
}

impl From<&PkgInputSpec> for ingest_certify_vex_statement::PkgInputSpec {
    fn from(value: &PkgInputSpec) -> Self {
        Self {
            type_: value.r#type.clone(),
            namespace: value.namespace.clone(),
            name: value.name.clone(),
            version: value.version.clone(),
            qualifiers: value
                .qualifiers
                .clone()
                .map(|inner| inner.iter().map(|each| each.into()).collect()),
            subpath: value.subpath.clone(),
        }
    }
}

impl From<&VulnerabilityInputSpec> for ingest_certify_vex_statement::VulnerabilityInputSpec {
    fn from(value: &VulnerabilityInputSpec) -> Self {
        Self {
            type_: value.r#type.clone(),
            vulnerability_id: value.vulnerability_id.clone(),
        }
    }
}


impl From<&PackageQualifierInputSpec> for ingest_certify_vex_statement::PackageQualifierInputSpec {
    fn from(value: &PackageQualifierInputSpec) -> Self {
        Self {
            key: value.key.clone(),
            value: value.value.clone(),
        }
    }
}

impl From<&VexStatementInputSpec> for ingest_certify_vex_statement::VexStatementInputSpec {
    fn from(value: &VexStatementInputSpec) -> Self {
        Self {
            status: (&value.status).into(),
            vex_justification: (&value.vex_justification).into(),
            statement: value.statement.clone(),
            status_notes: value.status_notes.clone(),
            known_since: value.known_since,
            origin: value.origin.clone(),
            collector: value.collector.clone(),
        }
    }
}

impl From<&VexStatus> for ingest_certify_vex_statement::VexStatus {
    fn from(value: &VexStatus) -> Self {
        match value {
            VexStatus::NotAffected => {
                ingest_certify_vex_statement::VexStatus::NOT_AFFECTED
            }
            VexStatus::Affected => {
                ingest_certify_vex_statement::VexStatus::AFFECTED
            }
            VexStatus::Fixed => {
                ingest_certify_vex_statement::VexStatus::FIXED
            }
            VexStatus::UnderInvestigation => {
                ingest_certify_vex_statement::VexStatus::UNDER_INVESTIGATION
            }
            VexStatus::Other(inner) => {
                ingest_certify_vex_statement::VexStatus::Other(inner.clone())
            }
        }
    }
}

impl From<&VexJustification> for ingest_certify_vex_statement::VexJustification {
    fn from(value: &VexJustification) -> Self {
        match value {
            VexJustification::ComponentNotPresent => {
                ingest_certify_vex_statement::VexJustification::COMPONENT_NOT_PRESENT
            }
            VexJustification::VulnerableCodeNotPresent => {
                ingest_certify_vex_statement::VexJustification::VULNERABLE_CODE_NOT_PRESENT
            }
            VexJustification::VulnerableCodeNotInExecutePath => {
                ingest_certify_vex_statement::VexJustification::VULNERABLE_CODE_NOT_IN_EXECUTE_PATH
            }
            VexJustification::VulnerableCodeCannotBeControlledByAdversary => {
                ingest_certify_vex_statement::VexJustification::VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY
            }
            VexJustification::InlineMitigationsAlreadyExist => {
                ingest_certify_vex_statement::VexJustification::INLINE_MITIGATIONS_ALREADY_EXIST
            }
            VexJustification::NotProvided => {
                ingest_certify_vex_statement::VexJustification::NOT_PROVIDED
            }
            VexJustification::Other(inner) => {
                ingest_certify_vex_statement::VexJustification::Other(inner.clone())
            }
        }
    }
}
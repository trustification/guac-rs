use chrono::Utc;
use graphql_client::GraphQLQuery;

use crate::client::intrinsic::certify_vex_statement::query::query_certify_vex_statement::{
    AllCertifyVexStatementTreeSubject, AllCertifyVexStatementTreeSubjectOnPackage,
    AllCertifyVexStatementTreeSubjectOnPackageNamespaces, AllCertifyVexStatementTreeSubjectOnPackageNamespacesNames,
    AllCertifyVexStatementTreeSubjectOnPackageNamespacesNamesVersions,
    AllCertifyVexStatementTreeSubjectOnPackageNamespacesNamesVersionsQualifiers,
    AllCertifyVexStatementTreeVulnerability, AllCertifyVexStatementTreeVulnerabilityVulnerabilityIDs,
};
use crate::client::intrinsic::certify_vex_statement::{
    CertifyVexStatement, CertifyVexStatementSpec, VexJustification, VexStatus,
};
use crate::client::intrinsic::package::{
    Package, PackageName, PackageNamespace, PackageQualifier, PackageQualifierSpec, PackageVersion, PkgSpec,
};
use crate::client::intrinsic::vulnerability::{Vulnerability, VulnerabilityId, VulnerabilitySpec};
use crate::client::intrinsic::{PackageOrArtifact, PackageOrArtifactSpec};

type Time = chrono::DateTime<Utc>;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/client/intrinsic/schema.json",
    query_path = "src/client/intrinsic/certify_vex_statement/certify_vex_statement.gql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct QueryCertifyVexStatement;

impl From<&CertifyVexStatementSpec> for query_certify_vex_statement::CertifyVEXStatementSpec {
    fn from(value: &CertifyVexStatementSpec) -> Self {
        Self {
            id: value.id.clone(),
            subject: value.subject.as_ref().map(|inner| inner.into()),
            vulnerability: value.vulnerability.as_ref().map(|inner| inner.into()),
            status: value.status.as_ref().map(|inner| inner.into()),
            vex_justification: value.vex_justification.as_ref().map(|inner| inner.into()),
            statement: value.statement.clone(),
            status_notes: value.status_notes.clone(),
            known_since: value.known_since,
            origin: value.origin.clone(),
            collector: value.collector.clone(),
        }
    }
}

impl From<&query_certify_vex_statement::allCertifyVEXStatementTree> for CertifyVexStatement {
    fn from(value: &query_certify_vex_statement::allCertifyVEXStatementTree) -> Self {
        Self {
            id: value.id.clone(),
            subject: (&value.subject).into(),
            vulnerability: (&value.vulnerability).into(),
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

impl From<&PackageOrArtifactSpec> for query_certify_vex_statement::PackageOrArtifactSpec {
    fn from(value: &PackageOrArtifactSpec) -> Self {
        Self {
            package: value.package.as_ref().map(|inner| inner.into()),
            artifact: None,
        }
    }
}

impl From<&VulnerabilitySpec> for query_certify_vex_statement::VulnerabilitySpec {
    fn from(value: &VulnerabilitySpec) -> Self {
        Self {
            id: value.id.clone(),
            type_: value.r#type.clone(),
            vulnerability_id: value.vulnerability_id.clone(),
            no_vuln: value.no_vuln,
        }
    }
}

impl From<&VexStatus> for query_certify_vex_statement::VexStatus {
    fn from(value: &VexStatus) -> Self {
        match value {
            VexStatus::NotAffected => query_certify_vex_statement::VexStatus::NOT_AFFECTED,
            VexStatus::Affected => query_certify_vex_statement::VexStatus::AFFECTED,
            VexStatus::Fixed => query_certify_vex_statement::VexStatus::FIXED,
            VexStatus::UnderInvestigation => query_certify_vex_statement::VexStatus::UNDER_INVESTIGATION,
            VexStatus::Other(inner) => query_certify_vex_statement::VexStatus::Other(inner.clone()),
        }
    }
}

impl From<&VexJustification> for query_certify_vex_statement::VexJustification {
    fn from(value: &VexJustification) -> Self {
        match value {
            VexJustification::ComponentNotPresent => {
                query_certify_vex_statement::VexJustification::COMPONENT_NOT_PRESENT
            }
            VexJustification::VulnerableCodeNotPresent => {
                query_certify_vex_statement::VexJustification::VULNERABLE_CODE_NOT_PRESENT
            }
            VexJustification::VulnerableCodeNotInExecutePath => {
                query_certify_vex_statement::VexJustification::VULNERABLE_CODE_NOT_IN_EXECUTE_PATH
            }
            VexJustification::VulnerableCodeCannotBeControlledByAdversary => {
                query_certify_vex_statement::VexJustification::VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY
            }
            VexJustification::InlineMitigationsAlreadyExist => {
                query_certify_vex_statement::VexJustification::INLINE_MITIGATIONS_ALREADY_EXIST
            }
            VexJustification::NotProvided => query_certify_vex_statement::VexJustification::NOT_PROVIDED,
            VexJustification::Other(inner) => query_certify_vex_statement::VexJustification::Other(inner.clone()),
        }
    }
}

impl From<&PkgSpec> for query_certify_vex_statement::PkgSpec {
    fn from(value: &PkgSpec) -> Self {
        Self {
            id: value.id.clone(),
            type_: value.r#type.clone(),
            namespace: value.namespace.clone(),
            name: value.name.clone(),
            version: value.version.clone(),
            qualifiers: value
                .qualifiers
                .as_ref()
                .map(|inner| inner.iter().map(|e| e.into()).collect()),
            match_only_empty_qualifiers: value.match_only_empty_qualifiers,
            subpath: value.subpath.clone(),
        }
    }
}

impl From<&PackageQualifierSpec> for query_certify_vex_statement::PackageQualifierSpec {
    fn from(value: &PackageQualifierSpec) -> Self {
        Self {
            key: value.key.clone(),
            value: value.value.clone(),
        }
    }
}

impl From<&AllCertifyVexStatementTreeSubject> for PackageOrArtifact {
    fn from(value: &AllCertifyVexStatementTreeSubject) -> Self {
        match value {
            AllCertifyVexStatementTreeSubject::Package(inner) => Self::Package(inner.into()),
            AllCertifyVexStatementTreeSubject::Artifact(inner) => {
                todo!("artifact not implemented")
            }
        }
    }
}

impl From<&AllCertifyVexStatementTreeVulnerability> for Vulnerability {
    fn from(value: &AllCertifyVexStatementTreeVulnerability) -> Self {
        Self {
            id: value.id.clone(),
            r#type: value.type_.clone(),
            vulnerability_ids: value.vulnerability_i_ds.iter().map(|inner| inner.into()).collect(),
        }
    }
}

impl From<&AllCertifyVexStatementTreeVulnerabilityVulnerabilityIDs> for VulnerabilityId {
    fn from(value: &AllCertifyVexStatementTreeVulnerabilityVulnerabilityIDs) -> Self {
        Self {
            id: value.id.clone(),
            vulnerability_id: value.vulnerability_id.clone(),
        }
    }
}

impl From<&AllCertifyVexStatementTreeSubjectOnPackage> for Package {
    fn from(value: &AllCertifyVexStatementTreeSubjectOnPackage) -> Self {
        Self {
            id: value.id.clone(),
            r#type: value.type_.clone(),
            namespaces: value.namespaces.iter().map(|e| e.into()).collect(),
        }
    }
}

impl From<&AllCertifyVexStatementTreeSubjectOnPackageNamespaces> for PackageNamespace {
    fn from(value: &AllCertifyVexStatementTreeSubjectOnPackageNamespaces) -> Self {
        Self {
            id: value.id.clone(),
            namespace: value.namespace.clone(),
            names: value.names.iter().map(|e| e.into()).collect(),
        }
    }
}

impl From<&AllCertifyVexStatementTreeSubjectOnPackageNamespacesNames> for PackageName {
    fn from(value: &AllCertifyVexStatementTreeSubjectOnPackageNamespacesNames) -> Self {
        Self {
            id: value.id.clone(),
            name: value.name.clone(),
            versions: value.versions.iter().map(|e| e.into()).collect(),
        }
    }
}

impl From<&AllCertifyVexStatementTreeSubjectOnPackageNamespacesNamesVersions> for PackageVersion {
    fn from(value: &AllCertifyVexStatementTreeSubjectOnPackageNamespacesNamesVersions) -> Self {
        Self {
            id: value.id.clone(),
            version: value.version.clone(),
            qualifiers: value.qualifiers.iter().map(|e| e.into()).collect(),
            subpath: value.subpath.clone(),
        }
    }
}

impl From<&AllCertifyVexStatementTreeSubjectOnPackageNamespacesNamesVersionsQualifiers> for PackageQualifier {
    fn from(value: &AllCertifyVexStatementTreeSubjectOnPackageNamespacesNamesVersionsQualifiers) -> Self {
        Self {
            key: value.key.clone(),
            value: value.value.clone(),
        }
    }
}

impl From<&query_certify_vex_statement::VexStatus> for VexStatus {
    fn from(value: &query_certify_vex_statement::VexStatus) -> Self {
        match value {
            query_certify_vex_statement::VexStatus::NOT_AFFECTED => Self::NotAffected,
            query_certify_vex_statement::VexStatus::AFFECTED => Self::Affected,
            query_certify_vex_statement::VexStatus::FIXED => Self::Fixed,
            query_certify_vex_statement::VexStatus::UNDER_INVESTIGATION => Self::UnderInvestigation,
            query_certify_vex_statement::VexStatus::Other(inner) => Self::Other(inner.clone()),
        }
    }
}

impl From<&query_certify_vex_statement::VexJustification> for VexJustification {
    fn from(value: &query_certify_vex_statement::VexJustification) -> Self {
        match value {
            query_certify_vex_statement::VexJustification::COMPONENT_NOT_PRESENT => Self::ComponentNotPresent,
            query_certify_vex_statement::VexJustification::VULNERABLE_CODE_NOT_PRESENT => {
                Self::VulnerableCodeNotPresent
            }
            query_certify_vex_statement::VexJustification::VULNERABLE_CODE_NOT_IN_EXECUTE_PATH => {
                Self::VulnerableCodeNotInExecutePath
            }
            query_certify_vex_statement::VexJustification::VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY => {
                Self::VulnerableCodeCannotBeControlledByAdversary
            }
            query_certify_vex_statement::VexJustification::INLINE_MITIGATIONS_ALREADY_EXIST => {
                Self::InlineMitigationsAlreadyExist
            }
            query_certify_vex_statement::VexJustification::NOT_PROVIDED => Self::NotProvided,
            query_certify_vex_statement::VexJustification::Other(inner) => Self::Other(inner.clone()),
        }
    }
}

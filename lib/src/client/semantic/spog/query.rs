use crate::client::graph::Node;
use chrono::Utc;
use graphql_client::GraphQLQuery;

use crate::client::intrinsic::certify_vex_statement::{self, CertifyVexStatement, VexJustification, VexStatus};
use crate::client::intrinsic::package::{
    Package, PackageName, PackageNamespace, PackageQualifier, PackageQualifierSpec, PackageVersion, PkgSpec,
};
use crate::client::intrinsic::vulnerability::{Vulnerability, VulnerabilityId};
use crate::client::semantic::spog::query::query_spog::allCertifyVEXStatementTree;
use crate::client::semantic::spog::query::query_spog::allCertifyVulnTree;
use crate::client::semantic::spog::query::query_spog::QuerySpogFindTopLevelPackagesRelatedToVulnerability as QS;
use crate::client::semantic::spog::query::query_spog::QuerySpogFindTopLevelPackagesRelatedToVulnerabilityOnPackage as QSPackage;
use crate::client::semantic::spog::query::query_spog::VexJustification as QSVexJustification;
use crate::client::semantic::spog::query::query_spog::VexStatus as QSVexStatus;
use crate::client::semantic::spog::query::query_spog::{
    AllCertifyVexStatementTreeSubject, AllCertifyVexStatementTreeSubjectOnPackage,
    AllCertifyVexStatementTreeSubjectOnPackageNamespaces, AllCertifyVexStatementTreeSubjectOnPackageNamespacesNames,
    AllCertifyVexStatementTreeSubjectOnPackageNamespacesNamesVersions,
    AllCertifyVexStatementTreeSubjectOnPackageNamespacesNamesVersionsQualifiers,
    AllCertifyVexStatementTreeVulnerability, AllCertifyVexStatementTreeVulnerabilityVulnerabilityIDs,
    AllPkgTreeNamespaces, AllPkgTreeNamespacesNames, AllPkgTreeNamespacesNamesVersions,
    AllPkgTreeNamespacesNamesVersionsQualifiers,
};

use crate::client::intrinsic::certify_vuln::{CertifyVuln, ScanMetadata};
use crate::client::intrinsic::{PackageOrArtifact, PackageOrArtifactInput, PackageOrArtifactSpec};
use crate::client::semantic::spog::query::query_spog::{
    AllCertifyVulnTreeMetadata, AllCertifyVulnTreePackage, AllCertifyVulnTreePackageNamespaces,
    AllCertifyVulnTreePackageNamespacesNames, AllCertifyVulnTreePackageNamespacesNamesVersions,
    AllCertifyVulnTreePackageNamespacesNamesVersionsQualifiers, AllCertifyVulnTreeVulnerability,
    AllCertifyVulnTreeVulnerabilityVulnerabilityIDs,
};

type Time = chrono::DateTime<Utc>;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/client/intrinsic/schema.json",
    query_path = "src/client/semantic/spog/spog.gql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct QuerySpog;

impl From<&allCertifyVEXStatementTree> for CertifyVexStatement {
    fn from(value: &allCertifyVEXStatementTree) -> Self {
        Self {
            id: value.id.clone(),
            subject: PackageOrArtifact::from(&value.subject),
            vulnerability: Vulnerability::from(&value.vulnerability),
            status: VexStatus::from(&value.status),
            vex_justification: VexJustification::from(&value.vex_justification),
            statement: value.statement.clone(),
            status_notes: value.status_notes.clone(),
            known_since: value.known_since,
            origin: value.origin.clone(),
            collector: value.collector.clone(),
        }
    }
}

impl From<&QSVexStatus> for VexStatus {
    fn from(value: &QSVexStatus) -> Self {
        match value {
            QSVexStatus::NOT_AFFECTED => Self::NotAffected,
            QSVexStatus::AFFECTED => Self::Affected,
            QSVexStatus::FIXED => Self::Fixed,
            QSVexStatus::UNDER_INVESTIGATION => Self::UnderInvestigation,
            QSVexStatus::Other(inner) => Self::Other(inner.clone()),
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

impl From<&QSVexJustification> for VexJustification {
    fn from(value: &QSVexJustification) -> Self {
        match value {
            QSVexJustification::COMPONENT_NOT_PRESENT => Self::ComponentNotPresent,
            QSVexJustification::VULNERABLE_CODE_NOT_PRESENT => Self::VulnerableCodeNotPresent,
            QSVexJustification::VULNERABLE_CODE_NOT_IN_EXECUTE_PATH => Self::VulnerableCodeNotInExecutePath,
            QSVexJustification::VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY => {
                Self::VulnerableCodeCannotBeControlledByAdversary
            }
            QSVexJustification::INLINE_MITIGATIONS_ALREADY_EXIST => Self::InlineMitigationsAlreadyExist,
            QSVexJustification::NOT_PROVIDED => Self::NotProvided,
            QSVexJustification::Other(inner) => Self::Other(inner.clone()),
        }
    }
}

impl From<&QSPackage> for Package {
    fn from(value: &QSPackage) -> Self {
        Self {
            id: value.id.clone(),
            r#type: value.type_.clone(),
            namespaces: value.namespaces.iter().map(|e| e.into()).collect(),
        }
    }
}

impl From<&AllPkgTreeNamespaces> for PackageNamespace {
    fn from(value: &AllPkgTreeNamespaces) -> Self {
        Self {
            id: value.id.clone(),
            namespace: value.namespace.clone(),
            names: value.names.iter().map(|e| e.into()).collect(),
        }
    }
}

impl From<&AllPkgTreeNamespacesNames> for PackageName {
    fn from(value: &AllPkgTreeNamespacesNames) -> Self {
        Self {
            id: value.id.clone(),
            name: value.name.clone(),
            versions: value.versions.iter().map(|e| e.into()).collect(),
        }
    }
}

impl From<&AllPkgTreeNamespacesNamesVersions> for PackageVersion {
    fn from(value: &AllPkgTreeNamespacesNamesVersions) -> Self {
        Self {
            id: value.id.clone(),
            version: value.version.clone(),
            qualifiers: value.qualifiers.iter().map(|e| e.into()).collect(),
            subpath: value.subpath.clone(),
        }
    }
}

impl From<&AllPkgTreeNamespacesNamesVersionsQualifiers> for PackageQualifier {
    fn from(value: &AllPkgTreeNamespacesNamesVersionsQualifiers) -> Self {
        Self {
            key: value.key.clone(),
            value: value.value.clone(),
        }
    }
}

// VULN

impl From<&allCertifyVulnTree> for CertifyVuln {
    fn from(value: &allCertifyVulnTree) -> Self {
        Self {
            id: value.id.clone(),
            package: (&value.package).into(),
            vulnerability: (&value.vulnerability).into(),
            metadata: (&value.metadata).into(),
        }
    }
}

impl From<&AllCertifyVulnTreePackage> for Package {
    fn from(value: &AllCertifyVulnTreePackage) -> Self {
        Self {
            id: value.id.clone(),
            r#type: value.type_.clone(),
            namespaces: value.namespaces.iter().map(|e| e.into()).collect(),
        }
    }
}

impl From<&AllCertifyVulnTreeVulnerability> for Vulnerability {
    fn from(value: &AllCertifyVulnTreeVulnerability) -> Self {
        Self {
            id: value.id.clone(),
            r#type: value.type_.clone(),
            vulnerability_ids: value.vulnerability_i_ds.iter().map(|e| e.into()).collect(),
        }
    }
}

impl From<&AllCertifyVulnTreeMetadata> for ScanMetadata {
    fn from(value: &AllCertifyVulnTreeMetadata) -> Self {
        Self {
            db_uri: value.db_uri.clone(),
            db_version: value.db_version.clone(),
            scanner_uri: value.scanner_uri.clone(),
            scanner_version: value.scanner_version.clone(),
            time_scanned: value.time_scanned,
            origin: value.origin.clone(),
            collector: value.collector.clone(),
            document_ref: value.document_ref.clone(),
        }
    }
}

impl From<&AllCertifyVulnTreePackageNamespaces> for PackageNamespace {
    fn from(value: &AllCertifyVulnTreePackageNamespaces) -> Self {
        Self {
            id: value.id.clone(),
            namespace: value.namespace.clone(),
            names: value.names.iter().map(|e| e.into()).collect(),
        }
    }
}

impl From<&AllCertifyVulnTreeVulnerabilityVulnerabilityIDs> for VulnerabilityId {
    fn from(value: &AllCertifyVulnTreeVulnerabilityVulnerabilityIDs) -> Self {
        Self {
            id: value.id.clone(),
            vulnerability_id: value.vulnerability_id.clone(),
        }
    }
}

impl From<&AllCertifyVulnTreePackageNamespacesNames> for PackageName {
    fn from(value: &AllCertifyVulnTreePackageNamespacesNames) -> Self {
        Self {
            id: value.id.clone(),
            name: value.name.clone(),
            versions: value.versions.iter().map(|e| e.into()).collect(),
        }
    }
}

impl From<&AllCertifyVulnTreePackageNamespacesNamesVersions> for PackageVersion {
    fn from(value: &AllCertifyVulnTreePackageNamespacesNamesVersions) -> Self {
        Self {
            id: value.id.clone(),
            version: value.version.clone(),
            qualifiers: value.qualifiers.iter().map(|e| e.into()).collect(),
            subpath: value.subpath.clone(),
        }
    }
}

impl From<&AllCertifyVulnTreePackageNamespacesNamesVersionsQualifiers> for PackageQualifier {
    fn from(value: &AllCertifyVulnTreePackageNamespacesNamesVersionsQualifiers) -> Self {
        Self {
            key: value.key.clone(),
            value: value.value.clone(),
        }
    }
}

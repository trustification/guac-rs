mod query;

use crate::client::graph::Node;
use crate::client::intrinsic::spog::query::QuerySpog;

use super::certify_vex_statement::{self, CertifyVexStatement, VexJustification, VexStatus};
use super::vulnerability::{Vulnerability, VulnerabilityId};
use crate::client::intrinsic::package::{
    Package, PackageName, PackageNamespace, PackageQualifier, PackageQualifierSpec, PackageVersion,
    PkgSpec,
};
use crate::client::intrinsic::spog::query::query_spog::allCertifyVEXStatementTree;
use crate::client::intrinsic::spog::query::query_spog::QuerySpogFindTopLevelPackagesRelatedToVulnerability as QS;
use crate::client::intrinsic::spog::query::query_spog::QuerySpogFindTopLevelPackagesRelatedToVulnerabilityOnPackage as QSPackage;
use crate::client::intrinsic::spog::query::query_spog::QuerySpogFindTopLevelPackagesRelatedToVulnerabilityOnPackageNamespaces as QSPackageNamespaces;
use crate::client::intrinsic::spog::query::query_spog::QuerySpogFindTopLevelPackagesRelatedToVulnerabilityOnPackageNamespacesNames as QSPackageNamespacesNames;
use crate::client::intrinsic::spog::query::query_spog::QuerySpogFindTopLevelPackagesRelatedToVulnerabilityOnPackageNamespacesNamesVersions as QSPackageNamespacesNamesVersions;
use crate::client::intrinsic::spog::query::query_spog::QuerySpogFindTopLevelPackagesRelatedToVulnerabilityOnPackageNamespacesNamesVersionsQualifiers as QSPackageNamespacesNamesVersionsQualifiers;
use crate::client::intrinsic::spog::query::query_spog::VexJustification as QSVexJustification;
use crate::client::intrinsic::spog::query::query_spog::VexStatus as QSVexStatus;
use crate::client::intrinsic::spog::query::query_spog::{
    AllCertifyVexStatementTreeSubject, AllCertifyVexStatementTreeSubjectOnPackage,
    AllCertifyVexStatementTreeSubjectOnPackageNamespaces,
    AllCertifyVexStatementTreeSubjectOnPackageNamespacesNames,
    AllCertifyVexStatementTreeSubjectOnPackageNamespacesNamesVersions,
    AllCertifyVexStatementTreeSubjectOnPackageNamespacesNamesVersionsQualifiers,
    AllCertifyVexStatementTreeVulnerability,
    AllCertifyVexStatementTreeVulnerabilityVulnerabilityIDs,
};
use crate::client::intrinsic::{
    IntrinsicGuacClient, PackageOrArtifact, PackageOrArtifactInput, PackageOrArtifactSpec,
};
use crate::client::{Error, Id};
use chrono::Utc;
use graphql_client::reqwest::post_graphql;
use graphql_client::GraphQLQuery;
use packageurl::PackageUrl;
use serde_json::json;

type Time = chrono::DateTime<Utc>;

impl IntrinsicGuacClient {
    pub async fn product_by_cve(&self, vulnerability_id: &str) -> Result<Vec<ProductByCve>, Error> {
        use self::query::query_spog;

        let variables = query_spog::Variables {
            vulnerability_id: vulnerability_id.to_string(),
        };
        let response_body =
            post_graphql::<QuerySpog, _>(self.client(), self.url(), variables).await?;

        if let Some(errors) = response_body.errors {
            return Err(Error::GraphQL(errors));
        }

        let data: <QuerySpog as GraphQLQuery>::ResponseData =
            response_body.data.ok_or(Error::GraphQL(vec![]))?;
        let mut res = Vec::new();

        for entry in &data.find_top_level_packages_related_to_vulnerability {
            let len = entry.len();
            let root = match &entry[len - 1] {
                QS::Package(inner) => Package::from(inner),
                _ => return Err(Error::GraphQL(vec![])),
            };

            let vex = match &entry[0] {
                QS::CertifyVEXStatement(inner) => CertifyVexStatement::from(inner),
                _ => return Err(Error::GraphQL(vec![])),
            };
            let mut path = Vec::new();
            for value in &entry[1..len - 1] {
                match value {
                    QS::Package(inner) => {
                        path.push(Package::from(inner));
                    }
                    val => {
                        //skipping
                    }
                }
            }
            let item = ProductByCve { root, vex, path };
            res.push(item);
        }

        Ok(res)
    }
}

#[derive(Debug, Clone)]
pub struct ProductByCve {
    pub root: Package,
    pub vex: CertifyVexStatement,
    pub path: Vec<Package>,
}

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
            vulnerability_ids: value
                .vulnerability_i_ds
                .iter()
                .map(|inner| inner.into())
                .collect(),
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

impl From<&AllCertifyVexStatementTreeSubjectOnPackageNamespacesNamesVersionsQualifiers>
    for PackageQualifier
{
    fn from(
        value: &AllCertifyVexStatementTreeSubjectOnPackageNamespacesNamesVersionsQualifiers,
    ) -> Self {
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
            QSVexJustification::VULNERABLE_CODE_NOT_IN_EXECUTE_PATH => {
                Self::VulnerableCodeNotInExecutePath
            }
            QSVexJustification::VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY => {
                Self::VulnerableCodeCannotBeControlledByAdversary
            }
            QSVexJustification::INLINE_MITIGATIONS_ALREADY_EXIST => {
                Self::InlineMitigationsAlreadyExist
            }
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

impl From<&QSPackageNamespaces> for PackageNamespace {
    fn from(value: &QSPackageNamespaces) -> Self {
        Self {
            id: value.id.clone(),
            namespace: value.namespace.clone(),
            names: value.names.iter().map(|e| e.into()).collect(),
        }
    }
}

impl From<&QSPackageNamespacesNames> for PackageName {
    fn from(value: &QSPackageNamespacesNames) -> Self {
        Self {
            id: value.id.clone(),
            name: value.name.clone(),
            versions: value.versions.iter().map(|e| e.into()).collect(),
        }
    }
}

impl From<&QSPackageNamespacesNamesVersions> for PackageVersion {
    fn from(value: &QSPackageNamespacesNamesVersions) -> Self {
        Self {
            id: value.id.clone(),
            version: value.version.clone(),
            qualifiers: value.qualifiers.iter().map(|e| e.into()).collect(),
            subpath: value.subpath.clone(),
        }
    }
}

impl From<&QSPackageNamespacesNamesVersionsQualifiers> for PackageQualifier {
    fn from(value: &QSPackageNamespacesNamesVersionsQualifiers) -> Self {
        Self {
            key: value.key.clone(),
            value: value.value.clone(),
        }
    }
}

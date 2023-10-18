mod query;

use crate::client::graph::Node;
use crate::client::intrinsic::spog::query::QuerySpog;

use crate::client::intrinsic::{
    IntrinsicGuacClient, PackageOrArtifact, PackageOrArtifactInput, PackageOrArtifactSpec,
};
use crate::client::{Error, Id};
use graphql_client::GraphQLQuery;
use graphql_client::reqwest::post_graphql;
use packageurl::PackageUrl;
use serde_json::json;
use crate::client::intrinsic::spog::query::query_spog::QuerySpogFindTopLevelPackagesRelatedToVulnerability as QS;
use crate::client::intrinsic::spog::query::query_spog::QuerySpogFindTopLevelPackagesRelatedToVulnerabilityOnPackage as QSPackage;
use crate::client::intrinsic::spog::query::query_spog::QuerySpogFindTopLevelPackagesRelatedToVulnerabilityOnPackageNamespaces as QSPackageNamespaces;
use crate::client::intrinsic::spog::query::query_spog::QuerySpogFindTopLevelPackagesRelatedToVulnerabilityOnPackageNamespacesNames as QSPackageNamespacesNames;
use crate::client::intrinsic::spog::query::query_spog::QuerySpogFindTopLevelPackagesRelatedToVulnerabilityOnPackageNamespacesNamesVersions as QSPackageNamespacesNamesVersions;
use crate::client::intrinsic::spog::query::query_spog::QuerySpogFindTopLevelPackagesRelatedToVulnerabilityOnPackageNamespacesNamesVersionsQualifiers as QSPackageNamespacesNamesVersionsQualifiers;
use crate::client::intrinsic::spog::query::query_spog::QuerySpogFindTopLevelPackagesRelatedToVulnerabilityOnCertifyVEXStatement as QSVex;
use crate::client::intrinsic::spog::query::query_spog::QuerySpogFindTopLevelPackagesRelatedToVulnerabilityOnCertifyVexStatementVulnerability as QSVexVulnerability;
use crate::client::intrinsic::spog::query::query_spog::QuerySpogFindTopLevelPackagesRelatedToVulnerabilityOnCertifyVexStatementVulnerabilityVulnerabilityIDs as QSVexVulnerabilityID;
use crate::client::intrinsic::spog::query::query_spog::VexStatus;

use super::certify_vex::{CertifyVEXStatement, self};
use super::package::{Package, PackageNamespace, PackageName, PackageVersion, PackageQualifier};
use super::vulnerability::{Vulnerability, VulnerabilityId};


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

        let data: <QuerySpog as GraphQLQuery>::ResponseData = response_body.data.ok_or(Error::GraphQL(vec![]))?;
        let mut res = Vec::new();

        for entry in &data.find_top_level_packages_related_to_vulnerability {
            let len = entry.len();
            let root = match &entry[len - 1] {
                QS::Package(inner) => {
                    Package::from(inner)
                },
                _ => return Err(Error::GraphQL(vec![]))
            };

            let vex = match &entry[0] {
                QS::CertifyVEXStatement(inner) => {
                    CertifyVEXStatement::from(inner)
                },
                _ => return Err(Error::GraphQL(vec![]))
            };
            let mut path = Vec::new();
            for value in &entry[1..len-1] {
                match value {
                    QS::Package(inner) => {
                        path.push(Package::from(inner));
                    },
                    val => { 
                        //skipping
                    },
                }
            }
            let item = ProductByCve {
                root,
                vex,
                path,
            };
            res.push(item);
        }

        Ok(res)
    }
}

#[derive(Debug, Clone)]
pub struct ProductByCve {
    pub root: Package,
    pub vex: CertifyVEXStatement,
    pub path: Vec<Package>,
}

impl From<&QSVexVulnerabilityID> for VulnerabilityId {
    fn from(value: &QSVexVulnerabilityID) -> Self {
        Self {
            vulnerability_id: value.vulnerability_id.clone(),
            id: "1".to_string(), //TODO
        }
    }
}

impl From<&QSVexVulnerability> for Vulnerability {
    fn from(value: &QSVexVulnerability) -> Self {
        Self {
            vulnerability_ids: value.vulnerability_i_ds.iter().map(|e| e.into()).collect(),
            r#type: "cve".to_string(),
            id: "1".to_string(), //TODO
        }
    }
}

impl From<&VexStatus> for certify_vex::VexStatus {
    fn from(value: &VexStatus) -> Self {
        match value {
            VexStatus::NOT_AFFECTED => Self::NotAffected,
            VexStatus::AFFECTED => Self::Affected,
            VexStatus::UNDER_INVESTIGATION => Self::UnderInvestigation,
            VexStatus::FIXED => Self::Fixed,
            VexStatus::Other(_) => todo!(),
        }
    }
}

impl From<&QSVex> for CertifyVEXStatement {
    fn from(value: &QSVex) -> Self {
        Self {
            vulnerability: Vulnerability::from(&value.vulnerability),
            status: certify_vex::VexStatus::from(&value.status),
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
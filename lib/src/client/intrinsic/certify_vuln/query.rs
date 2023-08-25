use crate::client::intrinsic::certify_vuln::query::query_certify_vuln::{
    allCertifyVulnTree, AllCertifyVulnTreeMetadata, AllCertifyVulnTreePackage,
    AllCertifyVulnTreePackageNamespaces, AllCertifyVulnTreePackageNamespacesNames,
    AllCertifyVulnTreePackageNamespacesNamesVersions,
    AllCertifyVulnTreePackageNamespacesNamesVersionsQualifiers, AllCertifyVulnTreeVulnerability,
    AllCertifyVulnTreeVulnerabilityVulnerabilityIDs,
};
use crate::client::intrinsic::certify_vuln::{CertifyVuln, CertifyVulnSpec, ScanMetadata};
use crate::client::intrinsic::package::{
    Package, PackageName, PackageNamespace, PackageQualifier, PackageQualifierSpec, PackageVersion,
    PkgSpec,
};
use crate::client::intrinsic::vulnerability::{Vulnerability, VulnerabilityId, VulnerabilitySpec};
use graphql_client::GraphQLQuery;
use packageurl::PackageUrl;
use std::str::FromStr;

//use self::query_certify_vuln_by_package::{PackageQualifierSpec, PkgSpec};

use super::Time;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/client/intrinsic/schema.json",
    query_path = "src/client/intrinsic/certify_vuln/certify_vuln.gql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct QueryCertifyVuln;

impl From<&CertifyVulnSpec> for query_certify_vuln::CertifyVulnSpec {
    fn from(value: &CertifyVulnSpec) -> Self {
        Self {
            id: value.id.clone(),
            package: value.package.as_ref().map(|inner| inner.into()),
            vulnerability: value.vulnerability.as_ref().map(|inner| inner.into()),
            time_scanned: value.time_scanned,
            db_uri: value.db_uri.clone(),
            db_version: value.db_version.clone(),
            scanner_uri: value.scanner_uri.clone(),
            scanner_version: value.scanner_version.clone(),
            origin: value.origin.clone(),
            collector: value.collector.clone(),
        }
    }
}

impl From<&PkgSpec> for query_certify_vuln::PkgSpec {
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

impl From<&PackageQualifierSpec> for query_certify_vuln::PackageQualifierSpec {
    fn from(value: &PackageQualifierSpec) -> Self {
        Self {
            key: value.key.clone(),
            value: value.value.clone(),
        }
    }
}

impl From<&VulnerabilitySpec> for query_certify_vuln::VulnerabilitySpec {
    fn from(value: &VulnerabilitySpec) -> Self {
        Self {
            id: value.id.clone(),
            type_: value.r#type.clone(),
            vulnerability_id: value.vulnerability_id.clone(),
            no_vuln: value.no_vuln,
        }
    }
}

impl From<&query_certify_vuln::allCertifyVulnTree> for CertifyVuln {
    fn from(value: &allCertifyVulnTree) -> Self {
        Self {
            id: value.id.clone(),
            package: (&value.package).into(),
            vulnerability: (&value.vulnerability).into(),
            metadata: (&value.metadata).into(),
        }
    }
}

impl From<&query_certify_vuln::AllCertifyVulnTreePackage> for Package {
    fn from(value: &query_certify_vuln::AllCertifyVulnTreePackage) -> Self {
        Self {
            id: value.id.clone(),
            r#type: value.type_.clone(),
            namespaces: value.namespaces.iter().map(|e| e.into()).collect(),
        }
    }
}

impl From<&query_certify_vuln::AllCertifyVulnTreeVulnerability> for Vulnerability {
    fn from(value: &AllCertifyVulnTreeVulnerability) -> Self {
        Self {
            id: value.id.clone(),
            r#type: value.type_.clone(),
            vulnerability_ids: value.vulnerability_i_ds.iter().map(|e| e.into()).collect(),
        }
    }
}

impl From<&query_certify_vuln::AllCertifyVulnTreeMetadata> for ScanMetadata {
    fn from(value: &AllCertifyVulnTreeMetadata) -> Self {
        Self {
            db_uri: value.db_uri.clone(),
            db_version: value.db_version.clone(),
            scanner_uri: value.scanner_uri.clone(),
            scanner_version: value.scanner_version.clone(),
            time_scanned: value.time_scanned,
            origin: value.origin.clone(),
            collector: value.collector.clone(),
        }
    }
}

impl From<&query_certify_vuln::AllCertifyVulnTreePackageNamespaces> for PackageNamespace {
    fn from(value: &AllCertifyVulnTreePackageNamespaces) -> Self {
        Self {
            id: value.id.clone(),
            namespace: value.namespace.clone(),
            names: value.names.iter().map(|e| e.into()).collect(),
        }
    }
}

impl From<&query_certify_vuln::AllCertifyVulnTreeVulnerabilityVulnerabilityIDs>
    for VulnerabilityId
{
    fn from(value: &AllCertifyVulnTreeVulnerabilityVulnerabilityIDs) -> Self {
        Self {
            id: value.id.clone(),
            vulnerability_id: value.vulnerability_id.clone(),
        }
    }
}

impl From<&query_certify_vuln::AllCertifyVulnTreePackageNamespacesNames> for PackageName {
    fn from(value: &AllCertifyVulnTreePackageNamespacesNames) -> Self {
        Self {
            id: value.id.clone(),
            name: value.name.clone(),
            versions: value.versions.iter().map(|e| e.into()).collect(),
        }
    }
}

impl From<&query_certify_vuln::AllCertifyVulnTreePackageNamespacesNamesVersions>
    for PackageVersion
{
    fn from(value: &AllCertifyVulnTreePackageNamespacesNamesVersions) -> Self {
        Self {
            id: value.id.clone(),
            version: value.version.clone(),
            qualifiers: value.qualifiers.iter().map(|e| e.into()).collect(),
            subpath: value.subpath.clone(),
        }
    }
}

impl From<&query_certify_vuln::AllCertifyVulnTreePackageNamespacesNamesVersionsQualifiers>
    for PackageQualifier
{
    fn from(value: &AllCertifyVulnTreePackageNamespacesNamesVersionsQualifiers) -> Self {
        Self {
            key: value.key.clone(),
            value: value.value.clone(),
        }
    }
}

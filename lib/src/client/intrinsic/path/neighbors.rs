use crate::client::graph::{Edge, Node};
use crate::client::intrinsic::certify_vuln::{CertifyVuln, ScanMetadata};
use crate::client::intrinsic::is_dependency::{DependencyType, IsDependency};
use crate::client::intrinsic::package::{Package, PackageName, PackageNamespace, PackageQualifier, PackageVersion};
use crate::client::intrinsic::vulnerability::{Vulnerability, VulnerabilityId};
use chrono::Utc;
use graphql_client::GraphQLQuery;

type Time = chrono::DateTime<Utc>;
#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/client/intrinsic/schema.json",
    query_path = "src/client/intrinsic/path/path.gql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct Neighbors;

impl From<&Edge> for neighbors::Edge {
    fn from(value: &Edge) -> Self {
        match value {
            Edge::ArtifactCertifyBad => Self::ARTIFACT_CERTIFY_BAD,
            Edge::ArtifactCertifyGood => Self::ARTIFACT_CERTIFY_GOOD,
            Edge::ArtifactCertifyVexStatement => Self::ARTIFACT_CERTIFY_VEX_STATEMENT,
            Edge::ArtifactHashEqual => Self::ARTIFACT_HASH_EQUAL,
            Edge::ArtifactHasSbom => Self::ARTIFACT_HAS_SBOM,
            Edge::ArtifactHasSlsa => Self::ARTIFACT_HAS_SLSA,
            Edge::ArtifactIsOccurrence => Self::ARTIFACT_IS_OCCURRENCE,
            Edge::ArtifactHasMetadata => Self::ARTIFACT_HAS_METADATA,
            Edge::ArtifactPointOfContact => Self::ARTIFACT_POINT_OF_CONTACT,
            Edge::BuilderHasSlsa => Self::BUILDER_HAS_SLSA,
            Edge::VulnerabilityCertifyVexStatement => Self::VULNERABILITY_CERTIFY_VEX_STATEMENT,
            Edge::VulnerabilityCertifyVuln => Self::VULNERABILITY_CERTIFY_VULN,
            Edge::VulnerabilityVulnEqual => Self::VULNERABILITY_VULN_EQUAL,
            Edge::VulnerabilityVulnMetadata => {
                todo!("weirdly not mapped?")
                //Self::VULNERABILITY_VULN_METADATA
            }
            Edge::PackageCertifyBad => Self::PACKAGE_CERTIFY_BAD,
            Edge::PackageCertifyGood => Self::PACKAGE_CERTIFY_GOOD,
            Edge::PackageCertifyVexStatement => Self::PACKAGE_CERTIFY_VEX_STATEMENT,
            Edge::PackageCertifyVuln => Self::PACKAGE_CERTIFY_VULN,
            Edge::PackageHasSbom => Self::PACKAGE_HAS_SBOM,
            Edge::PackageHasSourceAt => Self::PACKAGE_HAS_SOURCE_AT,
            Edge::PackageIsDependency => Self::PACKAGE_IS_DEPENDENCY,
            Edge::PackageIsOccurrence => Self::PACKAGE_IS_OCCURRENCE,
            Edge::PackagePkgEqual => Self::PACKAGE_PKG_EQUAL,
            Edge::PackageHasMetadata => Self::PACKAGE_HAS_METADATA,
            Edge::PackagePointOfContact => Self::PACKAGE_POINT_OF_CONTACT,
            Edge::SourceCertifyBad => Self::SOURCE_CERTIFY_BAD,
            Edge::SourceCertifyGood => Self::SOURCE_CERTIFY_GOOD,
            Edge::SourceCertifyScorecard => Self::SOURCE_CERTIFY_SCORECARD,
            Edge::SourceHasSourceAt => Self::SOURCE_HAS_SOURCE_AT,
            Edge::SourceIsOccurrence => Self::SOURCE_IS_OCCURRENCE,
            Edge::SourceHasMetadata => Self::SOURCE_HAS_METADATA,
            Edge::SourcePointOfContact => Self::SOURCE_POINT_OF_CONTACT,
            Edge::CertifyBadArtifact => Self::CERTIFY_BAD_ARTIFACT,
            Edge::CertifyBadPackage => Self::CERTIFY_BAD_PACKAGE,
            Edge::CertifyBadSource => Self::CERTIFY_BAD_SOURCE,
            Edge::CertifyGoodArtifact => Self::CERTIFY_GOOD_ARTIFACT,
            Edge::CertifyGoodPackage => Self::CERTIFY_GOOD_PACKAGE,
            Edge::CertifyGoodSource => Self::CERTIFY_GOOD_SOURCE,
            Edge::CertifyScorecardSource => Self::CERTIFY_SCORECARD_SOURCE,
            Edge::CertifyVexStatementArtifact => Self::CERTIFY_VEX_STATEMENT_ARTIFACT,
            Edge::CertifyVexStatementVulnerability => Self::CERTIFY_VEX_STATEMENT_VULNERABILITY,
            Edge::CertifyVexStatementPackage => Self::CERTIFY_VEX_STATEMENT_PACKAGE,
            Edge::CertifyVulnVulnerability => Self::CERTIFY_VULN_VULNERABILITY,
            Edge::CertifyVulnPackage => Self::CERTIFY_VULN_PACKAGE,
            Edge::HashEqualArtifact => Self::HASH_EQUAL_ARTIFACT,
            Edge::HasSbomArtifact => Self::HAS_SBOM_ARTIFACT,
            Edge::HasSbomPackage => Self::HAS_SBOM_PACKAGE,
            Edge::HasSlsaBuiltBy => Self::HAS_SLSA_BUILT_BY,
            Edge::HasSlsaMaterials => Self::HAS_SLSA_MATERIALS,
            Edge::HasSlsaSubject => Self::HAS_SLSA_SUBJECT,
            Edge::HasSourceAtPackage => Self::HAS_SOURCE_AT_PACKAGE,
            Edge::HasSourceAtSource => Self::HAS_SOURCE_AT_SOURCE,
            Edge::IsDependencyPackage => Self::IS_DEPENDENCY_PACKAGE,
            Edge::IsOccurrenceArtifact => Self::IS_OCCURRENCE_ARTIFACT,
            Edge::IsOccurrencePackage => Self::IS_OCCURRENCE_PACKAGE,
            Edge::IsOccurrenceSource => Self::IS_OCCURRENCE_SOURCE,
            Edge::VulnEqualVulnerability => Self::VULN_EQUAL_VULNERABILITY,
            Edge::PkgEqualPackage => Self::PKG_EQUAL_PACKAGE,
            Edge::HasMetadataPackage => Self::HAS_METADATA_PACKAGE,
            Edge::HasMetadataArtifact => Self::HAS_METADATA_ARTIFACT,
            Edge::HasMetadataSource => Self::HAS_METADATA_SOURCE,
            Edge::PointOfContactPackage => Self::POINT_OF_CONTACT_PACKAGE,
            Edge::PointOfContactArtifact => Self::POINT_OF_CONTACT_ARTIFACT,
            Edge::PointOfContactSource => Self::POINT_OF_CONTACT_SOURCE,
            Edge::VulnMetadataVulnerability => {
                todo!("again, weirdly not mapped")
                //Self::VULN_METADATA_VULNERABILITY
            }
        }
    }
}

impl From<&neighbors::allNodeTree> for Node {
    fn from(value: &neighbors::allNodeTree) -> Self {
        println!("{:?}", value);
        match value {
            neighbors::allNodeTree::Package(inner) => Node::Package(inner.into()),
            neighbors::allNodeTree::IsDependency(inner) => Node::IsDependency(inner.into()),
            neighbors::allNodeTree::CertifyVuln(inner) => Node::CertifyVuln(inner.into()),
            neighbors::allNodeTree::Vulnerability(inner) => Node::Vulnerability(inner.into()),
            _ => todo!("neighbors node type not implemented"),
        }
    }
}

impl From<&neighbors::allPackageTree> for Package {
    fn from(value: &neighbors::allPackageTree) -> Self {
        Self {
            id: value.id.clone(),
            r#type: value.type_.clone(),
            namespaces: value.namespaces.iter().map(|e| e.into()).collect(),
        }
    }
}

impl From<&neighbors::allIsDependencyTree> for IsDependency {
    fn from(value: &neighbors::allIsDependencyTree) -> Self {
        Self {
            id: value.id.clone(),
            package: (&value.package).into(),
            dependent_package: (&value.dependency_package).into(),
            version_range: value.version_range.clone(),
            dependency_type: (&value.dependency_type).into(),
            justification: value.justification.clone(),
            origin: value.origin.clone(),
            collector: value.collector.clone(),
        }
    }
}

impl From<&neighbors::allCertifyVulnTree> for CertifyVuln {
    fn from(value: &neighbors::allCertifyVulnTree) -> Self {
        Self {
            id: value.id.clone(),
            package: (&value.package).into(),
            vulnerability: (&value.vulnerability).into(),
            metadata: (&value.metadata).into(),
        }
    }
}

impl From<&neighbors::AllCertifyVulnTreeMetadata> for ScanMetadata {
    fn from(value: &neighbors::AllCertifyVulnTreeMetadata) -> Self {
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

impl From<&neighbors::AllCertifyVulnTreeVulnerability> for Vulnerability {
    fn from(value: &neighbors::AllCertifyVulnTreeVulnerability) -> Self {
        Self {
            id: value.id.clone(),
            r#type: value.type_.clone(),
            vulnerability_ids: value.vulnerability_i_ds.iter().map(|e| e.into()).collect(),
        }
    }
}

impl From<&neighbors::AllCertifyVulnTreeVulnerabilityVulnerabilityIDs> for VulnerabilityId {
    fn from(value: &neighbors::AllCertifyVulnTreeVulnerabilityVulnerabilityIDs) -> Self {
        Self {
            id: value.id.clone(),
            vulnerability_id: value.vulnerability_id.clone(),
        }
    }
}

impl From<&neighbors::DependencyType> for DependencyType {
    fn from(value: &neighbors::DependencyType) -> Self {
        match value {
            neighbors::DependencyType::DIRECT => Self::Direct,
            neighbors::DependencyType::INDIRECT => Self::Indirect,
            neighbors::DependencyType::UNKNOWN => Self::Unknown,
            neighbors::DependencyType::Other(_) => Self::Unknown,
        }
    }
}

impl From<&neighbors::AllPackageTreeNamespaces> for PackageNamespace {
    fn from(value: &neighbors::AllPackageTreeNamespaces) -> Self {
        Self {
            id: value.id.clone(),
            namespace: value.namespace.clone(),
            names: value.names.iter().map(|e| e.into()).collect(),
        }
    }
}

impl From<&neighbors::AllPackageTreeNamespacesNames> for PackageName {
    fn from(value: &neighbors::AllPackageTreeNamespacesNames) -> Self {
        Self {
            id: value.id.clone(),
            name: value.name.clone(),
            versions: value.versions.iter().map(|e| e.into()).collect(),
        }
    }
}

impl From<&neighbors::AllPackageTreeNamespacesNamesVersions> for PackageVersion {
    fn from(value: &neighbors::AllPackageTreeNamespacesNamesVersions) -> Self {
        Self {
            id: value.id.clone(),
            version: value.version.clone(),
            qualifiers: value.qualifiers.iter().map(|e| e.into()).collect(),
            subpath: value.subpath.clone(),
        }
    }
}

impl From<&neighbors::AllPackageTreeNamespacesNamesVersionsQualifiers> for PackageQualifier {
    fn from(value: &neighbors::AllPackageTreeNamespacesNamesVersionsQualifiers) -> Self {
        Self {
            key: value.key.clone(),
            value: value.value.clone(),
        }
    }
}

impl From<&neighbors::allVulnerabilityTree> for Vulnerability {
    fn from(value: &neighbors::allVulnerabilityTree) -> Self {
        Self {
            id: value.id.clone(),
            r#type: value.type_.clone(),
            vulnerability_ids: value.vulnerability_i_ds.iter().map(|e| e.into()).collect(),
        }
    }
}

impl From<&neighbors::AllVulnerabilityTreeVulnerabilityIDs> for VulnerabilityId {
    fn from(value: &neighbors::AllVulnerabilityTreeVulnerabilityIDs) -> Self {
        Self {
            id: value.id.clone(),
            vulnerability_id: value.vulnerability_id.clone(),
        }
    }
}

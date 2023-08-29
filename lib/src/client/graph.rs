use crate::client::intrinsic::certify_bad::CertifyBad;
use crate::client::intrinsic::certify_good::CertifyGood;
use crate::client::intrinsic::certify_vuln::CertifyVuln;
use crate::client::intrinsic::is_dependency::IsDependency;
use crate::client::intrinsic::package::Package;
use crate::client::intrinsic::vulnerability::{Vulnerability, VulnerabilityId};
use crate::client::Id;

#[derive(Clone, Debug)]
pub enum Node {
    Package(Package),
    //...
    IsDependency(IsDependency),
    VulnerabilityId(VulnerabilityId),
    CertifyGood(CertifyGood),
    CertifyBad(CertifyBad),
    CertifyVuln(CertifyVuln),
    Vulnerability(Vulnerability),
    // ...
}

impl Node {
    pub fn id(&self) -> Id {
        match self {
            Node::Package(inner) => inner.id.clone(),
            Node::IsDependency(inner) => inner.id.clone(),
            Node::VulnerabilityId(inner) => inner.id.clone(),
            Node::CertifyGood(inner) => inner.id.clone(),
            Node::CertifyBad(inner) => inner.id.clone(),
            Node::CertifyVuln(inner) => inner.id.clone(),
            Node::Vulnerability(inner) => inner.id.clone(),
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub enum Edge {
    ArtifactCertifyBad,
    ArtifactCertifyGood,
    ArtifactCertifyVexStatement,
    ArtifactHashEqual,
    ArtifactHasSbom,
    ArtifactHasSlsa,
    ArtifactIsOccurrence,
    ArtifactHasMetadata,
    ArtifactPointOfContact,
    BuilderHasSlsa,
    VulnerabilityCertifyVexStatement,
    VulnerabilityCertifyVuln,
    VulnerabilityVulnEqual,
    VulnerabilityVulnMetadata,
    PackageCertifyBad,
    PackageCertifyGood,
    PackageCertifyVexStatement,
    PackageCertifyVuln,
    PackageHasSbom,
    PackageHasSourceAt,
    PackageIsDependency,
    PackageIsOccurrence,
    PackagePkgEqual,
    PackageHasMetadata,
    PackagePointOfContact,
    SourceCertifyBad,
    SourceCertifyGood,
    SourceCertifyScorecard,
    SourceHasSourceAt,
    SourceIsOccurrence,
    SourceHasMetadata,
    SourcePointOfContact,
    CertifyBadArtifact,
    CertifyBadPackage,
    CertifyBadSource,
    CertifyGoodArtifact,
    CertifyGoodPackage,
    CertifyGoodSource,
    CertifyScorecardSource,
    CertifyVexStatementArtifact,
    CertifyVexStatementVulnerability,
    CertifyVexStatementPackage,
    CertifyVulnVulnerability,
    CertifyVulnPackage,
    HashEqualArtifact,
    HasSbomArtifact,
    HasSbomPackage,
    HasSlsaBuiltBy,
    HasSlsaMaterials,
    HasSlsaSubject,
    HasSourceAtPackage,
    HasSourceAtSource,
    IsDependencyPackage,
    IsOccurrenceArtifact,
    IsOccurrencePackage,
    IsOccurrenceSource,
    VulnEqualVulnerability,
    PkgEqualPackage,
    HasMetadataPackage,
    HasMetadataArtifact,
    HasMetadataSource,
    PointOfContactPackage,
    PointOfContactArtifact,
    PointOfContactSource,
    VulnMetadataVulnerability,
}

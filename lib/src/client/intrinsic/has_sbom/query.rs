use crate::client::intrinsic::artifact::{Artifact, ArtifactSpec};
use crate::client::intrinsic::has_sbom::query::query_has_sbom::{
    allHasSBOMTree, AllHasSbomTreeSubject, AllHasSbomTreeSubjectOnArtifact, AllHasSbomTreeSubjectOnPackage,
    AllHasSbomTreeSubjectOnPackageNamespaces, AllHasSbomTreeSubjectOnPackageNamespacesNames,
    AllHasSbomTreeSubjectOnPackageNamespacesNamesVersions,
    AllHasSbomTreeSubjectOnPackageNamespacesNamesVersionsQualifiers,
};
use crate::client::intrinsic::has_sbom::{HasSBOM, HasSBOMSpec};
use crate::client::intrinsic::is_dependency::query::query_is_dependency;
use crate::client::intrinsic::is_dependency::{DependencyType, IsDependencySpec};
use crate::client::intrinsic::is_occurence::IsOccurrenceSpec;
use crate::client::intrinsic::package::{
    Package, PackageName, PackageNamespace, PackageQualifier, PackageQualifierSpec, PackageVersion, PkgSpec,
};
use crate::client::intrinsic::{
    PackageOrArtifact, PackageOrArtifactSpec, PackageOrSourceSpec, PackageSourceOrArtifactSpec,
};
use async_nats::connection::ShouldFlush::No;
use chrono::Utc;
use graphql_client::GraphQLQuery;

type Time = chrono::DateTime<Utc>;
#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/client/intrinsic/schema.json",
    query_path = "src/client/intrinsic/has_sbom/has_sbom.gql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct QueryHasSBOM;

impl From<&HasSBOMSpec> for query_has_sbom::HasSBOMSpec {
    fn from(value: &HasSBOMSpec) -> Self {
        Self {
            id: value.id.clone(),
            subject: value.subject.as_ref().map(|inner| inner.into()),
            uri: value.uri.clone(),
            algorithm: value.algorithm.clone(),
            digest: value.digest.clone(),
            download_location: value.download_location.clone(),
            origin: value.origin.clone(),
            collector: value.collector.clone(),
            known_since: value.known_since,
            document_ref: value.document_ref.clone(),
            included_dependencies: value
                .included_dependencies
                .as_ref()
                .map(|inner| inner.iter().map(|e| e.into()).collect()),
            included_occurrences: value
                .included_occurrences
                .as_ref()
                .map(|inner| inner.iter().map(|e| e.into()).collect()),
            included_software: value
                .included_software
                .as_ref()
                .map(|inner| inner.iter().map(|e| e.into()).collect()),
        }
    }
}

impl From<&PackageOrArtifactSpec> for query_has_sbom::PackageOrArtifactSpec {
    fn from(value: &PackageOrArtifactSpec) -> Self {
        Self {
            package: value.package.as_ref().map(|inner| inner.into()),
            artifact: None,
        }
    }
}

impl From<&PkgSpec> for query_has_sbom::PkgSpec {
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

impl From<&PackageQualifierSpec> for query_has_sbom::PackageQualifierSpec {
    fn from(value: &PackageQualifierSpec) -> Self {
        Self {
            key: value.key.clone(),
            value: value.value.clone(),
        }
    }
}

impl From<&IsDependencySpec> for query_has_sbom::IsDependencySpec {
    fn from(value: &IsDependencySpec) -> Self {
        Self {
            id: value.id.clone(),
            package: value.package.as_ref().map(|inner| inner.into()),
            dependency_package: value.dependent_package.as_ref().map(|inner| inner.into()),
            version_range: value.version_range.clone(),
            dependency_type: value.dependency_type.as_ref().map(|inner| inner.into()),
            justification: value.justification.clone(),
            origin: value.origin.clone(),
            collector: value.collector.clone(),
            document_ref: value.document_ref.clone(),
        }
    }
}

impl From<&DependencyType> for query_has_sbom::DependencyType {
    fn from(value: &DependencyType) -> Self {
        match value {
            DependencyType::Direct => Self::DIRECT,
            DependencyType::Indirect => Self::INDIRECT,
            DependencyType::Unknown => Self::UNKNOWN,
        }
    }
}

impl From<&IsOccurrenceSpec> for query_has_sbom::IsOccurrenceSpec {
    fn from(value: &IsOccurrenceSpec) -> Self {
        Self {
            id: value.id.clone(),
            subject: value.subject.as_ref().map(|inner| inner.into()),
            artifact: value.artifact.as_ref().map(|inner| inner.into()),
            justification: value.justification.clone(),
            origin: value.origin.clone(),
            collector: value.collector.clone(),
            document_ref: value.document_ref.clone(),
        }
    }
}

impl From<&PackageOrSourceSpec> for query_has_sbom::PackageOrSourceSpec {
    fn from(value: &PackageOrSourceSpec) -> Self {
        Self {
            package: value.package.as_ref().map(|inner| inner.into()),
            source: None,
        }
    }
}

impl From<&ArtifactSpec> for query_has_sbom::ArtifactSpec {
    fn from(value: &ArtifactSpec) -> Self {
        Self {
            id: value.id.clone(),
            algorithm: value.algorithm.clone(),
            digest: value.digest.clone(),
        }
    }
}

impl From<&query_has_sbom::allHasSBOMTree> for HasSBOM {
    fn from(value: &allHasSBOMTree) -> Self {
        Self {
            id: value.id.clone(),
            subject: (&value.subject).into(),
            uri: value.uri.clone(),
            algorithm: value.algorithm.clone(),
            digest: value.digest.clone(),
            download_location: value.download_location.clone(),
            origin: value.origin.clone(),
            collector: value.collector.clone(),
            known_since: None,
        }
    }
}

impl From<&query_has_sbom::AllHasSbomTreeSubject> for PackageOrArtifact {
    fn from(value: &AllHasSbomTreeSubject) -> Self {
        match value {
            AllHasSbomTreeSubject::Package(inner) => PackageOrArtifact::Package(inner.into()),
            AllHasSbomTreeSubject::Artifact(inner) => PackageOrArtifact::Artifact(inner.into()),
        }
    }
}

impl From<&AllHasSbomTreeSubjectOnPackage> for Package {
    fn from(value: &AllHasSbomTreeSubjectOnPackage) -> Self {
        Self {
            id: value.id.clone(),
            r#type: value.type_.clone(),
            namespaces: value.namespaces.iter().map(|e| e.into()).collect(),
        }
    }
}

impl From<&AllHasSbomTreeSubjectOnPackageNamespaces> for PackageNamespace {
    fn from(value: &AllHasSbomTreeSubjectOnPackageNamespaces) -> Self {
        Self {
            id: value.id.clone(),
            namespace: value.namespace.clone(),
            names: value.names.iter().map(|e| e.into()).collect(),
        }
    }
}

impl From<&AllHasSbomTreeSubjectOnPackageNamespacesNames> for PackageName {
    fn from(value: &AllHasSbomTreeSubjectOnPackageNamespacesNames) -> Self {
        Self {
            id: value.id.clone(),
            name: value.name.clone(),
            versions: value.versions.iter().map(|e| e.into()).collect(),
        }
    }
}

impl From<&AllHasSbomTreeSubjectOnPackageNamespacesNamesVersions> for PackageVersion {
    fn from(value: &AllHasSbomTreeSubjectOnPackageNamespacesNamesVersions) -> Self {
        Self {
            id: value.id.clone(),
            version: value.version.clone(),
            qualifiers: value.qualifiers.iter().map(|e| e.into()).collect(),
            subpath: value.subpath.clone(),
        }
    }
}

impl From<&AllHasSbomTreeSubjectOnPackageNamespacesNamesVersionsQualifiers> for PackageQualifier {
    fn from(value: &AllHasSbomTreeSubjectOnPackageNamespacesNamesVersionsQualifiers) -> Self {
        Self {
            key: value.key.clone(),
            value: value.value.clone(),
        }
    }
}

impl From<&AllHasSbomTreeSubjectOnArtifact> for Artifact {
    fn from(value: &AllHasSbomTreeSubjectOnArtifact) -> Self {
        Self {
            id: value.id.clone(),
            algorithm: value.algorithm.clone(),
            digest: value.digest.clone(),
        }
    }
}

use crate::client::intrinsic::has_sbom::query::query_has_sbom::{
    allHasSBOMTree, AllHasSbomTreeSubject, AllHasSbomTreeSubjectOnPackage,
    AllHasSbomTreeSubjectOnPackageNamespaces, AllHasSbomTreeSubjectOnPackageNamespacesNames,
    AllHasSbomTreeSubjectOnPackageNamespacesNamesVersions,
    AllHasSbomTreeSubjectOnPackageNamespacesNamesVersionsQualifiers,
};
use crate::client::intrinsic::has_sbom::{HasSBOM, HasSBOMSpec};
use crate::client::intrinsic::package::{
    Package, PackageName, PackageNamespace, PackageQualifier, PackageQualifierSpec, PackageVersion,
    PkgSpec,
};
use crate::client::intrinsic::{PackageOrArtifact, PackageOrArtifactSpec};
use graphql_client::GraphQLQuery;

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
            digest: value.digist.clone(),
            download_location: value.download_location.clone(),
            origin: value.origin.clone(),
            collector: value.collector.clone(),
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
        }
    }
}

impl From<&query_has_sbom::AllHasSbomTreeSubject> for PackageOrArtifact {
    fn from(value: &AllHasSbomTreeSubject) -> Self {
        match value {
            AllHasSbomTreeSubject::Package(inner) => PackageOrArtifact::Package(inner.into()),
            AllHasSbomTreeSubject::Artifact(inner) => {
                todo!()
            }
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

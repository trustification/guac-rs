use crate::client::intrinsic::package::{Package, PkgInputSpec, PkgSpec};
use crate::client::semantic::SemanticGuacClient;
use crate::client::GuacClient;
use packageurl::PackageUrl;
use reqwest::{Client, IntoUrl};
use serde::{Deserialize, Serialize};

pub mod certify_bad;
pub mod certify_good;
pub mod certify_vex_statement;
pub mod certify_vuln;
pub mod has_sbom;
pub mod is_dependency;
pub mod package;
pub mod path;
pub mod vuln_equal;
pub mod vuln_metadata;
pub mod vulnerability;

pub struct IntrinsicGuacClient {
    client: GuacClient,
}

impl IntrinsicGuacClient {
    pub(crate) fn new(client: &GuacClient) -> Self {
        Self {
            client: client.clone(),
        }
    }

    pub(crate) fn client(&self) -> &Client {
        &self.client.client
    }

    pub fn url(&self) -> impl IntoUrl {
        self.client.url.clone()
    }

    pub fn semantic(&self) -> SemanticGuacClient {
        SemanticGuacClient::new(&self.client)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum PackageSourceOrArtifact {
    Package(Package),
    // Source
    // Artifact
}

#[derive(Debug, Clone)]
pub struct PackageSourceOrArtifactSpec {
    package: Option<PkgSpec>,
    // source
    // artifact
}

impl From<PkgSpec> for PackageSourceOrArtifactSpec {
    fn from(package: PkgSpec) -> Self {
        Self {
            package: Some(package),
        }
    }
}

impl From<PackageUrl<'_>> for PackageSourceOrArtifactSpec {
    fn from(package: PackageUrl<'_>) -> Self {
        Self {
            package: Some(package.into()),
        }
    }
}

pub struct PackageSourceOrArtifactInput {
    package: Option<PkgInputSpec>,
    // source
    // artifact
}

impl From<PkgInputSpec> for PackageSourceOrArtifactInput {
    fn from(package: PkgInputSpec) -> Self {
        Self {
            package: Some(package),
        }
    }
}

impl From<PackageUrl<'_>> for PackageSourceOrArtifactInput {
    fn from(package: PackageUrl) -> Self {
        Self {
            package: Some(package.into()),
        }
    }
}

#[derive(Clone, Debug)]
pub enum PackageOrArtifact {
    Package(Package),
    //Artifact(Artifact),
}

#[derive(Clone, Debug)]
pub struct PackageOrArtifactSpec {
    package: Option<PkgSpec>,
    // artifact: Option<Artifact>,
}

#[derive(Clone, Debug)]
pub struct PackageOrArtifactInput {
    package: Option<PkgInputSpec>,
    // artifact: Option<ArtifactInputSpec>,
}

impl From<PackageUrl<'_>> for PackageOrArtifactInput {
    fn from(package: PackageUrl) -> Self {
        Self {
            package: Some(package.into()),
        }
    }
}

impl From<PackageUrl<'_>> for PackageOrArtifactSpec {
    fn from(package: PackageUrl<'_>) -> Self {
        Self {
            package: Some(package.into()),
        }
    }
}

#[derive(Copy, Clone)]
pub struct MatchFlags {
    pkg: PkgMatchType,
}

#[derive(Copy, Clone)]
pub enum PkgMatchType {
    AllVersions,
    SpecificVersion,
}

impl From<PkgMatchType> for MatchFlags {
    fn from(pkg: PkgMatchType) -> Self {
        Self { pkg }
    }
}

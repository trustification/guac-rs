use std::ops::Deref;
use reqwest::{Client, IntoUrl};
use crate::client::GuacClient;
use crate::client::intrinsic::package::{Package, PkgInputSpec, PkgSpec};
use crate::client::semantic::SemanticGuacClient;

pub mod certify_bad;
pub mod certify_good;
pub mod certify_vuln;
pub mod is_dependency;
pub mod package;
pub mod vulnerability;



pub struct IntrinsicGuacClient<'c> {
    client: &'c GuacClient
}

impl<'c> IntrinsicGuacClient<'c> {

    pub(crate) fn new(client: &'c GuacClient) -> Self {
        Self {
            client,
        }
    }

    pub(crate) fn client(&self) -> &Client {
        &self.client.client
    }

    pub fn url(&self) -> impl IntoUrl {
        self.client.url.clone()
    }

    pub fn semantic(&self) -> SemanticGuacClient {
        SemanticGuacClient::new( self.client )
    }
}

type Id = String;

pub enum PackageSourceOrArtifact {
    Package(Package),
    // Source
    // Artifact
}

pub struct PackageSourceOrArtifactSpec {
    package: Option<PkgSpec>,
    // source
    // artifact
}

pub struct PackageSourceOrArtifactInput {
    package: Option<PkgInputSpec>,
    // source
    // artifact
}

pub struct MatchFlags {
    pkg: PkgMatchType,
}

pub enum PkgMatchType {
    AllVersions,
    SpecificVersion
}
use async_trait::async_trait;
use packageurl::PackageUrl;

use crate::client::intrinsic::is_dependency::{DependencyType, IsDependencyInputSpec};
use crate::client::intrinsic::PkgMatchType;
use crate::client::{Error, GuacClient};

pub trait Subject {}

#[async_trait]
pub trait Predicate<S: Subject> {
    async fn apply<'a>(&'a self, client: &GuacClient, subject: &'a S) -> Result<(), Error>;
}

impl Subject for PackageUrl<'_> {}

pub struct HasDependency<'a> {
    dependent: PackageUrl<'a>,
}

impl<'a> HasDependency<'a> {
    pub fn new(dependent: &PackageUrl<'a>) -> Self {
        Self {
            dependent: dependent.clone(),
        }
    }
}

#[async_trait]
impl Predicate<PackageUrl<'_>> for HasDependency<'_> {
    async fn apply<'a>(
        &'a self,
        client: &GuacClient,
        subject: &'a PackageUrl<'a>,
    ) -> Result<(), Error> {
        let intrinsic = client.intrinsic();

        intrinsic.ingest_package(&subject.clone().into()).await?;

        intrinsic
            .ingest_package(&self.dependent.clone().into())
            .await?;

        intrinsic
            .ingest_is_dependency(
                &subject.clone().into(),
                &self.dependent.clone().into(),
                PkgMatchType::SpecificVersion,
                &IsDependencyInputSpec {
                    version_range: "".to_string(),
                    dependency_type: DependencyType::Direct,
                    justification: "".to_string(),
                    origin: "".to_string(),
                    collector: "".to_string(),
                },
            )
            .await?;
        Ok(())
    }
}

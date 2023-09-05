mod ingest;
mod query;

use crate::client::intrinsic::has_sbom::ingest::IngestHasSBOM;
use crate::client::intrinsic::has_sbom::query::QueryHasSBOM;
use crate::client::intrinsic::{
    IntrinsicGuacClient, PackageOrArtifact, PackageOrArtifactInput, PackageOrArtifactSpec,
};
use crate::client::{Error, Id};
use graphql_client::reqwest::post_graphql;
use packageurl::PackageUrl;

impl IntrinsicGuacClient {
    pub async fn ingest_has_sbom(
        &self,
        subject: &PackageOrArtifactInput,
        has_sbom: &HasSBOMInputSpec,
    ) -> Result<Id, Error> {
        use self::ingest::ingest_has_sbom;

        let variables = ingest_has_sbom::Variables {
            subject: subject.into(),
            has_sbom: has_sbom.into(),
        };

        let response_body =
            post_graphql::<IngestHasSBOM, _>(self.client(), self.url(), variables).await?;

        if let Some(errors) = response_body.errors {
            return Err(Error::GraphQL(errors));
        }

        let data = response_body.data.ok_or(Error::GraphQL(vec![]))?;

        Ok(data.ingest_has_sbom)
    }

    pub async fn has_sbom(&self, has_sbom_spec: &HasSBOMSpec) -> Result<Vec<HasSBOM>, Error> {
        use self::query::query_has_sbom;

        let variables = query_has_sbom::Variables {
            has_sbom_spec: has_sbom_spec.into(),
        };
        let response_body =
            post_graphql::<QueryHasSBOM, _>(self.client(), self.url(), variables).await?;

        if let Some(errors) = response_body.errors {
            return Err(Error::GraphQL(errors));
        }

        let data = response_body.data.ok_or(Error::GraphQL(vec![]))?;

        let mut has_sboms = Vec::new();

        for entry in &data.has_sbom {
            has_sboms.push(entry.into());
        }

        Ok(has_sboms)
    }
}

impl From<PackageUrl<'_>> for HasSBOMSpec {
    fn from(value: PackageUrl) -> Self {
        Self {
            id: None,
            subject: Some(value.into()),
            uri: None,
            algorithm: None,
            digist: None,
            download_location: None,
            origin: None,
            collector: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct HasSBOM {
    pub id: Id,
    pub subject: PackageOrArtifact,
    pub uri: String,
    pub algorithm: String,
    pub digest: String,
    pub download_location: String,
    pub origin: String,
    pub collector: String,
}

#[derive(Clone, Debug)]
pub struct HasSBOMSpec {
    pub id: Option<Id>,
    pub subject: Option<PackageOrArtifactSpec>,
    pub uri: Option<String>,
    pub algorithm: Option<String>,
    pub digist: Option<String>,
    pub download_location: Option<String>,
    pub origin: Option<String>,
    pub collector: Option<String>,
}

#[derive(Clone, Debug)]
pub struct HasSBOMInputSpec {
    pub uri: String,
    pub algorithm: String,
    pub digest: String,
    pub download_location: String,
    pub origin: String,
    pub collector: String,
}

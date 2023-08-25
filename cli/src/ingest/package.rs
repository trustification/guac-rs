use crate::ingest::IngestConfig;
use guac::client::GuacClient;
use packageurl::PackageUrl;
use std::process::ExitCode;
use std::str::FromStr;

#[derive(clap::Args, Debug)]
#[command(
    about = "Run the query to find CertifyBad information of the package (purl)",
    args_conflicts_with_subcommands = true
)]
pub struct PackageCommand {
    #[command(flatten)]
    pub(crate) config: IngestConfig,

    purl: String,
}

impl PackageCommand {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        let guac = GuacClient::new(&self.config.guac_url);

        guac.intrinsic()
            .ingest_package(&PackageUrl::from_str(&self.purl)?.into())
            .await?;
        Ok(ExitCode::SUCCESS)
    }
}

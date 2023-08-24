use crate::ingest::IngestConfig;
use guac::client::GuacClient;
use std::process::ExitCode;

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
        //let guac = GuacClient::new(self.config.guac_url);
        //guac.ingest_package(&self.purl).await?;
        Ok(ExitCode::SUCCESS)
    }
}

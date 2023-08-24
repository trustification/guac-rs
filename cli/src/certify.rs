use std::process::ExitCode;

use clap::{ColorChoice, Subcommand};

use guac::client::GuacClient;

#[derive(Subcommand, Debug)]
pub enum CertifyCommand {
    Good(CertifyGoodCommand),
    Bad(CertifyBadCommand),
}

impl CertifyCommand {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        match self {
            Self::Good(command) => command.run().await,
            Self::Bad(command) => command.run().await,
        }
    }
}

#[derive(Clone, Debug, clap::Args)]
#[command(
    rename_all_env = "SCREAMING_SNAKE_CASE",
    about = "Run the query to find all certified-good packages of the package (purl)",
    args_conflicts_with_subcommands = true
)]
pub struct CertifyGoodCommand {
    #[arg(
        short = 'g',
        long = "guac",
        default_value = "http://localhost:8080/query"
    )]
    pub(crate) guac_url: String,

    #[arg(short = 'C', long = "color", default_value = "auto")]
    color: ColorChoice,

    #[arg(short = 'j', long = "justification")]
    justification: String,

    #[arg(short = 'o', long = "origin", default_value = "cli")]
    origin: String,

    #[arg(short = 'c', long = "collector", default_value = "cli")]
    collector: String,

    purl: String,
}

impl CertifyGoodCommand {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        /*
        let guac = GuacClient::new(self.guac_url);
        guac.ingest_certify_good(&self.purl, self.origin, self.collector, self.justification)
            .await?;

         */
        Ok(ExitCode::SUCCESS)
    }
}

#[derive(Clone, Debug, clap::Args)]
#[command(
    rename_all_env = "SCREAMING_SNAKE_CASE",
    about = "Run the query to find all certified-good packages of the package (purl)",
    args_conflicts_with_subcommands = true
)]
pub struct CertifyBadCommand {
    #[arg(
        short = 'g',
        long = "guac",
        default_value = "http://localhost:8080/query"
    )]
    pub(crate) guac_url: String,

    #[arg(short = 'C', long = "color", default_value = "auto")]
    color: ColorChoice,

    #[arg(short = 'j', long = "justification")]
    justification: String,

    #[arg(short = 'o', long = "origin", default_value = "cli")]
    origin: String,

    #[arg(short = 'c', long = "collector", default_value = "cli")]
    collector: String,

    purl: String,
}

impl CertifyBadCommand {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        /*
        let guac = GuacClient::new(self.guac_url);
        guac.ingest_certify_bad(&self.purl, self.origin, self.collector, self.justification)
            .await?;

         */
        Ok(ExitCode::SUCCESS)
    }
}

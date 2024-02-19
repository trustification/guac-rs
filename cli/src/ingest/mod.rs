mod package;

use crate::ingest::package::PackageCommand;
use clap::ColorChoice;
use clap::Subcommand;
use std::process::ExitCode;

#[derive(Subcommand, Debug)]
pub enum IngestCommand {
    Package(PackageCommand),
}

#[derive(Clone, Debug, clap::Parser)]
#[command(rename_all_env = "SCREAMING_SNAKE_CASE")]
pub struct IngestConfig {
    #[arg(short = 'g', long = "guac", default_value = "http://localhost:8080/query")]
    pub(crate) guac_url: String,

    #[arg(short = 'c', long = "color", default_value = "auto")]
    color: ColorChoice,
}

impl IngestCommand {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        match self {
            IngestCommand::Package(command) => command.run().await,
        }
    }
}

mod bad;
mod dependencies;
mod dependents;
mod good;
mod known;
mod packages;
mod vulnerabilities;

use std::process::ExitCode;

use clap::{ColorChoice, Subcommand};

use crate::query::bad::BadCommand;
use crate::query::dependencies::DependenciesCommand;
use crate::query::dependents::DependentsCommand;
use crate::query::good::GoodCommand;
use crate::query::packages::PackagesCommand;
use crate::query::vulnerabilities::VulnerabilitiesCommand;

#[derive(Subcommand, Debug)]
pub enum QueryCommand {
    Dependencies(DependenciesCommand),
    Dependents(DependentsCommand),
    Packages(PackagesCommand),
    Vulnerabilities(VulnerabilitiesCommand),
    Good(GoodCommand),
    Bad(BadCommand),
}

#[derive(Clone, Debug, clap::Parser)]
#[command(rename_all_env = "SCREAMING_SNAKE_CASE")]
pub struct QueryConfig {
    #[arg(short = 'g', long = "guac", default_value = "http://localhost:8080/query")]
    pub(crate) guac_url: String,

    #[arg(short = 'c', long = "color", default_value = "auto")]
    color: ColorChoice,

    purl: String,
}

impl QueryCommand {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        match self {
            Self::Dependencies(command) => command.run().await,
            Self::Dependents(command) => command.run().await,
            Self::Packages(command) => command.run().await,
            Self::Vulnerabilities(command) => command.run().await,
            Self::Good(command) => command.run().await,
            Self::Bad(command) => command.run().await,
        }
    }
}

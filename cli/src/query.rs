use std::process::ExitCode;

use clap::{ColorChoice, Subcommand};
use guac::graphql::{client::GuacClient, vulns2vex};

use colored_json::{prelude::*, Output};

#[derive(Subcommand, Debug)]
pub enum QueryCommand {
    Dependencies(DependenciesCommand),
    Dependents(DependentsCommand),
    Packages(PackagesCommand),
    Vulnerabilities(VulnerabilitiesCommand),
}

#[derive(Clone, Debug, clap::Parser)]
#[command(rename_all_env = "SCREAMING_SNAKE_CASE")]
pub struct QueryConfig {
    #[arg(
        short = 'g',
        long = "guac",
        default_value = "http://localhost:8080/query"
    )]
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
        }
    }
}

#[derive(clap::Args, Debug)]
#[command(
    about = "Run the query to find all dependencies of the package (purl)",
    args_conflicts_with_subcommands = true
)]
pub struct DependenciesCommand {
    #[command(flatten)]
    pub(crate) config: QueryConfig,
}

impl DependenciesCommand {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        let guac = GuacClient::new(self.config.guac_url);
        let deps = guac.get_dependencies(&self.config.purl).await?;
        let out = serde_json::to_string(&deps)?.to_colored_json(color_mode(self.config.color))?;
        println!("{}", out);
        Ok(ExitCode::SUCCESS)
    }
}

#[derive(clap::Args, Debug)]
#[command(
    about = "Run the query to find all dependents of the package (purl)",
    args_conflicts_with_subcommands = true
)]
pub struct DependentsCommand {
    #[command(flatten)]
    pub(crate) config: QueryConfig,
}

impl DependentsCommand {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        let guac = GuacClient::new(self.config.guac_url);
        let deps = guac.is_dependent(&self.config.purl).await?;
        let out = serde_json::to_string(&deps)?.to_colored_json(color_mode(self.config.color))?;
        println!("{}", out);
        Ok(ExitCode::SUCCESS)
    }
}

#[derive(clap::Args, Debug)]
#[command(
    about = "Run the query to find all related packages of the package (purl)",
    args_conflicts_with_subcommands = true
)]
pub struct PackagesCommand {
    #[command(flatten)]
    pub(crate) config: QueryConfig,
}

impl PackagesCommand {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        let guac = GuacClient::new(self.config.guac_url);
        let pkgs = guac.get_packages(&self.config.purl).await?;
        let out = serde_json::to_string(&pkgs)?.to_colored_json(color_mode(self.config.color))?;
        println!("{}", out);
        Ok(ExitCode::SUCCESS)
    }
}

#[derive(Clone, Debug, clap::Parser)]
#[command(rename_all_env = "SCREAMING_SNAKE_CASE")]
pub struct VulnerabilitiesConfig {
    #[arg(
        short = 'g',
        long = "guac",
        default_value = "http://localhost:8080/query"
    )]
    pub(crate) guac_url: String,

    #[arg(short = 'c', long = "color", default_value = "auto")]
    color: ColorChoice,

    purl: String,

    #[arg(short = 'v', long = "vex", default_value = "false")]
    vex: bool,
}

#[derive(clap::Args, Debug)]
#[command(
    about = "Run the query to find all related packages of the package (purl)",
    args_conflicts_with_subcommands = true
)]
pub struct VulnerabilitiesCommand {
    #[command(flatten)]
    pub(crate) config: VulnerabilitiesConfig,
}

impl VulnerabilitiesCommand {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        let guac = GuacClient::new(self.config.guac_url);
        let vulns = guac.certify_vuln(&self.config.purl).await?;
        let out = if self.config.vex {
            let vex = vulns2vex(vulns);
            serde_json::to_string(&vex)?.to_colored_json(color_mode(self.config.color))?
        } else {
            serde_json::to_string(&vulns)?.to_colored_json(color_mode(self.config.color))?
        };
        println!("{}", out);
        Ok(ExitCode::SUCCESS)
    }
}

fn color_mode(choice: ColorChoice) -> ColorMode {
    match choice {
        ColorChoice::Auto => ColorMode::Auto(Output::StdOut),
        ColorChoice::Always => ColorMode::On,
        ColorChoice::Never => ColorMode::Off,
    }
}

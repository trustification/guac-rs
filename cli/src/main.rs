use anyhow::*;
use clap::{ColorChoice, Parser, Subcommand};
use guac::client::GuacClient;

use colored_json::{prelude::*, Output};

#[derive(Parser, Debug)]
#[command(
    author,
    version = env!("CARGO_PKG_VERSION"),
    about = "Guac API CLI",
    long_about = None
)]
pub struct Cli {
    #[arg(
        short = 'g',
        long = "guac",
        default_value = "http://localhost:8080/query"
    )]
    pub(crate) guac_url: String,

    #[arg(short = 'c', long = "color", default_value = "auto")]
    color: ColorChoice,

    #[command(subcommand)]
    pub(crate) command: Commands,
}

// TODO: group arguments for guac related commands (url, purl, color, ...)
#[derive(Subcommand, Debug)]
enum Commands {
    /// get all dependencies for the provided purl.
    Dependencies {
        /// Artifact purl
        purl: String,
    },
    /// get all dependents on the provided purl.
    Dependents {
        /// Artifact purl
        purl: String,
    },
    /// get all versions for the provided package purl.
    Packages {
        /// Artifact purl
        purl: String,
    },
    /// get all known vulnerabilities for the provided purl.
    Vulnerabilities {
        /// Artifact purl
        purl: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    //let purl = "pkg:maven/io.vertx/vertx-web@4.3.7";
    //let purl = "pkg:deb/debian";
    //let purl = "pkg:pypi/django";
    //let purl = "pkg:rpm/redhat/openssl@1.1.1k-7.el8_6";

    let cli = Cli::parse();
    let guac = GuacClient::new(cli.guac_url);

    match cli.command {
        Commands::Dependencies { purl } => {
            let deps = guac.get_dependencies(&purl).await?;
            let out = serde_json::to_string(&deps)?.to_colored_json(color_mode(cli.color))?;
            println!("{}", out);
        }
        Commands::Dependents { purl } => {
            let deps = guac.is_dependent(&purl).await?;
            let out = serde_json::to_string(&deps)?.to_colored_json(color_mode(cli.color))?;
            println!("{}", out);
        }
        Commands::Packages { purl } => {
            // e.g. "pkg:maven/io.vertx/vertx-web"
            let pkgs = guac.get_packages(&purl).await?;
            let out = serde_json::to_string(&pkgs)?.to_colored_json(color_mode(cli.color))?;
            println!("{}", out);
        }
        Commands::Vulnerabilities { purl } => {
            // TODO fix vex and make it optional
            //let vex = guac.certify_vuln_as_vex(&purl).await?;
            //let out = serde_json::to_string(&vex)?.to_colored_json(color_mode(cli.color))?;
            let vulns = guac.certify_vuln(&purl).await?;
            let out = serde_json::to_string(&vulns)?.to_colored_json(color_mode(cli.color))?;
            println!("{}", out);
        }
    }

    Ok(())
}

fn color_mode(choice: ColorChoice) -> ColorMode {
    match choice {
        ColorChoice::Auto => ColorMode::Auto(Output::StdOut),
        ColorChoice::Always => ColorMode::On,
        ColorChoice::Never => ColorMode::Off,
    }
}

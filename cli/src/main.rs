use std::process::{ExitCode, Termination};

use clap::{ColorChoice, Parser};
use colored_json::{ColorMode, Output};

pub mod certify;
pub mod collect;
pub mod collect_sub;
pub mod ingest;
pub mod query;

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    #[command(subcommand)]
    Query(query::QueryCommand),
    #[command(subcommand)]
    Certify(certify::CertifyCommand),
    #[command(subcommand)]
    Collect(collect::CollectCommand),
    #[command(subcommand)]
    Ingest(ingest::IngestCommand),
    #[command(subcommand)]
    CollectSub(collect_sub::CollectSubCommand),
}

#[derive(Parser, Debug)]
#[command(
    author,
    version = env!("CARGO_PKG_VERSION"),
    about = "Guac API CLI",
    long_about = None
)]
pub struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

impl Cli {
    async fn run(self) -> ExitCode {
        match self.run_command().await {
            Ok(code) => code,
            Err(err) => {
                eprintln!("Error: {err}");
                for (n, err) in err.chain().skip(1).enumerate() {
                    if n == 0 {
                        eprintln!("Caused by:");
                    }
                    eprintln!("\t{err}");
                }

                ExitCode::FAILURE
            }
        }
    }

    async fn run_command(self) -> anyhow::Result<ExitCode> {
        match self.command {
            Command::Query(run) => run.run().await,
            Command::Collect(run) => run.run().await,
            Command::Certify(run) => run.run().await,
            Command::Ingest(run) => run.run().await,
            Command::CollectSub(run) => run.run().await,
        }
    }
}

#[tokio::main]
async fn main() -> impl Termination {
    //let purl = "pkg:maven/io.vertx/vertx-web@4.3.7";
    //let purl = "pkg:deb/debian";
    //let purl = "pkg:pypi/django";
    //let purl = "pkg:rpm/redhat/openssl@1.1.1k-7.el8_6";

    env_logger::init();
    Cli::parse().run().await
}

pub fn color_mode(choice: ColorChoice) -> ColorMode {
    match choice {
        ColorChoice::Auto => ColorMode::Auto(Output::StdOut),
        ColorChoice::Always => ColorMode::On,
        ColorChoice::Never => ColorMode::Off,
    }
}

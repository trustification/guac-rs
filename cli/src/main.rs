use std::process::{ExitCode, Termination};

use clap::Parser;

pub mod collect;
pub mod query;

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    #[command(subcommand)]
    Query(query::QueryCommand),
    #[command(subcommand)]
    Collect(collect::CollectCommand),
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
        }
    }
}

#[tokio::main]
async fn main() -> impl Termination {
    //let purl = "pkg:maven/io.vertx/vertx-web@4.3.7";
    //let purl = "pkg:deb/debian";
    //let purl = "pkg:pypi/django";
    //let purl = "pkg:rpm/redhat/openssl@1.1.1k-7.el8_6";

    Cli::parse().run().await
}

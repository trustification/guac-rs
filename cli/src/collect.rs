use std::process::ExitCode;

use anyhow::*;
use guac::collector::{
    collector::{Collector, FileCollector},
    emitter::NatsEmitter,
};

use clap::Subcommand;

#[derive(Subcommand, Debug)]
pub enum CollectCommand {
    File(FileCommand),
    // S3(Box<exporter::Run>),
}

impl CollectCommand {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        match self {
            Self::File(command) => command.run().await,
            // Self::S3(command) => command.run().await,
        }
    }
}

#[derive(Clone, Debug, clap::Parser)]
#[command(rename_all_env = "SCREAMING_SNAKE_CASE")]
pub struct FileConfig {
    #[arg(short = 'n', long = "nats", default_value = "127.0.0.1:4222")]
    pub(crate) nats_url: String,

    path: String,
}

#[derive(clap::Args, Debug)]
#[command(about = "Run the file collector", args_conflicts_with_subcommands = true)]
pub struct FileCommand {
    #[command(flatten)]
    pub(crate) config: FileConfig,
}

impl FileCommand {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        println!("Collecting file {:?}", self.config.path);
        let emitter = NatsEmitter::new(&self.config.nats_url).await?;

        let collector = FileCollector { path: self.config.path };

        collector.run(emitter).await?;
        Ok(ExitCode::SUCCESS)
    }
}

use std::process::ExitCode;

use anyhow::*;
use guac::collector::{
    collector::{Collector, FileCollector},
    emitter::NatsEmitter,
};

#[derive(clap::Subcommand, Debug)]
pub enum CollectCommand {
    File { path: String },
    S3 {},
}

impl CollectCommand {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        println!("Collecting ...");

        let emitter = NatsEmitter::new("127.0.0.1:4222").await?;

        let collector = FileCollector {
            path: "example/seedwing-java-example.bom".to_string(),
        };

        collector.run(emitter).await?;

        Ok(ExitCode::SUCCESS)
    }
}

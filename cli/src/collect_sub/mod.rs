use std::process::ExitCode;

use clap::ColorChoice;
use clap::Subcommand;

use humantime::Duration;

use crate::collect_sub::get::GetCommand;
//use crate::collect_sub::poll::PollCommand;

mod get;
mod poll;

#[derive(Subcommand, Debug)]
pub enum CollectSubCommand {
    Get(GetCommand),
    //Poll(PollCommand),
}

#[derive(Clone, Debug, clap::Parser)]
#[command(rename_all_env = "SCREAMING_SNAKE_CASE")]
pub struct CollectSubConfig {
    #[arg(short = 'u', long = "csub-url", default_value = "http://localhost:2782/")]
    pub(crate) csub_url: String,

    #[arg(short = 'c', long = "color", default_value = "auto")]
    color: ColorChoice,

    #[arg(short = 's', long = "since")]
    since: Option<Duration>,
}

impl CollectSubCommand {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        match self {
            CollectSubCommand::Get(command) => command.run().await,
            //CollectSubCommand::Poll(command) => command.run().await,
        }
    }
}

use crate::collect_sub::CollectSubConfig;
use std::process::ExitCode;

#[derive(clap::Args, Debug)]
#[command(
    about = "Run the query to find CertifyBad information of the package (purl)",
    args_conflicts_with_subcommands = true
)]
pub struct PollCommand {
    #[command(flatten)]
    pub(crate) config: CollectSubConfig,
}

#[allow(unused)]
impl PollCommand {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        Ok(ExitCode::SUCCESS)
    }
}

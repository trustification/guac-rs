use crate::collect_sub::CollectSubConfig;
use colored_json::ToColoredJson;
use guac::collectsub::{CollectSubClient, Filter};
use std::process::ExitCode;
use std::time::SystemTime;

#[derive(clap::Args, Debug)]
#[command(
    about = "Run the query to find CertifyBad information of the package (purl)",
    args_conflicts_with_subcommands = true
)]
pub struct GetCommand {
    #[command(flatten)]
    pub(crate) config: CollectSubConfig,
}

impl GetCommand {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        let mut csub = CollectSubClient::new(self.config.csub_url).await?;

        let since = if let Some(since) = self.config.since {
            println!("using duration {:?}", since);
            SystemTime::now()
                .checked_sub(*since)
                .expect("invalid `since`")
        } else {
            SystemTime::UNIX_EPOCH
        };

        let result = csub.get(vec![Filter::Purl("*".into())], since).await?;

        let out = serde_json::to_string(&result)?
            .to_colored_json(crate::color_mode(self.config.color))?;
        println!("{}", out);
        Ok(ExitCode::SUCCESS)
    }
}

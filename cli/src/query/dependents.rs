use crate::query::QueryConfig;
use colored_json::ToColoredJson;
use guac::graphql::GuacClient;
use std::process::ExitCode;

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
        let out =
            serde_json::to_string(&deps)?.to_colored_json(crate::color_mode(self.config.color))?;
        println!("{}", out);
        Ok(ExitCode::SUCCESS)
    }
}

use crate::query::QueryConfig;
use colored_json::ToColoredJson;
use guac::client::GuacClient;
use std::process::ExitCode;

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
        /*
        let guac = GuacClient::new(self.config.guac_url);
        let pkgs = guac.get_packages(&self.config.purl).await?;
        let out =
            serde_json::to_string(&pkgs)?.to_colored_json(crate::color_mode(self.config.color))?;
        println!("{}", out);

         */
        Ok(ExitCode::SUCCESS)
    }
}

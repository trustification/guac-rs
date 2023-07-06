use crate::query::QueryConfig;
use colored_json::ToColoredJson;
use guac::graphql::{vulns2vex, GuacClient};
use std::process::ExitCode;

#[derive(clap::Args, Debug)]
#[command(
    about = "Run the query to find all related packages of the package (purl)",
    args_conflicts_with_subcommands = true
)]
pub struct VulnerabilitiesCommand {
    #[command(flatten)]
    pub(crate) config: QueryConfig,

    #[arg(short = 'v', long = "vex", default_value = "false")]
    vex: bool,
}

impl VulnerabilitiesCommand {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        let guac = GuacClient::new(self.config.guac_url);
        let vulns = guac.certify_vuln(&self.config.purl).await?;
        let out = if self.vex {
            let vex = vulns2vex(vulns);
            serde_json::to_string(&vex)?.to_colored_json(crate::color_mode(self.config.color))?
        } else {
            serde_json::to_string(&vulns)?.to_colored_json(crate::color_mode(self.config.color))?
        };
        println!("{}", out);
        Ok(ExitCode::SUCCESS)
    }
}

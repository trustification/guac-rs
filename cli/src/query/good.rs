use crate::query::QueryConfig;
use colored_json::ToColoredJson;
use guac::client::GuacClient;
use packageurl::PackageUrl;
use std::process::ExitCode;
use std::str::FromStr;

#[derive(clap::Args, Debug)]
#[command(
    about = "Run the query to find CertifyGood information of the package (purl)",
    args_conflicts_with_subcommands = true
)]
pub struct GoodCommand {
    #[command(flatten)]
    pub(crate) config: QueryConfig,
}

impl GoodCommand {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        let guac = GuacClient::new(&self.config.guac_url);
        let spec = (&PackageUrl::from_str(&self.config.purl)?).into();
        let good = guac.intrinsic().certify_good(&spec).await?;
        let out =
            serde_json::to_string(&good)?.to_colored_json(crate::color_mode(self.config.color))?;
        println!("{}", out);

        Ok(ExitCode::SUCCESS)
    }
}

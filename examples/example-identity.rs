use gnunet::service::identity;
use gnunet::util::Config;
use std::error::Error;
use std::str::FromStr;
use tracing_subscriber::FmtSubscriber;

#[async_std::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(tracing::Level::TRACE) // uncomment for lots of logs
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let config = Config::default()?;
    let ident = identity::Client::connect(&config).await?;

    Ok(())
}

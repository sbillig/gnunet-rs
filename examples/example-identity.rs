use gnunet::service::identity;
use gnunet::util::Config;
use std::error::Error;

#[async_std::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let config = Config::default()?;
    let _ident = identity::Client::connect(&config).await?;

    Ok(())
}

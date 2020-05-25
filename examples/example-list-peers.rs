use gnunet::service::{transport, PeerInfo};
use gnunet::util::{Config, PeerIdentity};
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
    let mut peerinfo = PeerInfo::connect(&config).await?;

    // get all peers
    let peers_vec = peerinfo.all_peers().await?;
    for (id, _) in peers_vec {
        println!("Peer: {}", id);
    }

    // get a single peer
    let pk = "DPQIBOOJV8QBS3FGJ6B0K5NTSQ9SULV45H5KCR4HU7PQ64N8Q9F0";
    let id = PeerIdentity::from_str(pk)?;
    match peerinfo.get_peer(&id).await? {
        Some(p) => println!("Peer found: {:?}", p),
        None => println!("peer not found"),
    };

    let hello = transport::self_hello(&config).await?;
    println!("Our id is: {}", hello.id);

    Ok(())
}

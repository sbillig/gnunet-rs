use gnunet::service::peerinfo;
use gnunet::service::transport::tcp::{IPv4TcpAddress, IPv6TcpAddress};
use gnunet::util::serial::cast;
use gnunet::util::Config;
use std::error::Error;
use std::mem::size_of;
use tracing_subscriber::FmtSubscriber;

#[async_std::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(tracing::Level::TRACE) // uncomment for lots of logs
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let config = Config::default()?;
    let mut peerinfo = peerinfo::Client::connect(&config).await?;

    for hello in peerinfo.all_peers().await? {
        println!("Peer `{}'", hello.peer_id());

        for addr in hello.addresses {
            print!("\tExpires: {}\t{}.", addr.expiration, addr.transport_name);

            if addr.transport_name == "udp" || addr.transport_name == "tcp" {
                if addr.address.len() == size_of::<IPv4TcpAddress>() {
                    print!("{}", cast::<IPv4TcpAddress>(&addr.address));
                } else if addr.address.len() == size_of::<IPv6TcpAddress>() {
                    print!("{}", cast::<IPv6TcpAddress>(&addr.address));
                } else {
                    print!("{:?}", addr.address);
                }
            } else {
                print!("{:?}", addr.address)
            }
            println!();
        }
        println!();
    }

    Ok(())
}

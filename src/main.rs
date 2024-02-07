use std::time::Duration;

use clap::Parser;
use socksprox::{Socks5Server, SocksUser};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct SocksArgs {
    /// IP to accept SOCKS clients on (0.0.0.0 for all interfaces; 127.0.0.1 default)
    #[arg(short, long)]
    ip: Option<String>,

    /// Port to accept SOCKS clients on (1080 default)
    #[arg(short, long)]
    port: Option<u16>,

    /// Optional users for authentication in a comma-separated list of format "username:password"
    #[arg(short, long, use_value_delimiter = true, value_delimiter = ',')]
    users: Option<Vec<String>>,

    /// Optional timeout for connecting to upstream servers (in ms)
    #[arg(short, long)]
    timeout: Option<usize>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let args = SocksArgs::parse();

    let ip = args.ip.unwrap_or("127.0.0.1".to_string());
    let port = args.port.unwrap_or(1080);

    let users = args.users.map(|x| {
        x.iter()
            .filter_map(|userpass| {
                let mut fields = userpass.split(':');
                if let Some(user) = fields.next() {
                    fields
                        .next()
                        .map(|pass| SocksUser::new(user.to_string(), pass.to_string()))
                } else {
                    None
                }
            })
            .collect::<Vec<SocksUser>>()
    });

    let timeout = if let Some(to) = args.timeout {
        Some(Duration::from_millis(to.try_into()?))
    } else {
        None
    };

    let mut s = match Socks5Server::new(&ip, port, users, timeout).await {
        Ok(s) => s,
        Err(e) => {
            return Err(anyhow::anyhow!("Error starting server: {e}"));
        }
    };

    s.serve().await;

    Ok(())
}

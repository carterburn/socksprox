use socksprox::{Socks5Server, SocksUser};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    // create 1 basic SocksUser
    let users = vec![SocksUser::new("user".to_string(), "admin".to_string())];

    let mut s = match Socks5Server::new("0.0.0.0", 4444, Some(users), None).await {
        Ok(s) => s,
        Err(e) => {
            return Err(anyhow::anyhow!("Error starting server: {e}"));
        }
    };

    s.serve().await;

    Ok(())
}

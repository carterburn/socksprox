# socksprox
Simple SOCKS5 Proxy Server in Rust. Probably shouldn't use this, but you can.

A super simple, feature-lacking async SOCKS5 server.
Currently only supports the CONNECT command (TCP) and limited authentication
(Username/Password). No authentication is also supported.

## But Why
Why would you want to use this? You probably don't, better implementations exist. BUT if you
want a straightforward, easy-to-use SOCKS5 library, well, you found it. This can be used (along
with the provided binary) to quickly and easily deploy a SOCKS5 Server.

To use in your own binary, all you need is the tokio runtime. Using anyhow for errors is also
convienent to easily handle errors provided by the library. The main function for the binary
in it's nascent stages looked something like this:

```rust
use socksprox::Socks5Server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut server = match Socks5Server::new("0.0.0.0", 4444, None, None).await {
        Ok(s) => s,
        Err(e) => { return Err(anyhow::anyhow!("Error starting server: {e}")); }
    };

    server.serve().await;

    Ok(())
}
```

## Contributing
PR's are definitely welcome. Feautres that could be nice:
[ ] UDPAssociate 
[ ] Bind
[ ] More than username/password authentication
[ ] Better argument handling
[ ] Generic impl for the server (don't hardcode TcpStream, but use Tokio's
AsyncRead/WriteExt as a trait bound)

## Credits
I sought some help from merino (probably? the first SOCKS5 implementation in Rust) that
can be found [here](https://github.com/ajmwagar/merino/tree/master). The design
is roughly the same with some tweaks here or there that I added. The 'additions'
that I added are probably not correct or industry standard, but gave it my best
shot. If clippy didn't complain, it's perfect in my opinion. 

The RFC for SOCKS5 is very easy to understand as well, so it was a good first
stab at implementing a network protocol in Rust. [RFC1928](https://datatracker.ietf.org/doc/html/rfc1928)

### Still Asking Why
I am trying to learn how to use tokio and needed something small that I could start working toward. 🧑‍🔧
Hoping to put out better projects using tokio in the future. Have to start
somewhere.

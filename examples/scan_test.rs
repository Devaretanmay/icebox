// Smoke test: load the TCP scanner and run it against the loopback address.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut m = icebox::modules::load("tcp_port_scanner").expect("scanner loaded");
    m.module.set_option("host", "127.0.0.1")?;
    m.module.set_option("ports", "22,80,443,8080,8443")?;
    m.module.set_option("timeout_ms", "2000")?;

    println!("Running...");
    let r = m.module.run().await?;
    println!("Result: {r:#?}");
    Ok(())
}

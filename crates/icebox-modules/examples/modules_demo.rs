#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut dns = icebox_modules::load("dns_resolver").unwrap();
    dns.module.set_option("hostname", "localhost")?;
    println!("=== DNS Resolver (localhost) ===");
    println!("{:#?}\n", dns.module.run().await?);

    let mut fp = icebox_modules::load("service_fingerprinter").unwrap();
    fp.module.set_option("host", "127.0.0.1")?;
    fp.module.set_option("ports", "22,80,443,8443")?;
    println!("=== Service Fingerprinter (127.0.0.1:22,80,443,8443) ===");
    let r = fp.module.run().await?;
    println!("finding: {:?}", r.finding);
    for s in &r.evidence {
        println!("  {s}");
    }
    if r.evidence.is_empty() {
        println!("  (no services fingerprinted  -  all connections failed or got no response)");
    }

    Ok(())
}

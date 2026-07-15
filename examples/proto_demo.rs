//! Discover built-in modules, show options, and run one.

use icebox::modules::{discover, load};

#[tokio::main]
async fn main() {
    let entries = discover();
    println!(
        "ICEBOX prototype  -  discovered {} built-in module(s):",
        entries.len()
    );
    for e in &entries {
        let info = (e.info)();
        println!(
            "  - {} [{}]  -  {}",
            info.name,
            info.kind.as_str(),
            info.description
        );
    }
    if entries.is_empty() {
        return;
    }

    let name = (entries[0].info)().name.clone();
    println!("\n[use] {}", name);

    let loaded = load(&name).expect("module should load");
    println!("[show options] (defaults) {}", loaded.module.options_json());
    println!("[run] ...");
    match loaded.module.run().await {
        Ok(r) => println!("[result] {}", serde_json::to_string_pretty(&r).unwrap()),
        Err(e) => println!("[error] {}", e),
    }
}

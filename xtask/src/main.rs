use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let task = args.get(1).map(|s| s.as_str()).unwrap_or("help");

    match task {
        "build-sandbox-worker" => build_sandbox_worker()?,
        _ => {
            println!("Usage: cargo xtask <task>");
            println!(
                "  build-sandbox-worker Build dist/icebox-worker (Linux musl) for the sandbox"
            );
        }
    }
    Ok(())
}

fn workspace_root() -> Result<PathBuf> {
    let dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(dir)
        .parent()
        .map(|p| p.to_path_buf())
        .context("workspace root not found")
}

fn build_sandbox_worker() -> Result<()> {
    let root = workspace_root()?;
    let dist = root.join("dist");
    fs::create_dir_all(&dist).context("create dist dir")?;
    let docker = Command::new("docker").arg("--version").output();
    if docker.is_ok() {
        let status = Command::new("docker")
            .args([
                "run",
                "--rm",
                "-v",
                &format!("{}:/src", root.display()),
                "-w",
                "/src",
                "rust:1-alpine",
                "sh",
                "-c",
                "rustup target add x86_64-unknown-linux-musl >/dev/null && \
                 cargo build --release --target x86_64-unknown-linux-musl --bin icebox-daemon && \
                 cp target/x86_64-unknown-linux-musl/release/icebox-daemon /src/dist/icebox-worker && \
                 chmod +x /src/dist/icebox-worker",
            ])
            .status()
            .context("failed to run docker build")?;
        if !status.success() {
            anyhow::bail!("docker build of sandbox worker failed");
        }
    } else {
        let status = Command::new("cargo")
            .args([
                "build",
                "--release",
                "--target",
                "x86_64-unknown-linux-musl",
                "--bin",
                "icebox-daemon",
            ])
            .current_dir(&root)
            .status()
            .context("failed to run cargo build")?;
        if !status.success() {
            anyhow::bail!(
                "cross build failed; install musl target + linker (rustup target add x86_64-unknown-linux-musl)"
            );
        }
        let src = root.join("target/x86_64-unknown-linux-musl/release/icebox-daemon");
        fs::copy(&src, dist.join("icebox-worker")).context("copy worker binary")?;
    }
    println!("Built dist/icebox-worker");
    Ok(())
}

use std::path::{Path, PathBuf};
use std::fs;
use std::process::Command;
use sha2::{Sha256, Digest};
use anyhow::{Context, Result};
use std::io::Write;

const KERNEL_URL: &str = "https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/kernels/vmlinux.bin";
const KERNEL_SHA256: &str = "ea5e7d5cf494a8c4ba043259812fc018b44880d70bcbbfc4d57d2760631b1cd6";

const ROOTFS_URL: &str = "https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/rootfs/bionic.rootfs.ext4";
const ROOTFS_SHA256: &str = "2a840feeccb5cb161c6eab1ecd86667c06ed5e307da534d2d3c9e39a6ec6c30a";

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let task = args.get(1).map(|s| s.as_str()).unwrap_or("help");

    match task {
        "fetch-firecracker" => fetch_artifacts().await?,
        "build-sandbox-worker" => build_sandbox_worker()?,
        _ => {
            println!("Usage: cargo xtask <task>");
            println!("  fetch-firecracker    Download Firecracker kernel + rootfs");
            println!("  build-sandbox-worker Build dist/icebox-worker (Linux musl) for the sandbox");
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
        let src = root
            .join("target/x86_64-unknown-linux-musl/release/icebox-daemon");
        fs::copy(&src, dist.join("icebox-worker")).context("copy worker binary")?;
    }
    println!("Built dist/icebox-worker");
    Ok(())
}

async fn fetch_artifacts() -> Result<()> {
    let home = std::env::var("HOME").context("HOME not set")?;
    let cache_dir = PathBuf::from(home).join(".cache").join("icebox").join("firecracker");
    fs::create_dir_all(&cache_dir).context("failed to create cache dir")?;

    println!("Fetching Firecracker artifacts to: {}", cache_dir.display());

    let kernel_path = cache_dir.join("vmlinux.bin");
    download_and_verify(KERNEL_URL, &kernel_path, KERNEL_SHA256).await?;

    let rootfs_path = cache_dir.join("bionic.rootfs.ext4");
    download_and_verify(ROOTFS_URL, &rootfs_path, ROOTFS_SHA256).await?;

    println!("All artifacts verified and ready.");
    Ok(())
}

async fn download_and_verify(url: &str, path: &Path, expected_hash: &str) -> Result<()> {
    if path.exists() {
        if verify_hash(path, expected_hash)? {
            println!("Valid artifact already exists at {}, skipping download.", path.display());
            return Ok(());
        }
        println!("Existing artifact at {} is invalid. Redownloading.", path.display());
    }

    println!("Downloading {}...", url);
    let resp = reqwest::get(url).await?.error_for_status()?;
    let bytes = resp.bytes().await?;

    let mut file = fs::File::create(path)?;
    file.write_all(&bytes)?;

    if !verify_hash(path, expected_hash)? {
        anyhow::bail!("Downloaded artifact does not match expected SHA256 checksum: {}", expected_hash);
    }

    println!("Successfully downloaded and verified {}", path.display());
    Ok(())
}

fn verify_hash(path: &Path, expected: &str) -> Result<bool> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    let hash = hex::encode(hasher.finalize());
    
    if hash == expected {
        Ok(true)
    } else {
        println!("Hash mismatch for {}: expected {}, got {}", path.display(), expected, hash);
        Ok(false)
    }
}

import sys
import os
import subprocess
import time

def print_header():
    print("=" * 60)
    print("🧊 ICEBOX - The Runtime Governance Layer".center(60))
    print("=" * 60)
    print()

def check_command(cmd, name):
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        print(f" [✓] {name} is installed.")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(f" [✗] {name} is NOT installed or not in PATH.")
        return False

def prompt_yes_no(prompt):
    while True:
        resp = input(f"{prompt} [Y/n]: ").strip().lower()
        if resp in ("", "y", "yes"):
            return True
        if resp in ("n", "no"):
            return False

def interactive_setup():
    print_header()
    print("Welcome! Let's get your ICEBOX environment set up.\n")

    print("Checking dependencies...")
    has_docker = check_command(["docker", "--version"], "Docker")
    has_cargo = check_command(["cargo", "--version"], "Cargo (Rust)")
    has_daemon = check_command(["icebox-daemon", "--version"], "ICEBOX Daemon")

    print("\n" + "-" * 60 + "\n")

    if not has_docker:
        print("⚠️  Docker is missing.")
        print("   ICEBOX requires Docker for mandatory target sandboxing.")
        print("   Please install Docker Desktop: https://www.docker.com/products/docker-desktop/\n")
    
    if not has_cargo:
        print("⚠️  Cargo (Rust toolchain) is missing.")
        print("   ICEBOX requires Rust to compile and install the core daemon.")
        print("   Install it via: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh\n")

    if has_cargo and not has_daemon:
        print("⚙️  ICEBOX Daemon is not installed.")
        if prompt_yes_no("Would you like to install it now via 'cargo install icebox-gov'?"):
            print("\nInstalling ICEBOX Daemon (this may take a minute)...")
            try:
                subprocess.run(["cargo", "install", "icebox-gov"], check=True)
                print("\n[✓] ICEBOX Daemon successfully installed as 'icebox-daemon'!\n")
                has_daemon = True
            except subprocess.CalledProcessError:
                print("\n[✗] Failed to install ICEBOX Daemon. Please try running 'cargo install icebox-gov' manually.\n")
    
    if has_docker and has_cargo and has_daemon:
        print("✅ Your ICEBOX environment is fully configured!")
        print("\nTo start the REST API and Governance engine, run:")
        print("  icebox --api")
        print("\nTo launch the autonomous CLI orchestrator, run:")
        print("  icebox")
        print("\n(Note: any arguments passed to 'icebox' are directly forwarded to the 'icebox-daemon').")
    else:
        print("❌ Setup is incomplete. Please resolve the missing dependencies and run 'icebox' again.")

def main():
    # If the user passed arguments, we act as a transparent proxy to the Rust daemon.
    # We skip the setup wizard so it doesn't break automated workflows.
    if len(sys.argv) > 1:
        # Check if the daemon exists before trying to run it
        try:
            # os.execvp replaces the current process with the icebox-daemon
            os.execvp("icebox-daemon", ["icebox-daemon"] + sys.argv[1:])
        except FileNotFoundError:
            print("❌ Error: 'icebox-daemon' not found in PATH.")
            print("Please run 'icebox' (with no arguments) to launch the setup wizard and install it.")
            sys.exit(1)
    
    # If no arguments were provided, launch the interactive setup wizard.
    try:
        interactive_setup()
    except KeyboardInterrupt:
        print("\nSetup cancelled.")
        sys.exit(1)

if __name__ == "__main__":
    main()

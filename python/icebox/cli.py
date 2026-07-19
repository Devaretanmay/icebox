import sys
import os
import json

def _menu(prompt, options):
    print(prompt)
    for i, label in enumerate(options, 1):
        print(f"{i}. {label}")
    while True:
        resp = input("> ").strip()
        if resp.isdigit() and 1 <= int(resp) <= len(options):
            return int(resp)
        print(f"Please enter a number between 1 and {len(options)}.")

def _save(onboard):
    path = os.path.expanduser("~/.icebox/onboard.json")
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            json.dump(onboard, fh)
    except OSError:
        pass

def interactive_setup():
    print("-" * 48)
    print("Welcome to ICEBOX")
    print()
    print("ICEBOX safely governs autonomous security actions.")
    print()
    print("Let's get you set up.")
    print("-" * 48)
    print()

    use = _menu(
        "What are you using ICEBOX for?",
        ["Autonomous Security Agents", "Security Automation Scripts",
         "Security Research", "Custom"],
    )

    profile = _menu(
        "Select a safety profile.",
        ["Safe (Recommended)", "Balanced", "Advanced"],
    )

    approval = _menu(
        "Do you want approval before dangerous actions are executed?",
        ["Always", "High Risk Only (Recommended)", "Never"],
    )

    audit = _menu(
        "Enable audit logging?",
        ["Yes (Recommended)", "No"],
    )

    _save({
        "use_case": ["agents", "automation", "research", "custom"][use - 1],
        "profile": ["safe", "balanced", "advanced"][profile - 1],
        "approvals": ["always", "high_risk_only", "never"][approval - 1],
        "audit": audit == 1,
    })

    print("-" * 48)
    print()
    print("ICEBOX is ready.")
    print()
    print("Your configuration:")
    print(f"Safety Profile: {['Safe', 'Balanced', 'Advanced'][profile - 1]}")
    print(f"Approvals: {['Always', 'High Risk Only', 'Never'][approval - 1]}")
    print(f"Audit Logging: {['Enabled', 'Disabled'][audit - 1]}")
    print()
    print("-" * 48)
    print()
    print("You are ready to govern autonomous security actions.")
    print()
    print("Run:")
    print()
    print("icebox govern")
    print()
    print("-" * 48)

def main():
    # With args, proxy transparently to icebox-daemon; else run the wizard.
    if len(sys.argv) > 1:
        try:
            os.execvp("icebox-daemon", ["icebox-daemon"] + sys.argv[1:])
        except FileNotFoundError:
            print("[ERROR] 'icebox-daemon' not found in PATH.")
            print("Please run 'icebox' (with no arguments) to launch the setup wizard and install it.")
            sys.exit(1)

    try:
        interactive_setup()
    except KeyboardInterrupt:
        print("\nSetup cancelled.")
        sys.exit(1)

if __name__ == "__main__":
    main()

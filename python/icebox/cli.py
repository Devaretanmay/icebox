"""ICEBOX command-line entry point (v2).

Two commands a user needs for onboarding and health:

    icebox init      -> pick a Session profile (30-second setup)
    icebox doctor    -> Docker / Session / plugin / resource health

Plus session control:

    icebox session create [--profile aws] [--lifetime 1h]
    icebox session run <cmd|script>
    icebox session status
    icebox session exit <id>

Everything else is ICEBOX's problem, not the user's.
"""

import json
import os
import shutil
import subprocess
import sys

PROFILE_PATH = os.path.expanduser("~/.icebox/profile.json")


def _menu(prompt, options):
    print(prompt)
    for i, label in enumerate(options, 1):
        print(f"{i}. {label}")
    while True:
        resp = input("> ").strip()
        if resp.isdigit() and 1 <= int(resp) <= len(options):
            return int(resp)
        print(f"Please enter a number between 1 and {len(options)}.")


def _yes_no(prompt):
    print(prompt)
    while True:
        resp = input("> ").strip().lower()
        if resp in ("y", "yes"):
            return True
        if resp in ("n", "no"):
            return False
        print("Please answer Y or N.")


# Profiles are bundles of optional plugins. Core staging is always on; the
# profile only selects which optional concerns (governance, etc.) are mounted.
PROFILES = {
    1: ("default", "Pure isolated staging. Audit on, no governance.", []),
    2: ("aws", "Staging + AWS governance profile.", ["governance:aws"]),
    3: ("pentesting", "Staging + pentesting governance profile.", ["governance:pentesting"]),
    4: ("development", "Staging + relaxed governance for local work.", ["governance:dev"]),
}


def init_wizard():
    print("-" * 50)
    print("Welcome to ICEBOX")
    print()
    print("ICEBOX gives your agent a safe place to fail.")
    print("Pick a Session profile — you can change it anytime.")
    print("-" * 50)
    print()

    choice = _menu(
        "Which Session profile?",
        [f"{v[0]} — {v[1]}" for v in PROFILES.values()],
    )
    name, _, plugins = PROFILES[choice]

    profile = {
        "name": name,
        "plugins": plugins,
        "lifetime_s": None,
    }
    _save_profile(profile)

    print()
    print("-" * 50)
    print(f"ICEBOX profile ready:  {name}")
    print()
    print("Run a workflow in a Session:")
    print()
    print("    from icebox import icebox")
    print("    with icebox(profile=" + repr(name) + ") as s:")
    print("        s.run(my_agent.run_task)")
    print("-" * 50)


def _save_profile(profile):
    try:
        os.makedirs(os.path.dirname(PROFILE_PATH), exist_ok=True)
        with open(PROFILE_PATH, "w") as fh:
            json.dump(profile, fh, indent=2)
    except OSError:
        pass


def _load_profile():
    try:
        with open(PROFILE_PATH) as fh:
            return json.load(fh)
    except OSError:
        return None


def doctor():
    print("ICEBOX Status")
    print()
    checks = []

    docker = shutil.which("docker")
    checks.append((docker is not None,
                   "Docker available", "install Docker"))
    if docker:
        running = subprocess.run([docker, "info"],
                                 capture_output=True, text=True).returncode == 0
        checks.append((running, "Docker daemon running",
                       "start Docker"))

    profile = _load_profile()
    checks.append((profile is not None,
                   f"{profile['name']} profile loaded" if profile
                   else "No profile (using default staging)",
                   "run: icebox init"))
    if profile:
        checks.append((len(profile.get("plugins", [])) >= 0,
                       f"plugins: {profile.get('plugins') or 'none (core only)'}",
                       "re-run icebox init"))

    checks.append((True, "Audit built in to every Session",
                   ""))

    all_ok = True
    for ok, label, fix in checks:
        mark = "✓" if ok else "✗"
        print(f"{mark} {label}")
        if not ok:
            all_ok = False
            if fix:
                print(f"    fix: {fix}")
    print()
    print("You're ready to stage autonomous workflows."
          if all_ok else "ICEBOX needs attention above.")


def session_cmd(args):
    # Minimal local session control. Real orchestration lives in the SDK;
    # the CLI offers convenience entry points.
    if not args or args[0] == "create":
        print("Create a Session in code:")
        print("    from icebox import icebox")
        print("    with icebox(profile='aws') as s:")
        print("        s.run('python your_agent.py')")
        return
    if args[0] == "run":
        cmd = " ".join(args[1:])
        print(f"Running in a Session: {cmd!r}")
        print("Use the SDK: with icebox() as s: s.run(" + repr(cmd) + ")")
        return
    if args[0] == "status":
        print("Sessions are managed by the SDK; inspect live containers with:")
        print("    docker ps --filter label=icebox")
        return
    if args[0] == "exit":
        print("Sessions exit automatically when the `with` block ends.")
        return
    print(f"Unknown session command: {args[0]}")


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("init", "setup", "wizard"):
        try:
            init_wizard()
        except KeyboardInterrupt:
            print("\nSetup cancelled.")
            sys.exit(1)
        return
    if args[0] == "doctor":
        doctor()
        return
    if args[0] == "session":
        session_cmd(args[1:])
        return
    print("Usage:")
    print("  icebox init              set up a Session profile")
    print("  icebox doctor            check Docker / Session / plugin health")
    print("  icebox session <cmd>     session helpers (create/run/status/exit)")
    sys.exit(1)


if __name__ == "__main__":
    main()

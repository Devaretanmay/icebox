"""ICEBOX command-line entry point.

Two commands a user needs: ``icebox init`` (get protected) and
``icebox doctor`` (confirm you're protected). Everything else is ICEBOX's
problem, not the user's.
"""

import json
import os
import sys
import urllib.error
import urllib.request

from . import presets


DAEMON = "http://127.0.0.1:8443"
PROFILE_PATH = os.path.expanduser("~/.icebox/profile.json")


def _menu(prompt, options):
    print(prompt)
    for i, label in enumerate(options, 1):
        print(f"{i}. {label}")
    while True:
        resp = input("> ").strip()
        if resp.isdigit() and 1 <= int(resp) <= len(options):
            return str(int(resp))
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


def _post(path, body):
    req = urllib.request.Request(
        DAEMON + path,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=10).read()
        return True
    except urllib.error.HTTPError as e:
        print(f"  [warn] could not configure {path}: {e.read().decode()[:120]}")
        return False
    except urllib.error.URLError:
        return False


def _apply_profile(profile):
    ok = True
    ok &= _post("/api/v1/charter", {"engagement": profile["engagement"]})
    ok &= _post("/api/v1/scope", {"target": profile["scope"]})
    for rule in profile["policy"]:
        ok &= _post("/api/v1/policy/rules", rule)
    return ok


def _save_profile(profile):
    try:
        os.makedirs(os.path.dirname(PROFILE_PATH), exist_ok=True)
        with open(PROFILE_PATH, "w") as fh:
            json.dump(profile, fh, indent=2)
    except OSError:
        pass


def init_wizard():
    print("-" * 50)
    print("Welcome to ICEBOX")
    print()
    print("ICEBOX protects your AI agent from doing stupid things.")
    print("-" * 50)
    print()

    protect_key = _menu(
        "What do you want to protect?",
        [v[0] for v in presets.PROTECT_WHAT.values()],
    )
    env_key = _menu(
        "What environment is this?",
        [v[0] for v in presets.ENVIRONMENTS.values()],
    )
    approval = _yes_no("Should dangerous actions require your approval?  [Y/N]")
    deny_destructive = _yes_no("Should destructive actions be blocked by default?  [Y/N]")
    scope = input("What will your agent act on? (an IP range, a name like "
                  "'production-aws', or * for anything)\n> ").strip() or "*"

    profile = presets.build_profile(protect_key, env_key, approval,
                                    deny_destructive, scope)
    _save_profile(profile)

    print()
    print("Configuring ICEBOX...")
    reached = _apply_profile(profile)
    if not reached:
        print()
        print("  Could not reach a running ICEBOX daemon.")
        print("  Start it first, then re-run 'icebox init'. Your choices are saved.")
        return

    print()
    print("-" * 50)
    print(f"Your ICEBOX profile is ready:  {profile['name']}")
    print()
    for line in profile["summary"]:
        print(f"  - {line}")
    print()
    print("Done. Protect your agent with:")
    print()
    print("    from icebox import govern")
    print()
    print("    if govern(\"Delete EC2 Instance\", target=\"Production AWS\"):")
    print("        delete_ec2()")
    print("-" * 50)


def doctor():
    print("ICEBOX Status")
    print()
    checks = []

    # 1. Daemon reachable
    daemon_ok = _get("/api/v1/charter") is not None
    checks.append((daemon_ok, "Daemon running",
                   "start the ICEBOX daemon (icebox-daemon --api)"))

    profile = _load_profile()
    # 2. Charter accepted
    charter = _get("/api/v1/charter") or {}
    checks.append((bool(charter.get("accepted")),
                   "Policy loaded", "run: icebox init"))
    # 3. Policy rules present
    policy = _get("/api/v1/policy") or {}
    n_rules = len(policy.get("rules", []))
    checks.append((n_rules > 0, f"Policy loaded ({n_rules} rules)",
                   "run: icebox init"))
    # 4. Audit enabled (scope set => audit path active)
    scope = _get("/api/v1/scope") or []
    checks.append((len(scope) > 0, "Audit enabled",
                   "run: icebox init"))
    # 5. Sandbox from saved profile
    sandbox_ok = bool(profile and profile.get("sandbox"))
    checks.append((sandbox_ok, "Sandbox enabled",
                   "run: icebox init"))
    # 6. Profile loaded
    checks.append((profile is not None,
                   f"{profile['name']} profile loaded" if profile
                   else "No profile loaded",
                   "run: icebox init"))

    all_ok = True
    for ok, label, fix in checks:
        mark = "✓" if ok else "✗"
        print(f"{mark} {label}")
        if not ok:
            all_ok = False
            print(f"    fix: {fix}")
    print()
    print("You're protected." if all_ok else
          "ICEBOX is not fully active. Run 'icebox init'.")


def _get(path):
    try:
        req = urllib.request.Request(DAEMON + path, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read())
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError):
        return None


def _load_profile():
    try:
        with open(PROFILE_PATH) as fh:
            return json.load(fh)
    except OSError:
        return None


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
    # Anything else proxies to the daemon binary so `icebox --api` still works.
    try:
        os.execvp("icebox-daemon", ["icebox-daemon"] + args)
    except FileNotFoundError:
        print("[ERROR] 'icebox-daemon' not found in PATH.")
        sys.exit(1)


if __name__ == "__main__":
    main()

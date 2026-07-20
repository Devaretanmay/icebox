"""ICEBOX recipe: stage a Claude Code agent.

This is a starting point, not a maintained integration. It shows the pattern:
give the agent a Session, let it run its whole workflow inside, and only the
first success ever touches reality.

    from icebox import icebox

    def run_claude_code(task):
        # your agent loop — builds code, runs tests, refactors on failure
        ...

    with icebox(profile="development") as session:
        session.run(run_claude_code)
    # session exited: artifacts + status returned. Apply results yourself.
"""

from icebox import icebox


def stage(task: str, runner, *, profile: str | None = None):
    """Run ``runner(task)`` inside an ICEBOX Session.

    The agent may fail as many times as it needs; reality only sees the
    first success. Returns the Session audit (attempts, failures, artifacts).
    """
    with icebox(task=task, profile=profile) as session:
        return session.run(lambda: runner(task))

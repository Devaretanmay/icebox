"""ICEBOX recipe: stage an OpenAI Agents SDK workflow.

Starting point, not a maintained integration. The agent runs its whole
workflow inside a Session and may iterate freely; reality only sees the first
success.

    from icebox import icebox

    with icebox(profile="aws") as session:
        session.run(lambda: my_agent.run())   # Python callable
        # or session.run_cli("python agent.py") # CLI command group
"""

from icebox import icebox


def stage(task: str, agent_fn, *, profile: str | None = None):
    """Run ``agent_fn`` inside an ICEBOX Session and return its audit."""
    with icebox(task=task, profile=profile) as session:
        return session.run(agent_fn)

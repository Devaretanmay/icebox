"""ICEBOX recipe: stage a CrewAI crew.

Starting point, not a maintained integration. The crew runs its whole
workflow inside a Session and may iterate freely; reality only sees the first
success.

    from icebox import icebox

    with icebox(profile="development") as session:
        session.run(lambda: my_crew.kickoff())
"""

from icebox import icebox


def stage(task: str, crew_fn, *, profile: str | None = None):
    """Run ``crew_fn`` inside an ICEBOX Session and return its audit."""
    with icebox(task=task, profile=profile) as session:
        return session.run(crew_fn)

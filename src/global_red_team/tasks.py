from celery import Celery
from .config import Settings

settings = Settings()
app = Celery(
    "tasks",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)


@app.task
def run_test_suite(suite_name: str):
    """
    Runs a security test suite asynchronously.
    """
    from .red_team_orchestrator import RedTeamOrchestrator
    orchestrator = RedTeamOrchestrator(settings)
    orchestrator.register_test_suite(
        suite_name,
        orchestrator.suites[suite_name][0],
        orchestrator.suites[suite_name][1],
        orchestrator.suites[suite_name][2],
    )
    orchestrator.execute_all_tests()
    return orchestrator.stats

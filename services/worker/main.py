import redis
from rq import Worker, Queue
from worker.config import get_settings
from worker.ops import worker_identity

settings = get_settings()


def _v37_failure_handler(job, exc_type, exc_value, traceback):
    """RQ exception handler: classify + bounded retry / dead-letter.

    Returning True tells RQ the failure was handled (it will still move
    the job to FailedJobRegistry; our handler records the decision).
    """
    try:
        from worker.tasks_ops import handle_task_failure
        queue_name = getattr(getattr(job, "origin", None), "name", None) or str(job.origin)
        handle_task_failure(job, queue_name, exc_value)
    except Exception:
        pass  # never crash the worker on the handler itself
    return True


def main():
    """Start the RQ worker process."""
    conn = redis.from_url(settings.redis_url)
    queues = [
        Queue("scans", connection=conn),
        Queue("container_scans", connection=conn),
        Queue("log_analysis", connection=conn),
        # V3.7 Phase 16: dead-letter queues are monitored for depth but
        # never processed automatically — dead jobs require explicit
        # operator recovery.
        Queue("dead:scans", connection=conn),
        Queue("dead:container_scans", connection=conn),
        Queue("dead:log_analysis", connection=conn),
    ]

    print(f"Starting CYVRIX worker [{worker_identity()}], connecting to {settings.redis_url}")
    print("Listening on queues: scans, container_scans, log_analysis (+ dead-letter monitors)")

    worker = Worker(queues, connection=conn, name=worker_identity(),
                    exception_handlers=[_v37_failure_handler])
    worker.work(
        with_scheduler=True,
    )


if __name__ == "__main__":
    main()

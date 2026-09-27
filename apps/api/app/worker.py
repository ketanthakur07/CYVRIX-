import redis
from app.config import get_settings

settings = get_settings()

# Redis connection for job queue
redis_conn = redis.from_url(settings.redis_url, decode_responses=True)


def enqueue_scan(scan_id: str):
    """Enqueue a dependency scan job to the Redis queue."""
    from rq import Queue
    queue = Queue("scans", connection=redis_conn)
    queue.enqueue(
        "worker.tasks.run_scan",
        scan_id,
        job_timeout=f"{settings.scan_timeout_minutes}m",
        result_ttl=3600,
    )


def enqueue_container_scan(scan_id: str):
    """Enqueue a container/Dockerfile security scan job."""
    from rq import Queue
    queue = Queue("container_scans", connection=redis_conn)
    queue.enqueue(
        "worker.tasks.run_container_scan",
        scan_id,
        job_timeout=f"{settings.scan_timeout_minutes}m",
        result_ttl=3600,
    )


def enqueue_log_analysis(scan_id: str):
    """Enqueue a log/security analysis job."""
    from rq import Queue
    queue = Queue("log_analysis", connection=redis_conn)
    queue.enqueue(
        "worker.tasks.run_log_analysis",
        scan_id,
        job_timeout=f"{settings.scan_timeout_minutes}m",
        result_ttl=3600,
    )


def enqueue_outbound_webhook_delivery(delivery_row_id: str, delay_seconds: int = 0):
    """Enqueue one outbound webhook delivery attempt (V4.2 completion).

    The payload carries the delivery ROW id only — never URL, secret,
    or payload content; the dispatcher re-reads trusted state. Retries
    are scheduled with RQ's built-in delay so backoff+jitter is honored
    without a polling loop.
    """
    from rq import Queue
    queue = Queue("webhook_deliveries", connection=redis_conn)
    if delay_seconds and delay_seconds > 0:
        import datetime as _dt
        queue.enqueue_in(
            _dt.timedelta(seconds=int(delay_seconds)),
            "worker.tasks.deliver_outbound_webhook",
            delivery_row_id,
            job_timeout="120s",
            result_ttl=3600,
        )
    else:
        queue.enqueue(
            "worker.tasks.deliver_outbound_webhook",
            delivery_row_id,
            job_timeout="120s",
            result_ttl=3600,
        )

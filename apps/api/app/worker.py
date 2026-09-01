import redis
from app.config import get_settings

settings = get_settings()

# Redis connection for job queue
redis_conn = redis.from_url(settings.redis_url, decode_responses=True)


def enqueue_scan(scan_id: str):
    """Enqueue a scan job to the Redis queue."""
    from rq import Queue
    queue = Queue("scans", connection=redis_conn)
    queue.enqueue(
        "worker.tasks.run_scan",
        scan_id,
        job_timeout=f"{settings.scan_timeout_minutes}m",
        result_ttl=3600,
    )

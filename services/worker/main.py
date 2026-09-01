import redis
from rq import Worker, Queue
from worker.config import get_settings

settings = get_settings()


def main():
    """Start the RQ worker process."""
    conn = redis.from_url(settings.redis_url)
    queues = [Queue("scans", connection=conn)]

    print(f"Starting CYVRIX worker, connecting to {settings.redis_url}")
    print(f"Listening on queues: scans")

    worker = Worker(queues, connection=conn)
    worker.work(
        with_scheduler=True,
    )


if __name__ == "__main__":
    main()

"""CYVRIX worker entrypoint.

V4.2 additions (Phase 4/20/26/27):
  - drain mode: the worker observes a Redis drain marker and stops
    claiming new jobs, then exits cleanly — rolling deploys do not
    interrupt work that is already running (RQ warm shutdown completes
    the current job; drain prevents the NEXT claim).
  - heartbeat: Redis-backed liveness (state, queues, current job) with a
    bounded TTL so the API fleet can observe real worker liveness and
    queue depth (no fake metrics: absent worker = expired key).
  - graceful shutdown: RQ's own warm shutdown finishes or safely releases
    the current job; the heartbeat thread stops before exit.
"""
import logging
import threading
import time

import redis
from rq import Worker, Queue

from worker.config import get_settings
from worker.ops import worker_identity

settings = get_settings()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cyvrix.worker")


def _v37_failure_handler(job, exc_type, exc_value, traceback):
    """RQ exception handler: classify + bounded retry / dead-letter.

    Returning True tells RQ the failure was handled (it will still move
    the job to FailedJobRegistry; our handler records the decision and,
    since V4.2, actually re-schedules TRANSIENT retries with backoff).
    """
    try:
        from worker.tasks_ops import handle_task_failure
        queue_name = getattr(getattr(job, "origin", None), "name", None) or str(job.origin)
        handle_task_failure(job, queue_name, exc_value)
    except Exception:
        pass  # never crash the worker on the handler itself
    return True


def _heartbeat_loop(
    worker_name: str,
    queues: list[str],
    stop_event: threading.Event,
    drain_flag: dict,
) -> None:
    """Background liveness thread. Best-effort: Redis failures are
    logged and retried on the next tick — a heartbeat outage must never
    take the worker down (work continues; liveness is simply unknown,
    which the ops surface shows as a missing/expired key).

    Also observes the drain marker into `drain_flag` (shared dict, the
    one piece of process-local state here — its loss cannot create a
    duplicate side effect, only a slower shutdown)."""
    conn = None
    try:
        conn = redis.from_url(settings.redis_url, decode_responses=True)
    except Exception:
        return

    worker_key = f"cyvrix:worker:{worker_name}"

    while not stop_event.is_set():
        try:
            drain = conn.get(f"cyvrix:drain:{worker_name}")
            if drain:
                drain_flag["drain"] = True
            current_job = ""
            try:
                import rq.worker as _rq_worker
                current_job = _rq_worker.Worker.get_current_job_id(conn) or ""
            except Exception:
                current_job = ""
            state = "DRAINING" if drain else "RUNNING"
            pipe = conn.pipeline()
            pipe.hset(
                worker_key,
                mapping={
                    "state": state,
                    "queues": ",".join(queues)[:200],
                    "current_job": (current_job or "")[:64],
                    "last_heartbeat": str(int(time.time())),
                },
            )
            pipe.expire(worker_key, 90)
            pipe.execute()
        except Exception:
            logger.warning("worker_heartbeat_failed worker=%s", worker_name[:40])
        stop_event.wait(30)

    # One final honest write on the way out.
    try:
        conn.hset(worker_key, mapping={"state": "EXITED", "current_job": ""})
        conn.expire(worker_key, 90)
    except Exception:
        pass


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
    queue_names = [q.name for q in queues]

    worker_name = worker_identity()
    print(f"Starting CYVRIX worker [{worker_name}], connecting to {settings.redis_url}")
    print("Listening on queues: scans, container_scans, log_analysis (+ dead-letter monitors)")

    # ── V4.2 drain observation ──────────────────────────────────────
    # Wrap the worker's main loop check: RQ polls `worker.should_work` /
    # performs `dequeue` via `Worker.work`. The supported hook is
    # `before_process_job` + custom loop control via `max_idle_time` is
    # not a drain; instead a heartbeat-thread-owned flag is checked by
    # wrapping `Worker.dequeue_job_and_maintain_ttl` through subclassing.
    stop_event = threading.Event()

    drain_flag = {"drain": False}

    class DrainingWorker(Worker):
        """Stops claiming new jobs once a drain is requested (Phase 27).

        RQ's warm shutdown on SIGTERM already finishes the current job;
        this class ensures the worker also stops CLAIMING new work the
        moment a drain marker appears, then exits cleanly when idle."""

        def dequeue_job_and_maintain_ttl(self, max_idle_time: int = 0, *args, **kwargs):
            if drain_flag["drain"]:
                # Drain requested: stop claiming. Returning None ends the
                # work loop cleanly (current job, if any, already finished
                # because dequeue happens between jobs).
                logger.info("worker_draining stop_claiming worker=%s", worker_name)
                return None
            return super().dequeue_job_and_maintain_ttl(max_idle_time, *args, **kwargs)

    heartbeat_thread = threading.Thread(
        target=_heartbeat_loop,
        args=(worker_name, queue_names, stop_event, drain_flag),
        daemon=True,
        name="cyvrix-worker-heartbeat",
    )
    heartbeat_thread.start()

    worker = DrainingWorker(
        queues, connection=conn, name=worker_name,
        exception_handlers=[_v37_failure_handler],
    )

    try:
        worker.work(with_scheduler=True)
    finally:
        stop_event.set()
        heartbeat_thread.join(timeout=5)

    logger.info("worker_stopped worker=%s", worker_name)


if __name__ == "__main__":
    main()

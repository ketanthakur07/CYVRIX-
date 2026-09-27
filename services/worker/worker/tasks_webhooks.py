"""CYVRIX V4.2 completion — outbound webhook delivery task (RQ entry).

The task signature carries ONLY the delivery ROW id: URL, secret, and
payload are re-read from trusted database state by the dispatcher. The
worker listens on the `webhook_deliveries` queue (registered in
main.py); retries are re-enqueued with bounded backoff + jitter while
reusing the SAME delivery row and wire delivery_id.
"""
import asyncio
import logging

logger = logging.getLogger("cyvrix.webhook_task")


def deliver_outbound_webhook(delivery_row_id: str):
    """One delivery attempt. Returns the resulting state (bounded)."""
    import os
    import sys

    # Same sys.path bootstrap the scan tasks use to import app.* modules.
    _here = os.path.dirname(os.path.abspath(__file__))
    _apps = os.path.join(os.path.dirname(os.path.dirname(_here)), "apps")
    if _apps not in sys.path:
        sys.path.insert(0, _apps)

    import os as _os

    _os.chdir(_os.path.join(_apps, "api"))

    from app.services.outbound_webhook_service import dispatch_from_worker
    from app.worker import enqueue_outbound_webhook_delivery

    return asyncio.run(
        dispatch_from_worker(
            delivery_row_id,
            enqueue=enqueue_outbound_webhook_delivery,
        )
    )

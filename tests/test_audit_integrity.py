"""V3.8 — audit chain unit tests: canonicalization, digests, verifier,
redaction, export verification, and tamper detection (pure functions,
SQLite via conftest fixtures — no mocks of the crypto itself).

Real-stack race/tamper certification lives in tests/test_audit_chain_races.py
(RUN_INTEGRATION_TESTS gated) and tests/cert_v38_audit.py.
"""
import json
import os
import sys
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

import pytest

from app.services import audit_service as aus


# ── Canonicalization determinism (Phase 3) ───────────────────────────


class TestCanonicalization:
    def test_sorted_keys_no_whitespace(self):
        a = aus.canonical_json({"b": 1, "a": 2})
        b = aus.canonical_json({"a": 2, "b": 1})
        assert a == b == '{"a":2,"b":1}'

    def test_unicode_deterministic(self):
        s = aus.canonical_json({"k": "héllo→"})
        assert json.loads(s)["k"] == "héllo→"
        assert aus.canonical_json({"k": "héllo→"}) == s

    def test_null_representation_explicit(self):
        assert aus.canonical_json({"k": None}) == '{"k":null}'

    def test_datetime_utc_canonical(self):
        from datetime import datetime, timezone, timedelta
        dt = datetime(2026, 9, 25, 12, 0, 0, tzinfo=timezone.utc)
        assert aus.canonical_timestamp(dt) == "2026-09-25T12:00:00.000000Z"
        # naive treated as UTC
        assert aus.canonical_timestamp(dt.replace(tzinfo=None)) == aus.canonical_timestamp(dt)
        # non-UTC normalized
        dt2 = dt.astimezone(timezone(timedelta(hours=2)))
        assert aus.canonical_timestamp(dt2) == "2026-09-25T12:00:00.000000Z"

    def test_float_stringified_no_ambiguity(self):
        out = aus.redact_payload({"ratio": 0.1})
        assert isinstance(out["ratio"], str)  # repr string, not float bits

    def test_canonical_payload_is_closed_field_set(self):
        ev = aus.AuditChainEvent(
            chain_id=uuid.uuid4(), seq=1, event_type="EXECUTION_STARTED",
            event_version=1, actor_type="SYSTEM", occurred_at=None,
            recorded_at=None, prev_digest=aus.GENESIS_PREV_DIGEST,
            event_digest="x",
        )
        payload = aus.canonical_event_payload(ev)
        assert set(payload.keys()) == {
            "schema_version", "event_type", "event_version", "actor_type",
            "actor_id", "actor_user_id", "repository_id", "action_id",
            "authorization_id", "execution_run_id", "verification_id",
            "rollback_id", "reason_code", "result", "payload",
            "occurred_at", "recorded_at", "seq",
        }


# ── Redaction (Phase 15/38) ──────────────────────────────────────────


class TestRedaction:
    def test_secret_keys_redacted(self):
        out = aus.redact_payload({
            "github_token": "ghp_abcdefghijklmnopqrst",
            "executor_service_token": "st-secret",
            "password": "hunter2",
            "nested": {"api_key": "AKIA...", "safe": "visible"},
        })
        assert out["github_token"] == "[REDACTED]"
        assert out["executor_service_token"] == "[REDACTED]"
        assert out["password"] == "[REDACTED]"
        assert out["nested"]["api_key"] == "[REDACTED]"
        assert out["nested"]["safe"] == "visible"

    def test_token_shaped_strings_redacted_even_unflagged(self):
        out = aus.redact_payload({"note": "ghp_" + "a" * 30})
        assert out["note"] == "[REDACTED]"

    def test_depth_bounded(self):
        deep = cur = {}
        for _ in range(20):
            cur["child"] = {}
            cur = cur["child"]
        cur["x"] = 1
        out = aus.redact_payload(deep)
        assert "[TRUNCATED]" in json.dumps(out)


# ── Digest construction (Phase 4/5) ──────────────────────────────────


class TestDigest:
    def test_genesis_is_sixty_four_zeros(self):
        assert aus.GENESIS_PREV_DIGEST == "0" * 64

    def test_digest_binds_predecessor(self):
        p = {"event_type": "EXECUTION_STARTED", "seq": 1}
        d1 = aus.compute_event_digest(
            chain_id=uuid.uuid4(), prev_digest=aus.GENESIS_PREV_DIGEST,
            canonical_payload=p)
        d2 = aus.compute_event_digest(
            chain_id=uuid.uuid4(), prev_digest="f" * 64,
            canonical_payload=p)
        assert d1 != d2  # predecessor link is inside the hash

    def test_digest_binds_chain(self):
        p = {"event_type": "EXECUTION_STARTED", "seq": 1}
        cid = uuid.uuid4()
        d1 = aus.compute_event_digest(
            chain_id=cid, prev_digest=aus.GENESIS_PREV_DIGEST, canonical_payload=p)
        d2 = aus.compute_event_digest(
            chain_id=uuid.uuid4(), prev_digest=aus.GENESIS_PREV_DIGEST, canonical_payload=p)
        assert d1 != d2

    def test_digest_deterministic(self):
        p = {"event_type": "EXECUTION_STARTED", "seq": 1}
        cid = uuid.uuid4()
        a = aus.compute_event_digest(
            chain_id=cid, prev_digest=aus.GENESIS_PREV_DIGEST, canonical_payload=p)
        b = aus.compute_event_digest(
            chain_id=cid, prev_digest=aus.GENESIS_PREV_DIGEST, canonical_payload=p)
        assert a == b and len(a) == 64


# ── Registry (Phase 17) ──────────────────────────────────────────────


class TestRegistry:
    def test_unknown_event_type_rejected(self):
        with pytest.raises(KeyError):
            aus.EVENT_CRITICALITY["TOTALLY_FAKE_EVENT"]  # not registered ⇒ emit raises AuditEventError

    def test_legacy_map_targets_registered(self):
        for legacy, target in aus.LEGACY_EVENT_TYPE_MAP.items():
            assert target in aus.EVENT_CRITICALITY, f"{legacy} -> {target} unregistered"

    def test_all_v37_ops_events_registered(self):
        for name in (
            "SYSTEM_PAUSED", "SYSTEM_RESUMED", "EMERGENCY_STOP",
            "REPOSITORY_PAUSED", "CIRCUIT_OPENED", "CIRCUIT_RESET",
            "JOB_RECONCILED", "LEASE_EXPIRED", "QUOTA_EXCEEDED",
        ):
            assert name in aus.EVENT_CRITICALITY

    def test_actor_types_closed_world(self):
        assert aus.ActorType.USER in aus.VALID_ACTOR_TYPES
        assert "MAGIC_SUPERUSER" not in aus.VALID_ACTOR_TYPES


# ── Verifier over synthetic chains (Phase 19/20) ─────────────────────


class _Row:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def _build_chain(n=4, chain_id=None):
    """Build a valid synthetic chain of n events (pure, no DB)."""
    chain_id = chain_id or uuid.uuid4()
    rows = []
    prev = aus.GENESIS_PREV_DIGEST
    for seq in range(1, n + 1):
        row = _Row(
            chain_id=chain_id, seq=seq, event_type="EXECUTION_STARTED",
            event_version=1, actor_type="SYSTEM", actor_id="worker-A",
            actor_user_id=None, repository_id=None, action_id=None,
            authorization_id=None, execution_run_id=None,
            verification_id=None, rollback_id=None,
            reason_code="OK", result="OK",
            payload={"n": seq},
            occurred_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            recorded_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            prev_digest=prev, event_digest=None,
        )
        row.event_digest = aus.compute_event_digest(
            chain_id=chain_id, prev_digest=prev,
            canonical_payload=aus.canonical_event_payload(row))
        rows.append(row)
        prev = row.event_digest
    return rows


class TestVerifier:
    def test_valid_chain(self):
        res = aus.verify_chain_rows(_build_chain(5))
        assert res.status == "VALID" and res.ok and res.checked_events == 5

    def test_empty_chain_is_empty_not_invalid(self):
        res = aus.verify_chain_rows([])
        assert res.status == "EMPTY"

    def test_payload_tamper_detected(self):
        rows = _build_chain(4)
        rows[2].payload = {"n": 999}  # T1: modify historical event
        res = aus.verify_chain_rows(rows)
        codes = {i.code for i in res.issues}
        assert res.status == "INVALID" and "DIGEST_MISMATCH" in codes

    def test_actor_swap_detected(self):
        rows = _build_chain(4)
        rows[1].actor_id = "worker-EVIL"  # T6
        assert aus.verify_chain_rows(rows).status == "INVALID"

    def test_outcome_swap_detected(self):
        rows = _build_chain(4)
        rows[3].result = "SUCCESS"  # T12: invent success
        assert aus.verify_chain_rows(rows).status == "INVALID"

    def test_timestamp_tamper_detected(self):
        from datetime import datetime, timezone as tz
        rows = _build_chain(4)
        rows[0].occurred_at = datetime(1999, 1, 1, tzinfo=tz.utc)  # T8
        assert aus.verify_chain_rows(rows).status == "INVALID"

    def test_digest_field_tamper_detected(self):
        rows = _build_chain(4)
        rows[2].event_digest = "a" * 64  # T1 variant
        res = aus.verify_chain_rows(rows)
        assert res.status == "INVALID"

    def test_predecessor_swap_detected(self):
        rows = _build_chain(4)
        rows[3].prev_digest = rows[1].event_digest  # T5: fork/relink
        res = aus.verify_chain_rows(rows)
        codes = {i.code for i in res.issues}
        assert "PREDECESSOR_BREAK" in codes

    def test_middle_deletion_detected(self):
        rows = _build_chain(5)
        del rows[2]  # T2: delete one middle event
        res = aus.verify_chain_rows(rows)
        codes = {i.code for i in res.issues}
        assert res.status == "INVALID" and "SEQ_GAP" in codes

    def test_reordering_detected(self):
        rows = _build_chain(4)
        rows[1], rows[2] = rows[2], rows[1]  # T4
        res = aus.verify_chain_rows(rows)
        codes = {i.code for i in res.issues}
        assert res.status == "INVALID" and (
            "SEQ_DUPLICATE_OR_REORDER" in codes or "PREDECESSOR_BREAK" in codes)

    def test_duplicate_event_detected(self):
        rows = _build_chain(4)
        rows.append(rows[-1])  # T16: duplicate tail
        res = aus.verify_chain_rows(rows)
        assert res.status == "INVALID"

    def test_replayed_event_with_fresh_seq_detected(self):
        rows = _build_chain(4)  # T17: replay event 2 as a new event 5
        clone = _Row(**vars(rows[1]).copy())
        clone.seq = 5
        clone.prev_digest = rows[3].event_digest
        rows.append(clone)
        assert aus.verify_chain_rows(rows).status == "INVALID"

    def test_unsupported_future_version(self):
        rows = _build_chain(3)
        rows[2].event_version = 99
        res = aus.verify_chain_rows(rows)
        assert res.status == "UNSUPPORTED_VERSION"

    def test_tail_truncation_requires_checkpoint(self):
        """T13: deleting the last N events leaves the prefix valid —
        this is WHY signed checkpoints exist. Plain chain: prefix valid
        (documented limitation); with a trusted checkpoint: detected."""
        rows = _build_chain(6)
        # verify full
        assert aus.verify_chain_rows(rows).status == "VALID"
        # attacker truncates the tail
        truncated = rows[:4]
        assert aus.verify_chain_rows(truncated).status == "VALID"  # expected gap
        # with a checkpoint at seq 6 that survives elsewhere: detected
        from datetime import datetime, timezone as tz
        full_head = rows[5].event_digest
        material = aus.checkpoint_material(rows[0].chain_id, 6, full_head, 6)
        cp = _Row(
            chain_id=rows[0].chain_id, through_sequence=6,
            head_digest=full_head, event_count=6,
            payload_digest=material,
            mac=aus.checkpoint_mac(material, "test-key", 1),
            mac_key_version=1, created_at=datetime.now(tz.utc),
        )
        res = aus.verify_chain_rows(truncated, [cp], "test-key")
        codes = {i.code for i in res.issues}
        assert res.status == "INVALID" and "TRUNCATED_TAIL" in codes

    def test_checkpoint_mac_forgery_detected(self):
        rows = _build_chain(3)
        from datetime import datetime, timezone as tz
        material = aus.checkpoint_material(rows[-1].chain_id, 3, rows[-1].event_digest, 3)
        cp = _Row(
            chain_id=rows[-1].chain_id, through_sequence=3,
            head_digest=rows[-1].event_digest, event_count=3,
            payload_digest=material, mac="f" * 64,  # forged MAC
            mac_key_version=1, created_at=datetime.now(tz.utc),
        )
        res = aus.verify_chain_rows(rows, [cp], "test-key")
        assert any(i.code == "CHECKPOINT_MAC_MISMATCH" for i in res.issues)


# ── Export verification (Phase 27/28/50) ─────────────────────────────


class TestExport:
    def test_export_roundtrip_valid(self):
        rows = _build_chain(4)
        text = aus.export_chain_ndjson(rows)
        res = aus.verify_export_ndjson(text)
        assert res.status == "VALID" and res.checked_events == 4

    def test_export_tamper_payload_detected(self):
        rows = _build_chain(4)
        text = aus.export_chain_ndjson(rows)
        lines = text.strip().splitlines()
        rec = json.loads(lines[2])
        rec["payload"]["n"] = 42
        lines[2] = aus.canonical_json(rec)
        assert aus.verify_export_ndjson("\n".join(lines)).status == "INVALID"

    def test_export_tamper_order_detected(self):
        rows = _build_chain(4)
        text = aus.export_chain_ndjson(rows)
        lines = text.strip().splitlines()
        lines[1], lines[2] = lines[2], lines[1]
        assert aus.verify_export_ndjson("\n".join(lines)).status == "INVALID"

    def test_export_tamper_digest_detected(self):
        rows = _build_chain(4)
        text = aus.export_chain_ndjson(rows)
        lines = text.strip().splitlines()
        rec = json.loads(lines[1])
        rec["event_digest"] = "b" * 64
        lines[1] = aus.canonical_json(rec)
        assert aus.verify_export_ndjson("\n".join(lines)).status == "INVALID"

    def test_export_tamper_checkpoint_detected(self):
        rows = _build_chain(3)
        material = aus.checkpoint_material(rows[-1].chain_id, 3, rows[-1].event_digest, 3)
        from datetime import datetime, timezone as tz
        cps = [_Row(
            chain_id=rows[-1].chain_id, through_sequence=3,
            head_digest=rows[-1].event_digest, event_count=3,
            payload_digest=material,
            mac=aus.checkpoint_mac(material, "k", 1),
            mac_key_version=1, created_at=datetime.now(tz.utc))]
        text = aus.export_chain_ndjson(rows, cps)
        assert aus.verify_export_ndjson(text, checkpoint_key="k").status == "VALID"
        lines = text.strip().splitlines()
        rec = json.loads(lines[-1])
        rec["head_digest"] = "c" * 64  # forged checkpoint head
        lines[-1] = aus.canonical_json(rec)
        res = aus.verify_export_ndjson("\n".join(lines), checkpoint_key="k")
        assert res.status == "INVALID"

    def test_export_header_garbage_rejected(self):
        res = aus.verify_export_ndjson('{"type":"something_else"}\n')
        assert res.status == "INVALID"


# ── Append behavior over real (SQLite) session ───────────────────────


@pytest.mark.asyncio
class TestAppendAndVerify:
    async def test_emit_two_events_chain_valid(self, session_factory, test_installation):
        async with session_factory() as db:
            await aus.emit_security_event(
                db, installation_id=test_installation.id,
                event_type="SYSTEM_PAUSED", actor_type=aus.ActorType.USER,
                reason_code="PAUSED", result="OK", payload={"k": "v"})
            await aus.emit_security_event(
                db, installation_id=test_installation.id,
                event_type="EMERGENCY_STOP", actor_type=aus.ActorType.USER,
                reason_code="EMERGENCY_STOP", result="OK")
            await db.commit()
        async with session_factory() as db:
            res = await aus.verify_chain(db, chain_id=test_installation.id and (
                (await db.execute(
                    __import__("sqlalchemy").select(aus.AuditChain)
                )).scalars().first().id))
        assert res.status == "VALID" and res.checked_events == 2

    async def test_unknown_event_type_fails_closed(self, session_factory, test_installation):
        async with session_factory() as db:
            with pytest.raises(aus.AuditEventError):
                await aus.emit_security_event(
                    db, installation_id=test_installation.id,
                    event_type="NOT_A_REAL_EVENT", actor_type=aus.ActorType.SYSTEM)

    async def test_secret_in_payload_never_stored(self, session_factory, test_installation):
        async with session_factory() as db:
            await aus.emit_security_event(
                db, installation_id=test_installation.id,
                event_type="SYSTEM_PAUSED",
                payload={"github_token": "ghp_" + "z" * 30, "note": "safe"})
            await db.commit()
            from sqlalchemy import select
            ev = (await db.execute(select(aus.AuditChainEvent))).scalars().first()
            assert ev.payload["github_token"] == "[REDACTED]"
            assert ev.payload["note"] == "safe"
            # And the digest was computed over the REDACTED payload
            recomputed = aus.compute_event_digest(
                chain_id=ev.chain_id, prev_digest=ev.prev_digest,
                canonical_payload=aus.canonical_event_payload(ev))
            assert recomputed == ev.event_digest

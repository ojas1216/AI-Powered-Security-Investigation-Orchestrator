"""Kafka streaming ingestion: SIEM firehose -> investigations.

Message contract (JSON):
    {"tenant": "<tenant-id>", "alert": {<RawAlert payload, incl. "source">}}

Semantics:
- **At-least-once**: offsets are committed only after the alert is successfully
  dispatched; a crash between dispatch and commit re-delivers (investigations
  are idempotent per source_alert_id at the analyst level, and dispatch assigns
  a fresh id, so the cost of a rare duplicate is one extra investigation, never
  a lost one).
- **Poison messages** (bad JSON, invalid tenant, schema violations) are published
  to the DLQ topic with the error in a header, then the offset is committed —
  one malformed event can never wedge the partition.
- **Backpressure**: the dispatcher's concurrency bound is awaited, so consumption
  slows down instead of exhausting memory during an alert storm.

Run:  python -m app.ingestion.kafka_consumer     (requires pip install '.[kafka]')
"""
from __future__ import annotations

import asyncio
import json

from app.core.logging import get_logger
from app.core.tenancy import validate_tenant_id
from app.ingestion.normalizers import get_normalizer
from app.schemas.alert import Alert
from app.schemas.common import SourceProduct

try:
    from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

    _HAVE_KAFKA = True
except Exception:  # pragma: no cover - optional dep
    _HAVE_KAFKA = False

log = get_logger("ingestion.kafka")


class PoisonMessage(Exception):
    """Message can never be processed; route to DLQ and move on."""


def parse_message(raw: bytes) -> tuple[str, Alert]:
    """Validate and normalize one Kafka message; raises PoisonMessage."""
    try:
        envelope = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PoisonMessage(f"invalid JSON: {exc}") from exc
    if not isinstance(envelope, dict):
        raise PoisonMessage("envelope must be a JSON object")

    tenant = envelope.get("tenant")
    payload = envelope.get("alert")
    if not isinstance(tenant, str) or not tenant:
        raise PoisonMessage("missing/invalid 'tenant'")
    if not isinstance(payload, dict):
        raise PoisonMessage("missing/invalid 'alert' object")
    try:
        tenant = validate_tenant_id(tenant)
    except Exception as exc:
        raise PoisonMessage(f"invalid tenant id: {exc}") from exc

    try:
        source = SourceProduct(payload.get("source", "generic"))
        alert = get_normalizer(source).normalize(payload)
    except Exception as exc:
        raise PoisonMessage(f"normalization failed: {exc}") from exc
    return tenant, alert


async def run_consumer() -> None:  # pragma: no cover - needs a Kafka broker
    from app.core.config import settings
    from app.orchestrator.dispatch import get_dispatcher

    consumer = AIOKafkaConsumer(
        settings.kafka_alerts_topic,
        bootstrap_servers=settings.kafka_bootstrap,
        group_id=settings.kafka_group_id,
        enable_auto_commit=False,          # commit only after dispatch
        auto_offset_reset="earliest",
    )
    producer = AIOKafkaProducer(bootstrap_servers=settings.kafka_bootstrap)
    await consumer.start()
    await producer.start()
    log.info("kafka_consumer_started", topic=settings.kafka_alerts_topic,
             group=settings.kafka_group_id)
    dispatcher = get_dispatcher()
    try:
        async for msg in consumer:
            try:
                tenant, alert = parse_message(msg.value)
            except PoisonMessage as exc:
                log.warning("poison_message", error=str(exc),
                            partition=msg.partition, offset=msg.offset)
                await producer.send_and_wait(
                    settings.kafka_dlq_topic, msg.value,
                    headers=[("x-aegis-error", str(exc).encode())])
                await consumer.commit()
                continue

            while True:  # backpressure: wait for capacity, never drop
                try:
                    investigation_id = await dispatcher.submit(tenant, alert)
                    break
                except Exception as exc:
                    log.warning("dispatch_backpressure", error=str(exc))
                    await asyncio.sleep(1.0)
            log.info("kafka_alert_dispatched", tenant=tenant,
                     investigation_id=investigation_id, offset=msg.offset)
            await consumer.commit()
    finally:
        await consumer.stop()
        await producer.stop()


def main() -> None:  # pragma: no cover - infra entrypoint
    if not _HAVE_KAFKA:
        raise SystemExit("aiokafka not installed: pip install '.[kafka]'")
    asyncio.run(run_consumer())


if __name__ == "__main__":  # pragma: no cover
    main()

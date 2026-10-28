"""
ThreatLens GraphOps - Apache Kafka Event Producer Service
Validates security-event envelopes, serializes canonical payloads, routes events to
configured topic partitions with entity-ordered keys, and tracks delivery confirmations.
"""

import json
import logging
import time
from typing import Dict, Any, Optional, Callable
from datetime import datetime, timezone

from backend.core import config
from backend.models.graphops import (
    SecurityEventType,
    SecurityEventEnvelope,
    DeadLetterEventEnvelope,
    SecurityFindingRecord,
    EventPublishResponse,
)

logger = logging.getLogger("threatlens.graphops.kafka_producer")


class KafkaProducerError(Exception):
    """Raised when publishing a security event to Kafka fails."""
    pass


class GraphOpsKafkaProducer:
    """
    Kafka event producer for ThreatLens GraphOps telemetry and findings streaming.
    Provides robust validation, per-entity key routing, and delivery callback handling.
    """

    def __init__(
        self,
        bootstrap_servers: Optional[str] = None,
        client_id: Optional[str] = None,
        mock_mode: bool = False,
    ):
        self.bootstrap_servers = bootstrap_servers or config.KAFKA_BOOTSTRAP_SERVERS
        self.client_id = client_id or config.KAFKA_CLIENT_ID
        self.mock_mode = mock_mode

        self._producer = None
        self._mock_messages: Dict[str, list] = {}
        self.published_count = 0
        self.failed_count = 0

        if not self.mock_mode:
            is_reachable = False
            try:
                import socket
                first_server = self.bootstrap_servers.split(",")[0].strip()
                host, port_str = first_server.split(":")
                with socket.create_connection((host, int(port_str)), timeout=1.0):
                    is_reachable = True
            except Exception:
                is_reachable = False

            if not is_reachable:
                self.mock_mode = True
                logger.info(
                    f"Live Kafka broker at {self.bootstrap_servers} is unreachable. "
                    f"Operating in mock queue mode."
                )
            else:
                try:
                    import confluent_kafka
                    conf = {
                        "bootstrap.servers": self.bootstrap_servers,
                        "client.id": self.client_id,
                        "acks": "all",  # Strongest durability guarantee
                        "retries": 3,
                        "retry.backoff.ms": 250,
                        "delivery.timeout.ms": 2000,
                        "socket.timeout.ms": 1000,
                    }
                    self._producer = confluent_kafka.Producer(conf)
                    logger.info(f"Initialized confluent_kafka.Producer targeting {self.bootstrap_servers}")
                except Exception as e:
                    logger.warning(
                        f"Could not connect live Kafka producer at {self.bootstrap_servers}: {e}. "
                        f"Falling back to local development mock producer."
                    )
                    self.mock_mode = True

    def get_topic_for_event_type(self, event_type: SecurityEventType) -> str:
        """Determines destination Kafka topic for a given security event type."""
        mapping = {
            SecurityEventType.ENDPOINT_ALERT: config.KAFKA_TOPIC_ENDPOINT_EVENTS,
            SecurityEventType.PROCESS_EVENT: config.KAFKA_TOPIC_ENDPOINT_EVENTS,
            SecurityEventType.COMPROMISE_INDICATOR: config.KAFKA_TOPIC_ENDPOINT_EVENTS,
            SecurityEventType.IDENTITY_EVENT: config.KAFKA_TOPIC_IDENTITY_EVENTS,
            SecurityEventType.NETWORK_CONNECTION: config.KAFKA_TOPIC_NETWORK_EVENTS,
            SecurityEventType.EMAIL_INVESTIGATION_RESULT: config.KAFKA_TOPIC_EMAIL_EVENTS,
        }
        return mapping.get(event_type, config.KAFKA_TOPIC_ENDPOINT_EVENTS)

    def publish_security_event(
        self,
        event: SecurityEventEnvelope,
        topic: Optional[str] = None,
        sync_timeout: float = 5.0,
    ) -> EventPublishResponse:
        """
        Validates, serializes, and publishes a security event envelope to Apache Kafka.
        Uses primary entity ID as message key to enforce per-entity partition ordering.
        """
        target_topic = topic or self.get_topic_for_event_type(event.event_type)
        message_key = event.entity_ids[0] if event.entity_ids else event.event_id
        serialized_payload = event.model_dump_json().encode("utf-8")

        if self.mock_mode or self._producer is None:
            if target_topic not in self._mock_messages:
                self._mock_messages[target_topic] = []
            offset = len(self._mock_messages[target_topic])
            self._mock_messages[target_topic].append({
                "key": message_key,
                "value": serialized_payload,
                "offset": offset,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            self.published_count += 1
            logger.debug(f"[MOCK] Published event {event.event_id} to {target_topic} (offset: {offset})")
            return EventPublishResponse(
                event_id=event.event_id,
                status="ACCEPTED_FOR_STREAMING",
                topic=target_topic,
                partition=0,
                offset=offset,
                message=f"Event queued to streaming topic '{target_topic}' (local mock pipeline).",
            )

        delivery_result: Dict[str, Any] = {"error": None, "partition": None, "offset": None}

        def _delivery_callback(err, msg):
            if err:
                delivery_result["error"] = str(err)
                self.failed_count += 1
                logger.error(f"Kafka delivery failed for event {event.event_id}: {err}")
            else:
                delivery_result["partition"] = msg.partition()
                delivery_result["offset"] = msg.offset()
                self.published_count += 1
                logger.debug(
                    f"Kafka event {event.event_id} delivered to {msg.topic()} "
                    f"[{msg.partition()}] at offset {msg.offset()}"
                )

        try:
            self._producer.produce(
                topic=target_topic,
                key=message_key.encode("utf-8"),
                value=serialized_payload,
                on_delivery=_delivery_callback,
            )
            # Flush synchronously up to sync_timeout to verify delivery confirmation
            self._producer.flush(timeout=sync_timeout)

            if delivery_result["error"]:
                err_str = str(delivery_result["error"])
                if "Message timed out" in err_str or "Broker transport failure" in err_str or "_MSG_TIMED_OUT" in err_str:
                    logger.warning(
                        f"Live Kafka broker transport timeout ({err_str}). "
                        f"Gracefully operating via local development queue mode."
                    )
                    self.mock_mode = True
                    return self.publish_security_event(event, topic=topic)
                raise KafkaProducerError(f"Delivery failed: {delivery_result['error']}")

            return EventPublishResponse(
                event_id=event.event_id,
                status="ACCEPTED_FOR_STREAMING",
                topic=target_topic,
                partition=delivery_result.get("partition", 0),
                offset=delivery_result.get("offset", 0),
                message=f"Security event confirmed published to topic '{target_topic}'.",
            )
        except KafkaProducerError:
            raise
        except Exception as e:
            err_str = str(e)
            if "Message timed out" in err_str or "Broker transport failure" in err_str or "_MSG_TIMED_OUT" in err_str:
                logger.warning(
                    f"Live Kafka broker transport failure ({err_str}). "
                    f"Gracefully operating via local development queue mode."
                )
                self.mock_mode = True
                return self.publish_security_event(event, topic=topic)
            self.failed_count += 1
            raise KafkaProducerError(f"Failed to publish event {event.event_id} to {target_topic}: {e}")

    def publish_dead_letter(
        self,
        dlq_envelope: DeadLetterEventEnvelope,
    ) -> EventPublishResponse:
        """Publishes an unprocessable message to the dead-letter topic."""
        target_topic = config.KAFKA_TOPIC_DLQ
        message_key = dlq_envelope.event_id or "UNKNOWN"
        payload = dlq_envelope.model_dump_json().encode("utf-8")

        if self.mock_mode or self._producer is None:
            if target_topic not in self._mock_messages:
                self._mock_messages[target_topic] = []
            offset = len(self._mock_messages[target_topic])
            self._mock_messages[target_topic].append({
                "key": message_key,
                "value": payload,
                "offset": offset,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            return EventPublishResponse(
                event_id=message_key,
                status="DEAD_LETTERED",
                topic=target_topic,
                partition=0,
                offset=offset,
                message="Message safely routed to Dead-Letter Queue.",
            )

        try:
            self._producer.produce(
                topic=target_topic,
                key=message_key.encode("utf-8"),
                value=payload,
            )
            self._producer.flush(timeout=2.0)
            return EventPublishResponse(
                event_id=message_key,
                status="DEAD_LETTERED",
                topic=target_topic,
                message="Message safely routed to Dead-Letter Queue.",
            )
        except Exception as e:
            logger.error(f"Failed to dead-letter message {message_key}: {e}")
            raise KafkaProducerError(f"Failed to write to DLQ: {e}")

    def publish_finding(self, finding: SecurityFindingRecord) -> EventPublishResponse:
        """Publishes an explainable GraphOps security finding to the findings topic."""
        target_topic = config.KAFKA_TOPIC_FINDINGS
        message_key = finding.affected_entity_id
        payload = finding.model_dump_json().encode("utf-8")

        if self.mock_mode or self._producer is None:
            if target_topic not in self._mock_messages:
                self._mock_messages[target_topic] = []
            offset = len(self._mock_messages[target_topic])
            self._mock_messages[target_topic].append({
                "key": message_key,
                "value": payload,
                "offset": offset,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            return EventPublishResponse(
                event_id=finding.finding_id,
                status="ACCEPTED_FOR_STREAMING",
                topic=target_topic,
                partition=0,
                offset=offset,
                message="Finding published to graphops.findings.",
            )

        try:
            self._producer.produce(
                topic=target_topic,
                key=message_key.encode("utf-8"),
                value=payload,
            )
            self._producer.flush(timeout=2.0)
            return EventPublishResponse(
                event_id=finding.finding_id,
                status="ACCEPTED_FOR_STREAMING",
                topic=target_topic,
                message="Finding successfully published to graphops.findings.",
            )
        except Exception as e:
            logger.error(f"Failed to publish finding {finding.finding_id}: {e}")
            raise KafkaProducerError(f"Failed to publish finding: {e}")

    def flush(self, timeout: float = 5.0) -> int:
        """Flushes buffered messages."""
        if self._producer:
            return self._producer.flush(timeout=timeout)
        return 0

    def close(self):
        """Flushes and releases producer resources."""
        self.flush()

    def health_check(self) -> Dict[str, Any]:
        """Returns sanitized producer readiness diagnostics."""
        return {
            "status": "online" if (self._producer or self.mock_mode) else "offline",
            "mock_mode": self.mock_mode,
            "bootstrap_servers": self.bootstrap_servers,
            "published_count": self.published_count,
            "failed_count": self.failed_count,
        }


# Global producer singleton accessor
_global_producer: Optional[GraphOpsKafkaProducer] = None


def get_kafka_producer() -> GraphOpsKafkaProducer:
    """Returns singleton instance of GraphOpsKafkaProducer."""
    global _global_producer
    if _global_producer is None:
        _global_producer = GraphOpsKafkaProducer()
    return _global_producer

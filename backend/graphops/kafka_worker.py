"""
ThreatLens GraphOps - Dedicated Apache Kafka Consumer Worker
Continuously polls security-event topics, decodes canonical envelopes, handles transient
retries with backoff, routes permanent failures to the Dead-Letter Queue (DLQ), and
commits offsets strictly after successful graph updates and analytics execution.
"""

import json
import logging
import signal
import sys
import time
import threading
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

from backend.core import config
from backend.models.graphops import (
    SecurityEventType,
    SecurityEventEnvelope,
    DeadLetterEventEnvelope,
)
from backend.graphops.kafka_producer import GraphOpsKafkaProducer, get_kafka_producer
from backend.graphops.kafka_processor import (
    GraphOpsEventProcessor,
    PermanentEventError,
    TransientEventError,
)

logger = logging.getLogger("threatlens.graphops.kafka_worker")


class GraphOpsKafkaWorker:
    """
    Continuous Kafka event consumer worker.
    Provides controlled message polling, error classification, bounded retries,
    dead-letter queue publication, and manual offset commits.
    """

    def __init__(
        self,
        bootstrap_servers: Optional[str] = None,
        group_id: Optional[str] = None,
        topics: Optional[List[str]] = None,
        processor: Optional[GraphOpsEventProcessor] = None,
        producer: Optional[GraphOpsKafkaProducer] = None,
        mock_mode: bool = False,
    ):
        self.bootstrap_servers = bootstrap_servers or config.KAFKA_BOOTSTRAP_SERVERS
        self.group_id = group_id or config.KAFKA_CONSUMER_GROUP
        self.topics = topics or [
            config.KAFKA_TOPIC_ENDPOINT_EVENTS,
            config.KAFKA_TOPIC_IDENTITY_EVENTS,
            config.KAFKA_TOPIC_NETWORK_EVENTS,
            config.KAFKA_TOPIC_EMAIL_EVENTS,
        ]
        self.producer = producer or get_kafka_producer()
        self.processor = processor or GraphOpsEventProcessor(producer=self.producer)
        self.mock_mode = mock_mode or self.producer.mock_mode

        self.max_retries = config.KAFKA_MAX_RETRIES
        self.retry_backoff_sec = config.KAFKA_RETRY_BACKOFF_SECONDS
        self.poll_timeout = config.KAFKA_POLL_TIMEOUT_SECONDS

        self._consumer = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # Diagnostics & Metrics
        self.processed_count = 0
        self.retried_count = 0
        self.dlq_count = 0
        self.last_processed_timestamp: Optional[str] = None

        if not self.mock_mode:
            self._init_consumer()

    def _init_consumer(self):
        """Initializes confluent_kafka.Consumer if reachable."""
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
                f"Operating consumer in mock queue mode."
            )
        else:
            try:
                import confluent_kafka
                from confluent_kafka.admin import AdminClient, NewTopic

                # Ensure all subscribed topics exist on the broker before subscribing
                try:
                    admin = AdminClient({"bootstrap.servers": self.bootstrap_servers})
                    metadata = admin.list_topics(timeout=3.0)
                    existing_topics = set(metadata.topics.keys())
                    missing_topics = [t for t in self.topics if t not in existing_topics]
                    if missing_topics:
                        new_topics = [NewTopic(t, num_partitions=1, replication_factor=1) for t in missing_topics]
                        futures = admin.create_topics(new_topics)
                        for topic_name, future in futures.items():
                            try:
                                future.result(timeout=3.0)
                                logger.info("Auto-created missing Kafka topic on broker: %s", topic_name)
                            except Exception as ex:
                                logger.debug("Topic %s already exists or creation note: %s", topic_name, ex)
                except Exception as ex:
                    logger.debug("Topic existence verification warning: %s", ex)

                conf = {
                    "bootstrap.servers": self.bootstrap_servers,
                    "group.id": self.group_id,
                    "auto.offset.reset": config.KAFKA_AUTO_OFFSET_RESET,
                    "enable.auto.commit": False,  # Manual commit after processing!
                    "session.timeout.ms": 10000,
                    "max.poll.interval.ms": 300000,
                }
                self._consumer = confluent_kafka.Consumer(conf)
                self._consumer.subscribe(self.topics)
                logger.info(
                    f"Initialized confluent_kafka.Consumer (group: {self.group_id}) "
                    f"subscribed to {self.topics}"
                )
            except Exception as e:
                logger.warning(
                    f"Could not connect live Kafka consumer at {self.bootstrap_servers}: {e}. "
                    f"Operating in mock queue mode."
                )
                self.mock_mode = True

    def process_raw_message(
        self,
        raw_bytes: bytes,
        source_topic: str,
        partition: int = 0,
        offset: int = 0,
    ) -> bool:
        """
        Decodes raw Kafka bytes, parses SecurityEventEnvelope, executes retries,
        and triggers graph processing. Returns True if processed, False if dead-lettered.
        """
        # 1. Decode & Parse JSON
        try:
            payload_str = raw_bytes.decode("utf-8")
            data = json.loads(payload_str)
        except Exception as e:
            logger.error(f"Malformed non-JSON message on topic {source_topic}: {e}")
            self._route_to_dlq(
                event_id=None,
                source_topic=source_topic,
                partition=partition,
                offset=offset,
                failure_category="PERMANENT_MALFORMED_JSON",
                error_msg=f"JSON decoding failed: {e}",
                raw_payload={"raw_sample": str(raw_bytes[:200])},
            )
            return False

        # 2. Validate SecurityEventEnvelope Contract
        try:
            event = SecurityEventEnvelope(**data)
        except Exception as e:
            logger.error(f"Schema validation failed on topic {source_topic}: {e}")
            self._route_to_dlq(
                event_id=data.get("event_id") if isinstance(data, dict) else None,
                source_topic=source_topic,
                partition=partition,
                offset=offset,
                failure_category="PERMANENT_SCHEMA_VALIDATION_ERROR",
                error_msg=f"Pydantic validation error: {e}",
                raw_payload=data if isinstance(data, dict) else None,
            )
            return False

        # 3. Process with bounded retries
        attempt = 0
        while attempt <= self.max_retries:
            try:
                self.processor.process_event(event)
                self.processed_count += 1
                self.last_processed_timestamp = datetime.now(timezone.utc).isoformat()
                logger.info(f"Successfully processed event {event.event_id} from {source_topic}")
                return True
            except PermanentEventError as e:
                logger.error(f"Permanent error processing event {event.event_id}: {e}")
                self._route_to_dlq(
                    event_id=event.event_id,
                    source_topic=source_topic,
                    partition=partition,
                    offset=offset,
                    failure_category="PERMANENT_ENTITY_ERROR",
                    error_msg=str(e),
                    raw_payload=event.model_dump(),
                    retry_count=attempt,
                )
                return False
            except (TransientEventError, Exception) as e:
                attempt += 1
                self.retried_count += 1
                if attempt > self.max_retries:
                    logger.error(
                        f"Retries exhausted ({self.max_retries}) for event {event.event_id}. Routing to DLQ: {e}"
                    )
                    self._route_to_dlq(
                        event_id=event.event_id,
                        source_topic=source_topic,
                        partition=partition,
                        offset=offset,
                        failure_category="TRANSIENT_RETRIES_EXHAUSTED",
                        error_msg=f"Exhausted {self.max_retries} attempts: {e}",
                        raw_payload=event.model_dump(),
                        retry_count=attempt,
                    )
                    return False
                logger.warning(
                    f"Transient error on event {event.event_id} (attempt {attempt}/{self.max_retries}): {e}. "
                    f"Backing off for {self.retry_backoff_sec * attempt}s..."
                )
                time.sleep(self.retry_backoff_sec * attempt)

        return False

    def _route_to_dlq(
        self,
        event_id: Optional[str],
        source_topic: str,
        partition: int,
        offset: int,
        failure_category: str,
        error_msg: str,
        raw_payload: Optional[Dict[str, Any]],
        retry_count: int = 0,
    ):
        """Builds and publishes DeadLetterEventEnvelope."""
        self.dlq_count += 1
        dlq_envelope = DeadLetterEventEnvelope(
            event_id=event_id,
            source_topic=source_topic,
            partition=partition,
            offset=offset,
            failure_category=failure_category,
            sanitized_error=error_msg,
            retry_count=retry_count,
            raw_payload=raw_payload,
        )
        try:
            self.producer.publish_dead_letter(dlq_envelope)
        except Exception as e:
            logger.critical(f"FATAL: Failed to write to Dead-Letter Queue: {e}")

    def run_once(self) -> int:
        """
        Polls and processes one batch/message.
        Essential for unit and deterministic integration tests.
        Returns the number of messages processed.
        """
        if self.mock_mode or self._consumer is None or getattr(self.producer, "mock_mode", False):
            # Consume from producer's mock message buffer
            count = 0
            for topic in self.topics:
                msgs = self.producer._mock_messages.get(topic, [])
                while msgs:
                    msg_item = msgs.pop(0)
                    self.process_raw_message(
                        raw_bytes=msg_item["value"],
                        source_topic=topic,
                        offset=msg_item["offset"],
                    )
                    count += 1
            return count

        # Live Kafka Poll
        msg = self._consumer.poll(timeout=self.poll_timeout)
        if msg is None:
            return 0
        if msg.error():
            logger.error(f"Consumer poll error: {msg.error()}")
            return 0

        success = self.process_raw_message(
            raw_bytes=msg.value(),
            source_topic=msg.topic(),
            partition=msg.partition(),
            offset=msg.offset(),
        )

        # Manual offset commit strictly after processing or confirmed DLQ
        try:
            self._consumer.commit(message=msg, asynchronous=False)
        except Exception as e:
            logger.error(f"Failed to commit Kafka offset: {e}")

        return 1

    def run_loop(self):
        """Continuous consumer polling loop."""
        logger.info(f"Starting GraphOps Kafka worker polling loop (mock_mode={self.mock_mode})...")
        self._running = True
        while self._running:
            try:
                processed = self.run_once()
                if processed == 0:
                    time.sleep(0.1)
            except Exception as e:
                if not self._running:
                    break
                logger.error(f"Unexpected error in consumer loop: {e}")
                time.sleep(1.0)
        logger.info("Kafka consumer loop gracefully stopped.")

    def start_background(self):
        """Starts worker in a dedicated daemon thread."""
        with self._lock:
            if self._thread and self._thread.is_alive():
                logger.debug("Kafka worker background thread is already running.")
                return
            if not self.mock_mode and self._consumer is None:
                self._init_consumer()
            self._running = True
            self._thread = threading.Thread(target=self.run_loop, daemon=True, name="KafkaWorkerThread")
            self._thread.start()
            logger.info("Started GraphOps Kafka worker background thread.")

    def stop(self):
        """Stops the consumer loop and closes Kafka connection."""
        with self._lock:
            self._running = False
            if self._thread and self._thread.is_alive():
                # Allow background thread to cleanly exit its current poll iteration
                self._thread.join(timeout=max(self.poll_timeout + 1.0, 3.0))
                if self._thread.is_alive():
                    logger.warning("Kafka worker thread did not stop within timeout.")
            self._thread = None
            if self._consumer:
                try:
                    self._consumer.close()
                except Exception as e:
                    logger.warning(f"Error closing Kafka consumer: {e}")
                self._consumer = None

    def get_status(self) -> Dict[str, Any]:
        """Returns health diagnostics and consumption metrics."""
        is_running = bool(self._running and self._thread and self._thread.is_alive())
        return {
            "worker_running": is_running,
            "mock_mode": self.mock_mode,
            "bootstrap_servers": self.bootstrap_servers,
            "consumer_group": self.group_id,
            "subscribed_topics": self.topics,
            "processed_events_count": self.processed_count,
            "retried_events_count": self.retried_count,
            "dead_letter_events_count": self.dlq_count,
            "last_processed_timestamp": self.last_processed_timestamp,
        }


# Singleton accessor
_global_worker: Optional[GraphOpsKafkaWorker] = None
_global_worker_lock = threading.Lock()


def get_kafka_worker() -> GraphOpsKafkaWorker:
    """Returns singleton instance of GraphOpsKafkaWorker."""
    global _global_worker
    if _global_worker is None:
        with _global_worker_lock:
            if _global_worker is None:
                _global_worker = GraphOpsKafkaWorker()
    return _global_worker


def reset_kafka_worker(worker: Optional[GraphOpsKafkaWorker] = None):
    """Sets or resets the global singleton worker (primarily for testing)."""
    global _global_worker
    with _global_worker_lock:
        if _global_worker is not None and _global_worker is not worker:
            try:
                _global_worker.stop()
            except Exception:
                pass
        _global_worker = worker


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    worker = get_kafka_worker()

    def _sig_handler(sig, frame):
        logger.info(f"Signal {sig} received. Initiating graceful shutdown...")
        worker.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    worker.run_loop()

"""
ThreatLens GraphOps - Kafka Consumer Lifecycle & FastAPI Lifespan Unit Test Suite
Verifies:
1. Startup retrieves singleton worker and invokes start_background exactly once.
2. Multiple calls to start_background do not spawn duplicate threads.
3. Shutdown stops worker and guarantees close_graphops_client execution even if worker stop raises.
4. Startup and shutdown exceptions are caught and logged without crashing the application.
5. Worker get_status accurately reflects thread running state.
6. TestClient lifespan lifecycle integration with /events/status.
"""

import threading
import logging
from unittest.mock import MagicMock, patch
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.main import lifespan, app
from backend.graphops.kafka_worker import (
    GraphOpsKafkaWorker,
    get_kafka_worker,
    reset_kafka_worker,
)
from backend.graphops.kafka_producer import GraphOpsKafkaProducer


@pytest.fixture(autouse=True)
def cleanup_worker():
    """Ensures global worker is safely stopped and reset after each test."""
    yield
    reset_kafka_worker(None)


def test_lifespan_starts_and_stops_singleton_worker():
    """Lifespan must start the Kafka worker on entry and stop it and the DB on exit."""
    mock_worker = MagicMock()
    mock_close_client = MagicMock()

    with patch("backend.main.get_kafka_worker", return_value=mock_worker), \
         patch("backend.main.close_graphops_client", mock_close_client):

        test_app = FastAPI(lifespan=lifespan)
        with TestClient(test_app):
            mock_worker.start_background.assert_called_once()
            mock_worker.stop.assert_not_called()
            mock_close_client.assert_not_called()

        mock_worker.stop.assert_called_once()
        mock_close_client.assert_called_once()


def test_start_background_idempotent_no_duplicate_threads():
    """Repeated calls to start_background must not spawn duplicate threads."""
    producer = GraphOpsKafkaProducer(mock_mode=True)
    worker = GraphOpsKafkaWorker(producer=producer, mock_mode=True)

    try:
        assert worker._thread is None
        assert not worker.get_status()["worker_running"]

        # 1. First start
        worker.start_background()
        assert worker._thread is not None
        assert worker._thread.is_alive()
        assert worker.get_status()["worker_running"]
        first_thread = worker._thread

        # 2. Second redundant start call
        worker.start_background()
        assert worker._thread is first_thread
        assert threading.active_count() >= 1

        # 3. Clean stop
        worker.stop()
        assert worker._thread is None
        assert not worker._running
        assert not worker.get_status()["worker_running"]
    finally:
        worker.stop()


def test_shutdown_guarantees_cleanup_on_worker_stop_exception():
    """If stopping the worker raises an exception, DB client close must still execute."""
    mock_worker = MagicMock()
    mock_worker.stop.side_effect = RuntimeError("Simulated worker stop failure")
    mock_close_client = MagicMock()

    with patch("backend.main.get_kafka_worker", return_value=mock_worker), \
         patch("backend.main.close_graphops_client", mock_close_client), \
         patch("backend.main.logger") as mock_logger:

        test_app = FastAPI(lifespan=lifespan)
        with TestClient(test_app):
            pass

        mock_worker.stop.assert_called_once()
        mock_close_client.assert_called_once()
        mock_logger.error.assert_called()


def test_shutdown_guarantees_cleanup_on_client_close_exception():
    """If DB client close raises an exception, it is caught and logged."""
    mock_worker = MagicMock()
    mock_close_client = MagicMock(side_effect=RuntimeError("Simulated DB close failure"))

    with patch("backend.main.get_kafka_worker", return_value=mock_worker), \
         patch("backend.main.close_graphops_client", mock_close_client), \
         patch("backend.main.logger") as mock_logger:

        test_app = FastAPI(lifespan=lifespan)
        with TestClient(test_app):
            pass

        mock_worker.stop.assert_called_once()
        mock_close_client.assert_called_once()
        mock_logger.error.assert_called()


def test_startup_worker_failure_handled_and_logged():
    """Startup failure does not prevent FastAPI from starting and is logged."""
    mock_close_client = MagicMock()

    with patch("backend.main.get_kafka_worker", side_effect=RuntimeError("Worker init failed")), \
         patch("backend.main.close_graphops_client", mock_close_client), \
         patch("backend.main.logger") as mock_logger:

        test_app = FastAPI(lifespan=lifespan)
        with TestClient(test_app):
            pass

        mock_close_client.assert_called_once()
        mock_logger.error.assert_called()


def test_worker_get_status_reflects_actual_running_state():
    """Worker status accurately reports running state throughout lifecycle."""
    producer = GraphOpsKafkaProducer(mock_mode=True)
    worker = GraphOpsKafkaWorker(producer=producer, mock_mode=True)

    try:
        # Before starting: not running
        status_before = worker.get_status()
        assert status_before["worker_running"] is False
        assert status_before["mock_mode"] is True

        # After starting: running
        worker.start_background()
        status_during = worker.get_status()
        assert status_during["worker_running"] is True

        # After stopping: not running
        worker.stop()
        status_after = worker.get_status()
        assert status_after["worker_running"] is False
    finally:
        worker.stop()


def test_fastapi_testclient_lifespan_integration():
    """FastAPI TestClient enters lifespan, starts worker, and exposes valid /events/status."""
    producer = GraphOpsKafkaProducer(mock_mode=True)
    worker = GraphOpsKafkaWorker(producer=producer, mock_mode=True)
    reset_kafka_worker(worker)

    try:
        with TestClient(app) as client:
            resp = client.get("/api/v1/graphops/events/status")
            assert resp.status_code == 200
            data = resp.json()
            assert "consumer_worker_running" in data
            assert data["consumer_worker_running"] is True
            assert "bootstrap_servers" in data
            assert "active_consumer_group" in data
    finally:
        worker.stop()


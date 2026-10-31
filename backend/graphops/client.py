"""
ThreatLens GraphOps - Neo4j Database Client & Repository
Dedicated Neo4j driver initialization, connection pooling, session management,
parameterized Cypher execution, schema constraint deployment, and health monitoring.
"""

import threading
from typing import Dict, List, Optional, Any, Tuple
import logging

try:
    import neo4j
    from neo4j.exceptions import (
        ServiceUnavailable,
        AuthError,
        ConfigurationError as Neo4jConfigError,
        Neo4jError,
        DatabaseError,
        ClientError,
    )
except ImportError:
    neo4j = None
    ServiceUnavailable = Exception
    AuthError = Exception
    Neo4jConfigError = Exception
    Neo4jError = Exception
    DatabaseError = Exception
    ClientError = Exception

from backend.core import config as app_config
from backend.graphops.schema import CYPHER_SCHEMA_STATEMENTS

logger = logging.getLogger("threatlens.graphops.client")


# =====================================================================
# DOMAIN EXCEPTIONS
# =====================================================================

class GraphOpsDatabaseError(Exception):
    """Base exception for all GraphOps database errors."""
    pass


class GraphOpsConnectionError(GraphOpsDatabaseError):
    """Raised when Neo4j is unreachable, connection times out, or authentication fails."""
    pass


class GraphOpsQueryError(GraphOpsDatabaseError):
    """Raised when a Cypher query execution fails or violates database constraints."""
    pass


class GraphOpsConfigurationError(GraphOpsDatabaseError):
    """Raised when Neo4j configuration is missing or invalid."""
    pass


# =====================================================================
# NEO4J CLIENT CLASS
# =====================================================================

class Neo4jClient:
    """
    Thread-safe client managing the lifecycle of the official Neo4j Python driver.
    Provides connection verification, safe health checks, transaction execution,
    and automatic resource cleanup.
    """

    def __init__(
        self,
        uri: Optional[str] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
        database: Optional[str] = None,
        connection_timeout: Optional[float] = None,
        max_connection_lifetime: Optional[float] = None,
        max_connection_pool_size: Optional[int] = None,
    ):
        self.uri = uri if uri is not None else app_config.NEO4J_URI
        self.user = user if user is not None else app_config.NEO4J_USER
        self.password = password if password is not None else app_config.NEO4J_PASSWORD
        self.database = database if database is not None else app_config.NEO4J_DATABASE
        self.connection_timeout = (
            connection_timeout
            if connection_timeout is not None
            else app_config.NEO4J_CONNECTION_TIMEOUT_SECONDS
        )
        self.max_connection_lifetime = (
            max_connection_lifetime
            if max_connection_lifetime is not None
            else app_config.NEO4J_MAX_CONNECTION_LIFETIME_SECONDS
        )
        self.max_connection_pool_size = (
            max_connection_pool_size
            if max_connection_pool_size is not None
            else app_config.NEO4J_MAX_CONNECTION_POOL_SIZE
        )

        self._driver: Optional[Any] = None
        self._mock_client: Optional[Any] = None
        self._is_available: Optional[bool] = None
        self._lock = threading.Lock()

    def _get_mock_fallback(self) -> Any:
        if self._mock_client is None:
            try:
                from backend.graphops.mock_client import get_mock_graphops_client
                self._mock_client = get_mock_graphops_client()
            except Exception as e:
                logger.error("Failed to initialize in-memory fallback graph client: %s", e)
        return self._mock_client

    def get_driver(self) -> Any:
        """
        Lazily creates and returns the singleton neo4j.Driver instance with connection pooling.
        Raises GraphOpsConfigurationError if the neo4j library is missing or URI is invalid.
        """
        if neo4j is None:
            raise GraphOpsConfigurationError(
                "The 'neo4j' Python package is not installed. Please run: pip install 'neo4j>=5.28.0,<6.0.0'"
            )

        if not self.uri:
            raise GraphOpsConfigurationError("Neo4j database URI is not configured.")

        with self._lock:
            if self._driver is None:
                auth = (self.user, self.password) if self.user else None
                try:
                    self._driver = neo4j.GraphDatabase.driver(
                        self.uri,
                        auth=auth,
                        connection_timeout=min(self.connection_timeout, 2.0),
                        max_connection_lifetime=self.max_connection_lifetime,
                        max_connection_pool_size=self.max_connection_pool_size,
                        max_transaction_retry_time=1.0,
                    )
                    logger.info(f"Neo4j driver initialized for {self.uri} (user: {self.user})")
                except Exception as e:
                    raise GraphOpsConfigurationError(f"Failed to initialize Neo4j driver: {str(e)}")

        return self._driver

    def verify_connectivity(self) -> Dict[str, Any]:
        """
        Actively verifies connectivity to the Neo4j cluster/server.
        Returns sanitized server metadata without exposing credentials.
        Raises GraphOpsConnectionError if connection fails.
        """
        if self._is_available is False:
            raise GraphOpsConnectionError(f"Neo4j service unavailable at {self.uri}")

        driver = self.get_driver()
        try:
            server_info = driver.verify_connectivity()
            self._is_available = True
            # server_info can be ServerInfo object or dict depending on driver version
            agent = getattr(server_info, "agent", "Neo4j")
            protocol_version = getattr(server_info, "protocol_version", "Bolt")
            address = getattr(server_info, "address", self.uri)
            return {
                "connected": True,
                "agent": str(agent),
                "protocol_version": str(protocol_version),
                "address": str(address),
            }
        except (ServiceUnavailable, ConnectionRefusedError, TimeoutError, OSError) as e:
            self._is_available = False
            raise GraphOpsConnectionError(f"Neo4j service unavailable at {self.uri}: {str(e)}")
        except AuthError as e:
            self._is_available = False
            raise GraphOpsConnectionError(f"Neo4j authentication failed for user '{self.user}': {str(e)}")
        except Exception as e:
            self._is_available = False
            raise GraphOpsConnectionError(f"Neo4j connectivity check failed: {str(e)}")

    def health_check(self) -> Dict[str, Any]:
        """
        Non-raising safe health and readiness check for API health endpoints.
        Never discloses passwords or sensitive credentials.
        """
        try:
            info = self.verify_connectivity()
            return {
                "status": "healthy",
                "database": self.database,
                "connected": True,
                "server_agent": info.get("agent", "Neo4j Community"),
                "protocol": info.get("protocol_version", "Bolt"),
            }
        except Exception as e:
            # Return unhealthy when Neo4j is genuinely unreachable
            return {
                "status": "unhealthy",
                "database": self.database,
                "connected": False,
                "error": str(e),
            }

    def execute_query(
        self,
        query: str,
        parameters: Optional[Dict[str, Any]] = None,
        database: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Executes a parameterized Cypher read query within a managed session.
        Returns records as a list of dictionaries.
        Raises GraphOpsConnectionError or GraphOpsQueryError on failure.
        """
        driver = self.get_driver()
        db = database or self.database
        params = parameters or {}

        try:
            with driver.session(database=db) as session:
                result = session.run(query, params)
                records = [record.data() for record in result]
                self._is_available = True
                return records
        except (ServiceUnavailable, ConnectionRefusedError, TimeoutError, OSError, GraphOpsConnectionError) as e:
            self._is_available = False
            raise GraphOpsConnectionError(f"Failed to connect to Neo4j during query execution: {str(e)}")
        except AuthError as e:
            raise GraphOpsConnectionError(f"Neo4j authentication failed: {str(e)}")
        except Neo4jError as e:
            raise GraphOpsQueryError(f"Cypher query execution error [{e.code}]: {e.message}")
        except Exception as e:
            raise GraphOpsQueryError(f"Query execution failed: {str(e)}")

    def execute_write(
        self,
        query: str,
        parameters: Optional[Dict[str, Any]] = None,
        database: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Executes a parameterized Cypher write query within an explicit write transaction.
        Guarantees proper transaction commit or rollback on exception.
        Returns execution counters summary.
        """
        driver = self.get_driver()
        db = database or self.database
        params = parameters or {}

        def _transaction_work(tx):
            res = tx.run(query, params)
            consume = res.consume()
            counters = consume.counters
            return {
                "nodes_created": counters.nodes_created,
                "nodes_deleted": counters.nodes_deleted,
                "relationships_created": counters.relationships_created,
                "relationships_deleted": counters.relationships_deleted,
                "properties_set": counters.properties_set,
                "labels_added": counters.labels_added,
                "indexes_added": counters.indexes_added,
                "constraints_added": counters.constraints_added,
            }

        try:
            with driver.session(database=db) as session:
                out = session.execute_write(_transaction_work)
                self._is_available = True
                return out
        except (ServiceUnavailable, ConnectionRefusedError, TimeoutError, OSError, GraphOpsConnectionError) as e:
            self._is_available = False
            raise GraphOpsConnectionError(f"Failed to connect to Neo4j during write transaction: {str(e)}")
        except AuthError as e:
            raise GraphOpsConnectionError(f"Neo4j write authentication failed: {str(e)}")
        except Neo4jError as e:
            raise GraphOpsQueryError(f"Cypher write execution error [{e.code}]: {e.message}")
        except Exception as e:
            raise GraphOpsQueryError(f"Write transaction failed: {str(e)}")

    def init_schema_constraints(self, database: Optional[str] = None) -> Dict[str, Any]:
        """
        Applies standard Neo4j 5 unique constraints and indexes defined in CYPHER_SCHEMA_STATEMENTS.
        Safe and idempotent (uses IF NOT EXISTS).
        """
        applied = []
        errors = []

        for stmt in CYPHER_SCHEMA_STATEMENTS:
            try:
                self.execute_write(stmt, database=database)
                applied.append(stmt)
            except Exception as e:
                # If constraint already exists or syntax differs slightly across community minor versions
                errors.append(f"Statement failed: {stmt} -> {str(e)}")

        return {
            "total_statements": len(CYPHER_SCHEMA_STATEMENTS),
            "applied_count": len(applied),
            "applied": applied,
            "errors": errors,
        }

    def close(self) -> None:
        """
        Safely shuts down the driver and closes all idle connections in the pool.
        """
        with self._lock:
            if self._driver is not None:
                try:
                    self._driver.close()
                    logger.info("Neo4j driver closed successfully.")
                except Exception as e:
                    logger.warning(f"Error while closing Neo4j driver: {e}")
                finally:
                    self._driver = None


# =====================================================================
# GLOBAL SINGLETON & LIFECYCLE HELPERS
# =====================================================================

_global_graphops_client: Optional[Neo4jClient] = None
_client_lock = threading.Lock()


def get_graphops_client() -> Neo4jClient:
    """Returns the process-wide default Neo4j client instance."""
    global _global_graphops_client
    if _global_graphops_client is None:
        with _client_lock:
            if _global_graphops_client is None:
                _global_graphops_client = Neo4jClient()
    return _global_graphops_client


def close_graphops_client() -> None:
    """Closes and releases the process-wide Neo4j client on shutdown."""
    global _global_graphops_client
    with _client_lock:
        if _global_graphops_client is not None:
            _global_graphops_client.close()
            _global_graphops_client = None

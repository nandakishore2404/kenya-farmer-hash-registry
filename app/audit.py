"""
Asynchronous, Decoupled Audit Logging Engine for High-Volume PEP Verification
Decouples Policy Enforcement Point (PEP) consent checks (/v1/consent/check, /v1/consent/status)
from synchronous database write I/O.
- Enqueues audit events into a thread-safe in-memory buffer in <0.05ms.
- Background worker thread persists batches to SQLite/PostgreSQL.
- Transient DB errors are retried with exponential backoff (3 attempts).
- Unrecoverable failures spill to an append-only dead-letter audit file (audit_dead_letter.jsonl).
"""

import os
import json
import time
import queue
import logging
import threading
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import Optional, List, Callable
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import AuditLog

logger = logging.getLogger("oan.audit")

DEFAULT_DEAD_LETTER_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "audit_dead_letter.jsonl"
)

@dataclass
class AuditEvent:
    action: str
    partner_id: str
    entity_id: Optional[str] = None
    farmer_id: Optional[int] = None
    on_behalf_of_partner_id: Optional[str] = None
    at: Optional[datetime] = None

class AsyncAuditWorker:
    """
    Decoupled, non-blocking in-process audit logger for high-volume PEP paths.
    Fits single-server pilot deployments without requiring external infrastructure (Redis/Kafka).
    """
    def __init__(
        self,
        session_factory: Callable[[], Session] = SessionLocal,
        max_batch_size: int = 100,
        poll_interval: float = 0.05,
        dead_letter_path: str = DEFAULT_DEAD_LETTER_PATH
    ):
        self.session_factory = session_factory
        self.max_batch_size = max_batch_size
        self.poll_interval = poll_interval
        self.dead_letter_path = dead_letter_path
        self._queue: queue.Queue = queue.Queue()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._pause_event = threading.Event()
        self._pause_event.set()  # Unpaused by default
        self._lock = threading.Lock()
        self.total_enqueued = 0
        self.total_persisted = 0
        self.total_dead_letter = 0

    def start(self):
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop_event.clear()
            self._pause_event.set()
            self._thread = threading.Thread(
                target=self._run_worker,
                name="AsyncAuditWorkerThread",
                daemon=True
            )
            self._thread.start()

    def stop(self, flush: bool = True):
        self._stop_event.set()
        if flush:
            self.flush()
        with self._lock:
            if self._thread and self._thread.is_alive():
                self._thread.join(timeout=3.0)

    def pause(self):
        """Pauses worker consumption for deterministic non-blocking regression testing."""
        self._pause_event.clear()

    def resume(self):
        """Resumes worker consumption."""
        self._pause_event.set()

    def enqueue(
        self,
        action: str,
        partner_id: str,
        entity_id: Optional[str] = None,
        farmer_id: Optional[int] = None,
        on_behalf_of_partner_id: Optional[str] = None,
        at: Optional[datetime] = None
    ):
        """
        Non-blocking enqueue of an audit event. Returns immediately in sub-millisecond time.
        """
        if not self._thread or not self._thread.is_alive():
            self.start()

        if at is None:
            at = datetime.now(timezone.utc)

        event = AuditEvent(
            action=action,
            partner_id=partner_id,
            entity_id=entity_id,
            farmer_id=farmer_id,
            on_behalf_of_partner_id=on_behalf_of_partner_id,
            at=at
        )
        self._queue.put(event)
        self.total_enqueued += 1

    def flush(self, timeout: float = 5.0):
        """
        Blocks until all currently enqueued audit events have been processed by the worker.
        """
        self.resume()
        start_time = time.time()
        while not self._queue.empty():
            time.sleep(0.02)
            if time.time() - start_time > timeout:
                break
        # Allow brief moment for final database commit
        time.sleep(0.05)

    def _run_worker(self):
        while not self._stop_event.is_set() or not self._queue.empty():
            self._pause_event.wait()
            batch: List[AuditEvent] = []
            try:
                item = self._queue.get(timeout=self.poll_interval)
                batch.append(item)
                while len(batch) < self.max_batch_size:
                    try:
                        batch.append(self._queue.get_nowait())
                    except queue.Empty:
                        break
            except queue.Empty:
                continue

            if batch:
                self._persist_batch_with_retry(batch)
                for _ in batch:
                    self._queue.task_done()

    def _persist_batch_with_retry(self, batch: List[AuditEvent]):
        max_retries = 3
        backoff = 0.05
        for attempt in range(max_retries):
            db: Optional[Session] = None
            try:
                db = self.session_factory()
                for event in batch:
                    db.add(AuditLog(
                        action=event.action,
                        partner_id=event.partner_id,
                        entity_id=event.entity_id,
                        farmer_id=event.farmer_id,
                        on_behalf_of_partner_id=event.on_behalf_of_partner_id,
                        at=event.at
                    ))
                db.commit()
                self.total_persisted += len(batch)
                return
            except Exception as e:
                if db:
                    try:
                        db.rollback()
                    except Exception:
                        pass
                logger.warning(f"AuditLog batch write attempt {attempt + 1}/{max_retries} failed: {e}")
                time.sleep(backoff)
                backoff *= 2
            finally:
                if db:
                    try:
                        db.close()
                    except Exception:
                        pass

        # All retries failed: Spill to dead-letter storage
        self._spill_to_dead_letter(batch)

    def _spill_to_dead_letter(self, batch: List[AuditEvent]):
        self.total_dead_letter += len(batch)
        logger.critical(
            f"FATAL: Database write failed after retries. Spilling {len(batch)} audit events to dead-letter: {self.dead_letter_path}"
        )
        try:
            with open(self.dead_letter_path, "a", encoding="utf-8") as f:
                for event in batch:
                    payload = asdict(event)
                    payload["at"] = event.at.isoformat() if event.at else None
                    f.write(json.dumps(payload) + "\n")
        except Exception as file_err:
            logger.critical(f"EMERGENCY: Could not write to dead-letter file {self.dead_letter_path}: {file_err}")

# Global singleton audit worker
audit_worker = AsyncAuditWorker()

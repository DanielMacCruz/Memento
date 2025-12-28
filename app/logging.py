"""
Logging utilities.

Provides a consistent logging interface that sends messages
to both the console and the web SSE stream, with file persistence
for important events.
"""

from __future__ import annotations
import os
from datetime import datetime
from typing import Callable, Optional
from queue import Queue, Empty

# Store original print before anything overwrites it
_original_print = print

# Maximum queue size to prevent OOM when no SSE client is connected
MAX_QUEUE_SIZE = 1000


class Logger:
    """
    Logger that sends to both console and a queue for SSE.
    Also persists important messages to a log file.
    """
    
    def __init__(self, queue: Optional[Queue] = None):
        self._queue = queue
        self._file = None
        self._init_file_logging()
    
    def _init_file_logging(self) -> None:
        """Initialize file-based logging."""
        try:
            log_dir = 'data'
            os.makedirs(log_dir, exist_ok=True)
            log_path = os.path.join(log_dir, 'sniff.log')
            self._file = open(log_path, 'a', buffering=1)  # Line buffered
        except Exception:
            self._file = None
    
    def _should_persist(self, message: str, level: str) -> bool:
        """Determine if message should be saved to file."""
        # Always persist errors, warnings, and successes
        if level in ('error', 'warning', 'success'):
            return True
        
        # Skip verbose status updates
        skip_patterns = [
            'elapsed', 'Cycle', 'networks total', 'Found', 
            'Scanning...', 'seconds', 'dBm'
        ]
        if any(p in message for p in skip_patterns):
            return False
        
        # Persist operation starts/stops and important events
        persist_keywords = [
            'Starting', 'Complete', 'stopped', 'activated', 'deactivated',
            'Cracking', 'Attacking', 'captured', 'CRACKED', 'Handshake',
            'error', 'Error', 'failed', 'Failed', 'Batch', 'Vigilance',
            'Rolling', 'Auto-Solve', 'Monitor', 'Queue'
        ]
        return any(kw in message for kw in persist_keywords)
    
    def set_queue(self, queue: Queue) -> None:
        """Set the log queue for SSE streaming."""
        self._queue = queue
    
    def log(self, message: str, level: str = 'info') -> None:
        """Log a message."""
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        # Console output
        _original_print(f"[{timestamp}] {message}")
        
        # Queue for SSE - with overflow protection
        if self._queue:
            # Drop old messages if queue is too large (no client consuming)
            while self._queue.qsize() > MAX_QUEUE_SIZE:
                try:
                    self._queue.get_nowait()
                except Empty:
                    break
            
            self._queue.put({
                'timestamp': timestamp,
                'message': message,
                'level': level,
            })
        
        # File logging (filtered to important events only)
        if self._file and self._should_persist(message, level):
            try:
                full_ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                self._file.write(f"[{full_ts}] [{level.upper()}] {message}\n")
            except Exception:
                pass
    
    def info(self, message: str) -> None:
        self.log(message, 'info')
    
    def success(self, message: str) -> None:
        self.log(message, 'success')
    
    def warning(self, message: str) -> None:
        self.log(message, 'warning')
    
    def error(self, message: str) -> None:
        self.log(message, 'error')
    
    def get_callback(self, prefix: str = '') -> Callable[[str], None]:
        """Get a callback function for external tools."""
        def callback(message: str) -> None:
            if prefix:
                self.info(f"{prefix}: {message}")
            else:
                self.info(message)
        return callback
    
    def close(self) -> None:
        """Close the log file."""
        if self._file:
            try:
                self._file.close()
            except Exception:
                pass
            self._file = None


# Global logger instance
_logger: Optional[Logger] = None


def get_logger() -> Logger:
    """Get the global logger instance."""
    global _logger
    if _logger is None:
        _logger = Logger()
    return _logger


def log(message: str, level: str = 'info') -> None:
    """Convenience function for logging."""
    get_logger().log(message, level)


def set_log_queue(queue: Queue) -> None:
    """Set the SSE queue for the global logger."""
    get_logger().set_queue(queue)


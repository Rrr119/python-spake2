"""Failure counting and lockout for PAKE-backed login flows.

SPAKE2 itself only produces a key.  A login server learns whether an attempt
actually succeeded when it verifies a key-confirmation tag (or otherwise
tries to use the key).  This module keeps that part deliberately independent
of the wire protocol: callers record one success or failure per completed
attempt, and the counter enforces a per-principal lockout.
"""

import threading
import time

from .spake2 import LockedOut


class FailureCounter:
    """Track failed authentication attempts and lock principals out.

    ``max_failures`` consecutive failures lock the principal.  The lock lasts
    ``lockout_seconds`` seconds, after which the count starts again at zero.
    A value of zero locks until an administrator calls ``reset()``.  A
    successful attempt clears the count.  ``clock`` is injectable for
    deterministic tests.
    """

    def __init__(self, max_failures=5, lockout_seconds=300,
                 clock=None, **aliases):
        if "max_attempts" in aliases:
            max_failures = aliases.pop("max_attempts")
        if "threshold" in aliases:
            max_failures = aliases.pop("threshold")
        if "lock_seconds" in aliases:
            lockout_seconds = aliases.pop("lock_seconds")
        if "lockout" in aliases:
            lockout_seconds = aliases.pop("lockout")
        if aliases:
            raise TypeError("unexpected keyword argument(s): %s"
                            % ", ".join(sorted(aliases)))
        if max_failures < 1:
            raise ValueError("max_failures must be at least 1")
        if lockout_seconds < 0:
            raise ValueError("lockout_seconds must not be negative")

        self.max_failures = max_failures
        self.lockout_seconds = lockout_seconds
        self.max_attempts = max_failures
        self.lock_seconds = lockout_seconds
        self._clock = clock or time.monotonic
        self._states = {}
        self._lock = threading.RLock()

    def _now(self):
        return self._clock()

    def _state(self, key, now):
        state = self._states.get(key)
        if state is None:
            state = [0, None]
            self._states[key] = state
        elif state[1] is not None and now >= state[1]:
            # The lockout expired; start a fresh window.
            state[0] = 0
            state[1] = None
        return state

    def is_locked(self, key=b""):
        with self._lock:
            state = self._state(key, self._now())
            return state[1] is not None

    @property
    def locked(self):
        return self.is_locked()

    def locked_until(self, key=b""):
        with self._lock:
            state = self._state(key, self._now())
            return state[1]

    lockout_until = locked_until

    def locked_for(self, key=b""):
        with self._lock:
            state = self._state(key, self._now())
            if state[1] is None:
                return 0.0
            return max(0.0, state[1] - self._now())

    def failures(self, key=b""):
        with self._lock:
            return self._state(key, self._now())[0]

    def remaining(self, key=b""):
        with self._lock:
            state = self._state(key, self._now())
            if state[1] is not None:
                return 0
            return max(0, self.max_failures - state[0])

    def check(self, key=b""):
        """Raise :class:`LockedOut` if ``key`` is currently locked."""
        with self._lock:
            state = self._state(key, self._now())
            if state[1] is not None:
                raise LockedOut(
                    "principal is locked out for %.0f more second(s)"
                    % max(0.0, state[1] - self._now()))

    def record_failure(self, key=b""):
        """Record one failed attempt and return the new failure count.

        If the principal is already locked, ``LockedOut`` is raised and the
        count is not changed.  The failure that reaches the threshold locks
        the principal and returns normally so callers can finish their
        cleanup/audit work before rejecting the next attempt.
        """
        with self._lock:
            now = self._now()
            state = self._state(key, now)
            if state[1] is not None:
                raise LockedOut("principal is already locked out")
            state[0] += 1
            if state[0] >= self.max_failures:
                if self.lockout_seconds == 0:
                    # Zero means "locked until an administrator resets it".
                    state[1] = float("inf")
                else:
                    state[1] = now + self.lockout_seconds
            return state[0]

    def record_success(self, key=b""):
        """Clear failures for ``key``.  Locked principals stay locked."""
        with self._lock:
            now = self._now()
            state = self._state(key, now)
            if state[1] is not None:
                raise LockedOut("principal is locked out")
            state[0] = 0
            state[1] = None
            return 0

    def reset(self, key=b""):
        with self._lock:
            self._states.pop(key, None)

    def status(self, key=b""):
        with self._lock:
            now = self._now()
            state = self._state(key, now)
            return {"failures": state[0],
                    "remaining": (0 if state[1] is not None
                                  else max(0, self.max_failures - state[0])),
                    "locked": state[1] is not None,
                    "locked_until": state[1],
                    "locked_for": (0.0 if state[1] is None
                                   else max(0.0, state[1] - now))}

    # Conventional aliases, kept small and explicit.
    record_failed = record_failure
    record_failure_attempt = record_failure
    failure = record_failure
    hit = record_failure
    mark_failure = record_failure
    record_ok = record_success
    success = record_success
    mark_success = record_success
    check_locked = check
    ensure_unlocked = check
    is_locked_out = is_locked
    failure_count = failures
    count = failures
    remaining_attempts = remaining
    attempts_remaining = remaining
    reset_failures = reset


# Names that make the intended use clear to different callers.
LoginAttemptTracker = FailureCounter
AuthenticationAttemptTracker = FailureCounter
AttemptTracker = FailureCounter
AttemptLimiter = FailureCounter
LoginLimiter = FailureCounter
TooManyAttempts = LockedOut
AccountLocked = LockedOut


"""PAKE-login helpers: role-bound SPAKE2 plus attempt limiting.

The implementation lives in :mod:`spake2.spake2` (protocol state and key
confirmation) and :mod:`spake2.attempts` (failure counting/lockout).  This
module is a small, stable import surface for login code.
"""

from .spake2 import (SPAKE2_A, SPAKE2_B, SPAKE2_Symmetric,
                     KeyConfirmationError, LockedOut, InvalidRole,
                     MessageSequenceError, ProtocolVersionError,
                     confirmation_tag)
from .attempts import (FailureCounter, LoginAttemptTracker,
                       AuthenticationAttemptTracker, AttemptTracker,
                       AttemptLimiter, LoginLimiter, TooManyAttempts,
                       AccountLocked)

__all__ = [
    "SPAKE2_A", "SPAKE2_B", "SPAKE2_Symmetric",
    "KeyConfirmationError", "LockedOut", "InvalidRole",
    "MessageSequenceError", "ProtocolVersionError", "confirmation_tag",
    "FailureCounter", "LoginAttemptTracker", "AuthenticationAttemptTracker",
    "AttemptTracker", "AttemptLimiter", "LoginLimiter", "TooManyAttempts",
    "AccountLocked",
]


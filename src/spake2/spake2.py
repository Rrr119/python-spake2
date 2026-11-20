import os, json, hmac
from binascii import hexlify, unhexlify
from hashlib import sha256
from .params import _Params
from .parameters.ed25519 import ParamsEd25519

DefaultParams = ParamsEd25519

class SPAKEError(Exception):
    pass
class MessageSequenceError(SPAKEError):
    """A protocol message arrived out of order, or the state machine was
    advanced in the wrong order."""
class OnlyCallStartOnce(MessageSequenceError):
    """start() may only be called once. Re-using a SPAKE2 instance is likely
    to reveal the password or the derived key."""
class OnlyCallFinishOnce(MessageSequenceError):
    """finish() may only be called once. Re-using a SPAKE2 instance is likely
    to reveal the password or the derived key."""
class OffSides(MessageSequenceError):
    """I received a message from someone on the same side that I'm on: I was
    expecting the opposite side."""
class SerializedTooEarly(SPAKEError):
    pass
class WrongSideSerialized(SPAKEError):
    """You tried to unserialize data stored for the other side."""
class WrongGroupError(SPAKEError):
    pass
class ReflectionThwarted(MessageSequenceError):
    """Someone tried to reflect our message back to us."""
class InvalidRole(SPAKEError):
    """The peer's role identifier does not match the role we expected."""
class ProtocolVersionError(MessageSequenceError):
    """The peer used a different wire protocol version."""
class KeyConfirmationError(SPAKEError):
    """The peer's key-confirmation tag did not match our derived key."""
class LockedOut(SPAKEError):
    """Too many failed authentication attempts; this principal is locked."""

SideA = b"A"
SideB = b"B"
SideSymmetric = b"S"

PROTOCOL_VERSION_LEGACY = 1
PROTOCOL_VERSION_ROLE_BOUND = 2

MESSAGE_SEQUENCE_PAKE = 1
MESSAGE_SEQUENCE_CONFIRM = 2

ROLE_TAG_BYTES = 16

# x = random(Zp)
# X = scalarmult(g, x)
# X* = X + scalarmult(M, int(pw))
#  y = random(Zp)
#  Y = scalarmult(g, y)
#  Y* = Y + scalarmult(N, int(pw))
# KA = scalarmult(Y* + scalarmult(N, -int(pw)), x)
# key = H(H(pw) + H(idA) + H(idB) + X* + Y* + KA)
#  KB = scalarmult(X* + scalarmult(M, -int(pw)), y)
#  key = H(H(pw) + H(idA) + H(idB) + X* + Y* + KB)

# to serialize intermediate state, just remember x and A-vs-B. And M/N.

def _length_prefixed(data):
    if not isinstance(data, bytes):
        raise TypeError("SPAKE2 transcript fields must be bytestrings")
    return len(data).to_bytes(4, "big") + data

def _role_tag(role):
    if not isinstance(role, bytes):
        raise TypeError("SPAKE2 role identifiers must be bytestrings")
    return sha256(role).digest()[:ROLE_TAG_BYTES]

def finalize_SPAKE2(idA, idB, X_msg, Y_msg, K_bytes, pw,
                    roleA=None, roleB=None):
    if roleA is None and roleB is None:
        # Retain the original transcript for callers that do not opt in to
        # role binding. This is what makes old test vectors/serialized
        # sessions keep working.
        transcript = b"".join([sha256(pw).digest(),
                               sha256(idA).digest(), sha256(idB).digest(),
                               X_msg, Y_msg, K_bytes])
        return sha256(transcript).digest()

    if roleA is None:
        roleA = SideA
    if roleB is None:
        roleB = SideB
    if roleA == roleB:
        raise InvalidRole("the two roles must be different")

    # The role-bound transcript is domain-separated and length-prefixed so
    # that a message from a different role assignment cannot be made to share
    # a transcript with this session.
    transcript = b"".join([
        b"SPAKE2 role-bound v2\x00",
        sha256(pw).digest(),
        _length_prefixed(idA), _length_prefixed(idB),
        _length_prefixed(roleA), _length_prefixed(roleB),
        _length_prefixed(X_msg), _length_prefixed(Y_msg),
        _length_prefixed(K_bytes),
        _length_prefixed(bytes([MESSAGE_SEQUENCE_PAKE])),
        _length_prefixed(bytes([MESSAGE_SEQUENCE_PAKE])),
        ])
    key = sha256(transcript).digest()
    return key

def finalize_SPAKE2_symmetric(idSymmetric, msg1, msg2, K_bytes, pw,
                              roleSymmetric=None):
    # since we don't know which side is which, we must sort the messages
    first_msg, second_msg = sorted([msg1, msg2])
    if roleSymmetric is None:
        transcript = b"".join([sha256(pw).digest(),
                               sha256(idSymmetric).digest(),
                               first_msg, second_msg, K_bytes])
        return sha256(transcript).digest()

    transcript = b"".join([
        b"SPAKE2 symmetric role-bound v2\x00",
        sha256(pw).digest(),
        _length_prefixed(idSymmetric),
        _length_prefixed(roleSymmetric),
        _length_prefixed(first_msg), _length_prefixed(second_msg),
        _length_prefixed(K_bytes),
        _length_prefixed(bytes([MESSAGE_SEQUENCE_PAKE])),
        _length_prefixed(bytes([MESSAGE_SEQUENCE_PAKE])),
        ])
    key = sha256(transcript).digest()
    return key

def confirmation_tag(key, sender_role, recipient_role, context=b""):
    """Derive a key-confirmation tag for a specific sender/recipient pair.

    Both sides must use the same ``key``. The sender sends the tag for
    ``(sender_role, recipient_role)`` and verifies the peer's tag for the
    opposite direction. This makes a wrong-password/MitM attempt observable
    before application data is sent.
    """
    if not isinstance(key, bytes):
        raise TypeError("key must be a bytestring")
    pieces = [b"SPAKE2 key confirmation v2\x00",
              _length_prefixed(sender_role),
              _length_prefixed(recipient_role),
              _length_prefixed(context)]
    return hmac.new(key, b"".join(pieces), sha256).digest()

def _validate_protocol_version(version):
    if version not in (None, PROTOCOL_VERSION_LEGACY,
                       PROTOCOL_VERSION_ROLE_BOUND):
        raise ProtocolVersionError("unsupported SPAKE2 protocol version")

def _normalize_explicit_roles(roleA, roleB):
    if roleA is None and roleB is None:
        return None, None
    if roleA is None:
        roleA = SideA
    if roleB is None:
        roleB = SideB
    if not isinstance(roleA, bytes) or not isinstance(roleB, bytes):
        raise InvalidRole("role identifiers must be bytestrings")
    if not roleA or not roleB:
        raise InvalidRole("role identifiers must not be empty")
    if roleA == roleB:
        raise InvalidRole("the two roles must be different")
    return roleA, roleB

def _should_bind_roles(protocol_version, idA, idB, roleA, roleB):
    if protocol_version == PROTOCOL_VERSION_ROLE_BOUND:
        return True
    if protocol_version == PROTOCOL_VERSION_LEGACY:
        return False
    # Login-style use (with identifiers) and explicit role identifiers get
    # the hardened, role-bound protocol by default. A bare SPAKE2_A(pw) with
    # no identifiers retains the wire-compatible legacy transcript.
    return bool(idA or idB or roleA is not None or roleB is not None)

class _SPAKE2_Base:
    "This class manages one side of a SPAKE2 key negotiation."

    side = None # set by the subclass
    protocol_version = PROTOCOL_VERSION_LEGACY
    my_role = None
    peer_role = None

    def __init__(self, password,
                 params=DefaultParams, entropy_f=os.urandom):
        assert isinstance(password, bytes)
        self.pw = password
        self.pw_scalar = params.group.password_to_scalar(password)

        assert isinstance(params, _Params), repr(params)
        self.params = params
        self.entropy_f = entropy_f

        self._started = False
        self._finished = False
        self._confirmed = False
        self.outbound_sequence = 0
        self.inbound_sequence = 0
        self.next_inbound_sequence = MESSAGE_SEQUENCE_PAKE
        self.key = None

    def start(self):
        if self._started:
            raise OnlyCallStartOnce("start() can only be called once")
        if self._finished:
            raise MessageSequenceError(
                "cannot start() a session that has already finished")
        self._started = True

        g = self.params.group
        self.xy_scalar = g.random_scalar(self.entropy_f)
        self.xy_elem = g.Base.scalarmult(self.xy_scalar)
        self.compute_outbound_message()
        self.outbound_sequence = MESSAGE_SEQUENCE_PAKE
        return self._format_outbound_message(self.outbound_message,
                                             self.outbound_sequence)

    def compute_outbound_message(self):
        #message_elem = self.xy_elem + (self.my_blinding() * self.pw_scalar)
        pw_blinding = self.my_blinding().scalarmult(self.pw_scalar)
        message_elem = self.xy_elem.add(pw_blinding)
        self.outbound_message = message_elem.to_bytes()

    def _format_outbound_message(self, message, sequence):
        if not 0 < sequence <= 0xff:
            raise MessageSequenceError("message sequence number out of range")
        if self.protocol_version == PROTOCOL_VERSION_LEGACY:
            # Original wire format: side byte plus the group element.
            return self.side + message
        if self.protocol_version != PROTOCOL_VERSION_ROLE_BOUND:
            raise ProtocolVersionError("unsupported protocol version")
        return b"".join([self.side,
                         bytes([PROTOCOL_VERSION_ROLE_BOUND, sequence]),
                         _role_tag(self.my_role),
                         message])

    def _parse_inbound_message(self, inbound_side_and_message):
        if not isinstance(inbound_side_and_message, bytes):
            raise TypeError("inbound SPAKE2 messages must be bytestrings")
        if not inbound_side_and_message:
            raise MessageSequenceError("empty inbound SPAKE2 message")

        other_side = inbound_side_and_message[0:1]
        body = inbound_side_and_message[1:]
        element_size = self.params.group.element_size_bytes

        if self.protocol_version == PROTOCOL_VERSION_LEGACY:
            if len(body) != element_size:
                if (len(body) >= 2 + ROLE_TAG_BYTES + element_size
                        and body[0:1] == bytes(
                            [PROTOCOL_VERSION_ROLE_BOUND])):
                    raise ProtocolVersionError(
                        "received a role-bound v2 message in a legacy session")
                raise MessageSequenceError(
                    "legacy SPAKE2 message has the wrong length")
            return other_side, MESSAGE_SEQUENCE_PAKE, body

        header_size = 2 + ROLE_TAG_BYTES
        if len(body) != header_size + element_size:
            raise MessageSequenceError(
                "role-bound SPAKE2 message has the wrong length")
        version = body[0]
        if version != PROTOCOL_VERSION_ROLE_BOUND:
            raise ProtocolVersionError("wrong SPAKE2 protocol version")
        sequence = body[1]
        role_tag = body[2:header_size]
        expected_tag = _role_tag(self.peer_role)
        if not hmac.compare_digest(role_tag, expected_tag):
            raise InvalidRole(
                "peer role identifier does not match the expected role")
        return other_side, sequence, body[header_size:]

    def _validate_inbound_sequence(self, sequence):
        if sequence != self.next_inbound_sequence:
            raise MessageSequenceError(
                "expected message sequence %d, got %d"
                % (self.next_inbound_sequence, sequence))
        self.inbound_sequence = sequence
        self.next_inbound_sequence = sequence + 1

    def finish(self, inbound_side_and_message):
        if not self._started:
            raise MessageSequenceError("finish() called before start()")
        if self._finished:
            raise OnlyCallFinishOnce("finish() can only be called once")
        self._finished = True

        self.inbound_message = self._extract_message(inbound_side_and_message)

        g = self.params.group
        inbound_elem = g.bytes_to_element(self.inbound_message)
        if inbound_elem.to_bytes() == self.outbound_message:
            raise ReflectionThwarted
        #K_elem = (inbound_elem + (self.my_unblinding() * -self.pw_scalar)
        #          ) * self.xy_scalar
        pw_unblinding = self.my_unblinding().scalarmult(-self.pw_scalar)
        K_elem = inbound_elem.add(pw_unblinding).scalarmult(self.xy_scalar)
        K_bytes = K_elem.to_bytes()
        key = self._finalize(K_bytes)
        self.key = key
        return key

    def make_confirmation(self, context=b""):
        """Return the key-confirmation tag this side should send.

        Call this only after ``finish()``. The tag is derived from the
        transcript key and is bound to both role identifiers. It never
        reveals the key itself.
        """
        if not self._finished or self.key is None:
            raise MessageSequenceError(
                "make_confirmation() requires a completed finish()")
        sender, recipient = self._confirmation_roles()
        return confirmation_tag(self.key, sender, recipient, context)

    def verify_confirmation(self, tag, context=b"",
                            limiter=None, limiter_key=b""):
        """Verify the peer's key-confirmation tag.

        If ``limiter`` is supplied, it is consulted before verification and
        is updated with success/failure after verification. This lets a
        caller enforce a failure count and lockout per account/principal
        without leaking whether the password or the role binding failed.
        """
        if not self._finished or self.key is None:
            raise MessageSequenceError(
                "verify_confirmation() requires a completed finish()")
        if not isinstance(tag, bytes):
            raise TypeError("confirmation tag must be a bytestring")
        if limiter is not None:
            limiter.check(limiter_key)
        sender, recipient = self._confirmation_roles()
        expected = confirmation_tag(self.key, recipient, sender, context)
        if not hmac.compare_digest(tag, expected):
            if limiter is not None:
                limiter.record_failure(limiter_key)
            raise KeyConfirmationError("key confirmation failed")
        if limiter is not None:
            limiter.record_success(limiter_key)
        self._confirmed = True
        return True

    # Short aliases for applications that prefer a conventional name.
    def confirmation(self, context=b""):
        return self.make_confirmation(context)

    def confirm(self, tag, context=b"", limiter=None, limiter_key=b""):
        return self.verify_confirmation(tag, context=context,
                                        limiter=limiter,
                                        limiter_key=limiter_key)

    def _confirmation_roles(self):
        return self.my_role, self.peer_role

    @property
    def confirmed(self):
        return self._confirmed

    def hash_params(self):
        # We can't really reconstruct the group from static data, but we'll
        # record enough of the params to confirm that we're using the same
        # ones upon restore. Otherwise the failure mode is silent key
        # disagreement. Any changes to the group or the M/N seeds should
        # cause this to change.
        g = self.params.group
        pieces = [g.arbitrary_element(b"").to_bytes(),
                  g.scalar_to_bytes(g.password_to_scalar(b"")),
                  self.params.M.to_bytes(),
                  self.params.N.to_bytes(),
                  ]
        return sha256(b"".join(pieces)).hexdigest()

    def serialize(self):
        if not self._started:
            raise SerializedTooEarly("call .start() before .serialize()")
        return json.dumps(self._serialize_to_dict()).encode("ascii")

    @classmethod
    def from_serialized(klass, data, params=DefaultParams):
        d = json.loads(data.decode("ascii"))
        return klass._deserialize_from_dict(d, params)

class _SPAKE2_Asymmetric(_SPAKE2_Base):
    def __init__(self, password, idA=b"", idB=b"",
                 params=DefaultParams, entropy_f=os.urandom,
                 roleA=None, roleB=None, protocol_version=None):
        _SPAKE2_Base.__init__(self, password,
                              params=params, entropy_f=entropy_f)

        assert isinstance(idA, bytes), repr(idA)
        assert isinstance(idB, bytes), repr(idB)
        self.idA = idA
        self.idB = idB
        _validate_protocol_version(protocol_version)
        self.roleA, self.roleB = _normalize_explicit_roles(roleA, roleB)
        if _should_bind_roles(protocol_version, idA, idB, roleA, roleB):
            if self.roleA is None:
                self.roleA, self.roleB = _normalize_explicit_roles(
                    SideA, SideB)
            self.protocol_version = PROTOCOL_VERSION_ROLE_BOUND
        else:
            self.protocol_version = PROTOCOL_VERSION_LEGACY
            if self.roleA is None:
                self.roleA, self.roleB = SideA, SideB

        if self.side == SideA:
            self.my_role, self.peer_role = self.roleA, self.roleB
        else:
            self.my_role, self.peer_role = self.roleB, self.roleA

    def _extract_message(self, inbound_side_and_message):
        other_side = inbound_side_and_message[0:1]
        if other_side not in (SideA, SideB):
            raise OffSides("I don't know what side they're on")
        if self.side == other_side:
            if self.side == SideA:
                raise OffSides("I'm A, but I got a message from A (not B).")
            else:
                raise OffSides("I'm B, but I got a message from B (not A).")

        other_side, sequence, inbound_message = self._parse_inbound_message(
            inbound_side_and_message)
        self._validate_inbound_sequence(sequence)
        return inbound_message

    def _finalize(self, K_bytes):
        if self.protocol_version == PROTOCOL_VERSION_ROLE_BOUND:
            return finalize_SPAKE2(self.idA, self.idB,
                                   self.X_msg(), self.Y_msg(),
                                   K_bytes, self.pw,
                                   roleA=self.roleA, roleB=self.roleB)
        return finalize_SPAKE2(self.idA, self.idB,
                               self.X_msg(), self.Y_msg(),
                               K_bytes, self.pw)

    def _serialize_to_dict(self):
        g = self.params.group
        d = {"hashed_params": self.hash_params(),
             "side": self.side.decode("ascii"),
             "idA": hexlify(self.idA).decode("ascii"),
             "idB": hexlify(self.idB).decode("ascii"),
             "password": hexlify(self.pw).decode("ascii"),
             "xy_scalar": hexlify(g.scalar_to_bytes(self.xy_scalar)).decode("ascii"),
             }
        if self.protocol_version == PROTOCOL_VERSION_ROLE_BOUND:
            d["roleA"] = hexlify(self.roleA).decode("ascii")
            d["roleB"] = hexlify(self.roleB).decode("ascii")
            d["protocol_version"] = self.protocol_version
        return d

    @classmethod
    def _deserialize_from_dict(klass, d, params):
        def _should_be_unused(count): raise NotImplementedError
        if "protocol_version" in d:
            protocol_version = d["protocol_version"]
            roleA = unhexlify(d["roleA"].encode("ascii"))
            roleB = unhexlify(d["roleB"].encode("ascii"))
        else:
            # Old serialized sessions predate role binding.
            protocol_version = PROTOCOL_VERSION_LEGACY
            roleA = roleB = None
        self = klass(password=unhexlify(d["password"].encode("ascii")),
                     idA=unhexlify(d["idA"].encode("ascii")),
                     idB=unhexlify(d["idB"].encode("ascii")),
                     params=params, entropy_f=_should_be_unused,
                     roleA=roleA, roleB=roleB,
                     protocol_version=protocol_version)
        if d["side"].encode("ascii") != self.side:
            raise WrongSideSerialized
        if d["hashed_params"] != self.hash_params():
            err = ("SPAKE2.from_serialized() must be called with the same"
                   "params= that were used to create the serialized data."
                   "These are different somehow.")
            raise WrongGroupError(err)
        g = self.params.group
        self._started = True
        xy_scalar_bytes = unhexlify(d["xy_scalar"].encode("ascii"))
        self.xy_scalar = g.bytes_to_scalar(xy_scalar_bytes)
        self.xy_elem = g.Base.scalarmult(self.xy_scalar)
        self.compute_outbound_message()
        self.outbound_sequence = MESSAGE_SEQUENCE_PAKE
        return self


# applications should use SPAKE2_A and SPAKE2_B, not raw _SPAKE2_Base()

class SPAKE2_A(_SPAKE2_Asymmetric):
    side = SideA
    def my_blinding(self): return self.params.M
    def my_unblinding(self): return self.params.N
    def X_msg(self): return self.outbound_message
    def Y_msg(self): return self.inbound_message

class SPAKE2_B(_SPAKE2_Asymmetric):
    side = SideB
    def my_blinding(self): return self.params.N
    def my_unblinding(self): return self.params.M
    def X_msg(self): return self.inbound_message
    def Y_msg(self): return self.outbound_message

class SPAKE2_Symmetric(_SPAKE2_Base):
    side = SideSymmetric
    def __init__(self, password, idSymmetric=b"",
                 params=DefaultParams, entropy_f=os.urandom,
                 roleSymmetric=None, protocol_version=None):
        _SPAKE2_Base.__init__(self, password,
                              params=params, entropy_f=entropy_f)
        assert isinstance(idSymmetric, bytes), repr(idSymmetric)
        self.idSymmetric = idSymmetric
        _validate_protocol_version(protocol_version)
        bind_roles = (protocol_version == PROTOCOL_VERSION_ROLE_BOUND
                      or (protocol_version is None
                          and (idSymmetric or roleSymmetric is not None)))
        if bind_roles:
            if roleSymmetric is None:
                roleSymmetric = SideSymmetric
            if not isinstance(roleSymmetric, bytes):
                raise InvalidRole("role identifiers must be bytestrings")
            if not roleSymmetric:
                raise InvalidRole("role identifiers must not be empty")
            self.roleSymmetric = roleSymmetric
            self.protocol_version = PROTOCOL_VERSION_ROLE_BOUND
        else:
            self.roleSymmetric = SideSymmetric
            self.protocol_version = PROTOCOL_VERSION_LEGACY
        self.my_role = self.peer_role = self.roleSymmetric

    def my_blinding(self): return self.params.S
    def my_unblinding(self): return self.params.S

    def _confirmation_roles(self):
        # Both sides know the sorted order of the two outbound messages, so
        # it provides a direction tag even in the role-free symmetric mode.
        # This prevents reflecting a confirmation tag back to its sender.
        if self.outbound_message <= self.inbound_message:
            return b"first", b"second"
        return b"second", b"first"

    def _extract_message(self, inbound_side_and_message):
        other_side = inbound_side_and_message[0:1]
        if other_side == SideA:
            raise OffSides("I'm Symmetric, but I got a message from A")
        if other_side == SideB:
            raise OffSides("I'm Symmetric, but I got a message from B")
        if other_side != SideSymmetric:
            raise OffSides("I don't know what side they're on")

        other_side, sequence, inbound_message = self._parse_inbound_message(
            inbound_side_and_message)
        self._validate_inbound_sequence(sequence)
        return inbound_message

    def _finalize(self, K_bytes):
        if self.protocol_version == PROTOCOL_VERSION_ROLE_BOUND:
            return finalize_SPAKE2_symmetric(
                self.idSymmetric,
                self.inbound_message,
                self.outbound_message,
                K_bytes, self.pw,
                roleSymmetric=self.roleSymmetric)
        return finalize_SPAKE2_symmetric(self.idSymmetric,
                                         self.inbound_message,
                                         self.outbound_message,
                                         K_bytes, self.pw)

    def hash_params(self):
        g = self.params.group
        pieces = [g.arbitrary_element(b"").to_bytes(),
                  g.scalar_to_bytes(g.password_to_scalar(b"")),
                  self.params.S.to_bytes(),
                  ]
        return sha256(b"".join(pieces)).hexdigest()

    def _serialize_to_dict(self):
        g = self.params.group
        d = {"hashed_params": self.hash_params(),
             "side": self.side.decode("ascii"),
             "idS": hexlify(self.idSymmetric).decode("ascii"),
             "password": hexlify(self.pw).decode("ascii"),
             "xy_scalar": hexlify(g.scalar_to_bytes(self.xy_scalar)).decode("ascii"),
             }
        if self.protocol_version == PROTOCOL_VERSION_ROLE_BOUND:
            d["roleS"] = hexlify(self.roleSymmetric).decode("ascii")
            d["protocol_version"] = self.protocol_version
        return d

    @classmethod
    def _deserialize_from_dict(klass, d, params):
        if d["side"].encode("ascii") != SideSymmetric:
            raise WrongSideSerialized
        def _should_be_unused(count): raise NotImplementedError
        if "protocol_version" in d:
            protocol_version = d["protocol_version"]
            roleSymmetric = unhexlify(d["roleS"].encode("ascii"))
        else:
            protocol_version = PROTOCOL_VERSION_LEGACY
            roleSymmetric = None
        self = klass(password=unhexlify(d["password"].encode("ascii")),
                     idSymmetric=unhexlify(d["idS"].encode("ascii")),
                     params=params, entropy_f=_should_be_unused,
                     roleSymmetric=roleSymmetric,
                     protocol_version=protocol_version)
        if d["hashed_params"] != self.hash_params():
            err = ("SPAKE2.from_serialized() must be called with the same"
                   "params= that were used to create the serialized data."
                   "These are different somehow.")
            raise WrongGroupError(err)
        g = self.params.group
        self._started = True
        xy_scalar_bytes = unhexlify(d["xy_scalar"].encode("ascii"))
        self.xy_scalar = g.bytes_to_scalar(xy_scalar_bytes)
        self.xy_elem = g.Base.scalarmult(self.xy_scalar)
        self.compute_outbound_message()
        self.outbound_sequence = MESSAGE_SEQUENCE_PAKE
        return self

# add ECC version for smaller messages/storage
# consider timing attacks
# try for compatibility with Boneh's JS version

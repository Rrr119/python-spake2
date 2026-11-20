import unittest

from spake2 import (SPAKE2_A, SPAKE2_B, SPAKE2_Symmetric,
                    FailureCounter, MessageSequenceError, OffSides,
                    InvalidRole, ProtocolVersionError, KeyConfirmationError,
                    LockedOut)
from spake2.spake2 import (PROTOCOL_VERSION_LEGACY,
                           PROTOCOL_VERSION_ROLE_BOUND,
                           MESSAGE_SEQUENCE_PAKE,
                           ROLE_TAG_BYTES)


PW = b"correct horse battery staple"
IDS = dict(idA=b"alice", idB=b"example.com")
ROLES = dict(roleA=b"client", roleB=b"server")


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class RoleBinding(unittest.TestCase):
    def test_both_roles_are_bound(self):
        a = SPAKE2_A(PW, **IDS, **ROLES)
        b = SPAKE2_B(PW, **IDS, **ROLES)
        ma, mb = a.start(), b.start()
        self.assertEqual(a.protocol_version, PROTOCOL_VERSION_ROLE_BOUND)
        self.assertEqual(a.my_role, ROLES["roleA"])
        self.assertEqual(a.peer_role, ROLES["roleB"])
        self.assertEqual(b.my_role, ROLES["roleB"])
        self.assertEqual(b.peer_role, ROLES["roleA"])
        self.assertEqual(a.finish(mb), b.finish(ma))

    def test_peer_role_mismatch_is_rejected(self):
        a = SPAKE2_A(PW, **IDS, **ROLES)
        b = SPAKE2_B(PW, idA=IDS["idA"], idB=IDS["idB"],
                     roleA=b"impostor", roleB=b"server")
        ma, mb = a.start(), b.start()
        # B expects A to call itself "impostor", but A sent "client".
        self.assertRaises(InvalidRole, b.finish, ma)

    def test_role_tag_is_in_the_wire_message(self):
        a = SPAKE2_A(PW, **IDS, **ROLES)
        msg = a.start()
        self.assertEqual(msg[0:1], b"A")
        self.assertEqual(msg[1], PROTOCOL_VERSION_ROLE_BOUND)
        self.assertEqual(msg[2], MESSAGE_SEQUENCE_PAKE)
        self.assertEqual(len(msg[3:3 + ROLE_TAG_BYTES]), ROLE_TAG_BYTES)

        bad = bytearray(msg)
        bad[3] ^= 0xff
        b = SPAKE2_B(PW, **IDS, **ROLES)
        b.start()
        self.assertRaises(InvalidRole, b.finish, bytes(bad))

    def test_role_bound_keys_are_distinct_from_legacy(self):
        a1 = SPAKE2_A(PW, **IDS, **ROLES)
        b1 = SPAKE2_B(PW, **IDS, **ROLES)
        m1a, m1b = a1.start(), b1.start()
        k1 = a1.finish(m1b)
        self.assertEqual(k1, b1.finish(m1a))

        a2 = SPAKE2_A(PW, **IDS, **ROLES, protocol_version=1)
        b2 = SPAKE2_B(PW, **IDS, **ROLES, protocol_version=1)
        m2a, m2b = a2.start(), b2.start()
        k2 = a2.finish(m2b)
        self.assertEqual(k2, b2.finish(m2a))
        self.assertNotEqual(k1, k2)

    def test_same_role_identifier_is_rejected(self):
        self.assertRaises(InvalidRole, SPAKE2_A, PW,
                          roleA=b"same", roleB=b"same")


class MessageSequence(unittest.TestCase):
    def test_finish_before_start(self):
        a = SPAKE2_A(PW, **IDS, **ROLES)
        self.assertRaises(MessageSequenceError, a.finish, b"A" + b"\x00" * 33)

    def test_sequence_number_is_validated(self):
        a = SPAKE2_A(PW, **IDS, **ROLES)
        b = SPAKE2_B(PW, **IDS, **ROLES)
        a.start()
        mb = b.start()
        tampered = mb[:2] + bytes([MESSAGE_SEQUENCE_PAKE + 1]) + mb[3:]
        self.assertRaises(MessageSequenceError, a.finish, tampered)

    def test_replayed_message_is_rejected(self):
        a = SPAKE2_A(PW, **IDS, **ROLES)
        b = SPAKE2_B(PW, **IDS, **ROLES)
        ma, mb = a.start(), b.start()
        a.finish(mb)
        self.assertRaises(MessageSequenceError, a.finish, mb)

    def test_v2_message_is_not_accepted_by_legacy_session(self):
        legacy = SPAKE2_A(PW)
        legacy.start()
        modern = SPAKE2_B(PW, **IDS, **ROLES)
        modern_message = modern.start()
        self.assertRaises(ProtocolVersionError, legacy.finish,
                          modern_message)

    def test_wrong_side_is_rejected_before_payload_processing(self):
        a = SPAKE2_A(PW, **IDS, **ROLES)
        other_a = SPAKE2_A(PW, **IDS, **ROLES)
        a.start()
        self.assertRaises(OffSides, a.finish, other_a.start())

    def test_symmetric_sequence_is_validated(self):
        s1 = SPAKE2_Symmetric(PW, idSymmetric=b"pair")
        s2 = SPAKE2_Symmetric(PW, idSymmetric=b"pair")
        s1.start()
        m2 = s2.start()
        tampered = m2[:2] + bytes([MESSAGE_SEQUENCE_PAKE + 1]) + m2[3:]
        self.assertRaises(MessageSequenceError, s1.finish, tampered)

    def test_symmetric_confirmation_is_directional(self):
        s1 = SPAKE2_Symmetric(PW, idSymmetric=b"pair")
        s2 = SPAKE2_Symmetric(PW, idSymmetric=b"pair")
        m1, m2 = s1.start(), s2.start()
        s1.finish(m2)
        s2.finish(m1)
        self.assertTrue(s1.verify_confirmation(s2.make_confirmation()))
        self.assertTrue(s2.verify_confirmation(s1.make_confirmation()))
        # Reflect S1's own tag back to S1.
        self.assertRaises(KeyConfirmationError, s1.verify_confirmation,
                          s1.make_confirmation())


class FailureCounterTests(unittest.TestCase):
    def test_locks_after_threshold(self):
        counter = FailureCounter(max_failures=3, lockout_seconds=60)
        self.assertEqual(counter.remaining(b"alice"), 3)
        self.assertEqual(counter.record_failure(b"alice"), 1)
        self.assertEqual(counter.record_failure(b"alice"), 2)
        self.assertFalse(counter.is_locked(b"alice"))
        self.assertEqual(counter.record_failure(b"alice"), 3)
        self.assertTrue(counter.is_locked(b"alice"))
        self.assertEqual(counter.remaining(b"alice"), 0)
        self.assertRaises(LockedOut, counter.check, b"alice")
        self.assertRaises(LockedOut, counter.record_success, b"alice")
        self.assertEqual(counter.failures(b"alice"), 3)

    def test_lockout_expires(self):
        clock = FakeClock()
        counter = FailureCounter(max_failures=2, lockout_seconds=30,
                                 clock=clock)
        counter.record_failure(b"alice")
        counter.record_failure(b"alice")
        self.assertTrue(counter.is_locked(b"alice"))
        self.assertAlmostEqual(counter.locked_for(b"alice"), 30.0)
        clock.advance(29)
        self.assertTrue(counter.is_locked(b"alice"))
        clock.advance(2)
        self.assertFalse(counter.is_locked(b"alice"))
        self.assertEqual(counter.failures(b"alice"), 0)
        counter.check(b"alice")
        self.assertEqual(counter.remaining(b"alice"), 2)

    def test_success_resets_and_keys_are_isolated(self):
        counter = FailureCounter(max_failures=3)
        counter.record_failure(b"alice")
        counter.record_failure(b"alice")
        self.assertEqual(counter.failures(b"alice"), 2)
        counter.record_success(b"alice")
        self.assertEqual(counter.failures(b"alice"), 0)
        self.assertEqual(counter.failures(b"bob"), 0)
        counter.record_failure(b"bob")
        self.assertEqual(counter.failures(b"bob"), 1)
        self.assertEqual(counter.failures(b"alice"), 0)

    def test_already_locked_attempt_is_not_counted(self):
        counter = FailureCounter(max_failures=1, lockout_seconds=60)
        counter.record_failure(b"alice")
        self.assertRaises(LockedOut, counter.record_failure, b"alice")
        self.assertEqual(counter.failures(b"alice"), 1)

    def test_success_updates_limiter_for_confirmation(self):
        a = SPAKE2_A(PW, **IDS, **ROLES)
        b = SPAKE2_B(PW, **IDS, **ROLES)
        ma, mb = a.start(), b.start()
        a.finish(mb)
        b.finish(ma)
        counter = FailureCounter(max_failures=3)
        self.assertTrue(a.verify_confirmation(
            b.make_confirmation(), limiter=counter, limiter_key=b"alice"))
        self.assertEqual(counter.failures(b"alice"), 0)


class MitM(unittest.TestCase):
    def _intercept(self, attacker_password):
        """Run A <-> attacker <-> B and return all four derived keys."""
        a = SPAKE2_A(PW, **IDS, **ROLES)
        b = SPAKE2_B(PW, **IDS, **ROLES)
        # The attacker pretends to be B to A and A to B.
        attacker_as_b = SPAKE2_B(attacker_password, **IDS, **ROLES)
        attacker_as_a = SPAKE2_A(attacker_password, **IDS, **ROLES)

        ma = a.start()
        mb = b.start()
        m_to_a = attacker_as_b.start()
        m_to_b = attacker_as_a.start()

        k_a = a.finish(m_to_a)
        k_attacker_as_b = attacker_as_b.finish(ma)
        k_b = b.finish(m_to_b)
        k_attacker_as_a = attacker_as_a.finish(mb)
        return a, b, k_a, k_b, k_attacker_as_b, k_attacker_as_a

    def test_wrong_password_mitm_cannot_join_either_side(self):
        a, b, k_a, k_b, k_ab, k_ba = self._intercept(b"wrong password")
        self.assertNotEqual(k_a, k_ab)
        self.assertNotEqual(k_b, k_ba)
        self.assertNotEqual(k_a, k_b)
        self.assertNotEqual(k_ab, k_ba)

    def test_key_confirmation_exposes_mitm_and_counts_failure(self):
        a, b, k_a, k_b, k_ab, k_ba = self._intercept(b"wrong password")
        counter = FailureCounter(max_failures=2)
        # A thinks it is talking to B, but the tag was made with the attacker's
        # distinct key.
        self.assertRaises(KeyConfirmationError, a.verify_confirmation,
                          b.make_confirmation(), limiter=counter,
                          limiter_key=b"alice")
        self.assertEqual(counter.failures(b"alice"), 1)
        self.assertRaises(KeyConfirmationError, a.verify_confirmation,
                          b.make_confirmation(), limiter=counter,
                          limiter_key=b"alice")
        self.assertTrue(counter.is_locked(b"alice"))

    def test_wrong_password_mitm_is_locked_out_after_budget(self):
        counter = FailureCounter(max_failures=3, lockout_seconds=120)
        for expected_count in (1, 2, 3):
            counter.check(b"alice")
            _ = self._intercept(b"guess-%d" % expected_count)
            self.assertEqual(counter.record_failure(b"alice"),
                             expected_count)
        self.assertTrue(counter.is_locked(b"alice"))
        self.assertRaises(LockedOut, counter.check, b"alice")

    def test_role_tag_tampering_is_rejected(self):
        a = SPAKE2_A(PW, **IDS, **ROLES)
        b = SPAKE2_B(PW, **IDS, **ROLES)
        a.start()
        mb = bytearray(b.start())
        mb[3] ^= 1
        self.assertRaises(InvalidRole, a.finish, bytes(mb))

    def test_reflected_role_bound_message_is_rejected(self):
        a = SPAKE2_A(PW, **IDS, **ROLES)
        ma = a.start()
        reflected = b"B" + ma[1:]
        # Changing only the side byte leaves A's role tag, which is not the
        # peer role this side expects.
        self.assertRaises(InvalidRole, a.finish, reflected)


if __name__ == "__main__":
    unittest.main()

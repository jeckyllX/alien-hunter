import time
import unittest
from dataclasses import dataclass
from typing import List, Optional

from alien_hunter.ai.models import NetworkPosture, NetworkPostureAssessment
from alien_hunter.ai.posture_gate import (
    PostureDecision,
    PostureGate,
    _port_numbers,
    compute_fingerprint,
    normalize_threat,
)


@dataclass
class MockDevice:
    mac: str = ""
    trusted: bool = False
    is_alien: bool = False
    open_ports: Optional[List[str]] = None


@dataclass
class MockAudit:
    devices: Optional[List[MockDevice]] = None
    threats: Optional[List[str]] = None


class TestPostureGateUtils(unittest.TestCase):
    def test_normalize_threat(self):
        t1 = "Observed 53 MACs from AA:BB:CC:DD:EE:FF"
        t2 = "Observed 12 MACs from 11:22:33:44:55:66"
        self.assertEqual(normalize_threat(t1), "observed # macs from <mac>")
        self.assertEqual(normalize_threat(t2), "observed # macs from <mac>")

        t3 = "ARP Spoofing detected (Samples: AA:BB:CC:DD:EE:FF, 11:22:33:44:55:66)"
        self.assertEqual(normalize_threat(t3), "arp spoofing detected")

        t4 = "DNS drift on 192.168.1.1: newly opened port 53"
        self.assertEqual(normalize_threat(t4), "dns drift on 192.168.1.1: newly opened port #")

    def test_port_numbers(self):
        self.assertEqual(_port_numbers([]), ())
        self.assertEqual(_port_numbers(["80/TCP", "443/TCP", "invalid"]), (80, 443))
        self.assertEqual(_port_numbers(["8080", "53/UDP (DNS)"]), (53, 8080))
        self.assertEqual(_port_numbers(None), ())

    def test_compute_fingerprint(self):
        d1 = MockDevice(mac="AA:BB:CC:DD:EE:FF", trusted=True, open_ports=["80/TCP"])
        audit1 = MockAudit(devices=[d1], threats=["Threat One"])
        audit2 = MockAudit(devices=[d1], threats=["Threat One"])
        
        f1 = compute_fingerprint(audit1, NetworkPosture.SECURE)
        f2 = compute_fingerprint(audit2, NetworkPosture.SECURE)
        self.assertEqual(f1, f2)

        f3 = compute_fingerprint(audit1, NetworkPosture.WARNING)
        self.assertNotEqual(f1, f3)

        audit3 = MockAudit(devices=[d1], threats=["Threat Two"])
        f4 = compute_fingerprint(audit3, NetworkPosture.SECURE)
        self.assertNotEqual(f1, f4)


class TestPostureGate(unittest.TestCase):
    def setUp(self):
        self.current_time = 1000.0
        self.gate = PostureGate(min_interval=60.0, max_age=3600.0, clock=lambda: self.current_time)
        self.fp_base = "hash_base"
        self.fp_new = "hash_new"
        self.assessment = NetworkPostureAssessment(
            posture=NetworkPosture.SECURE,
            summary="All good",
            threats_found=[],
            hardening_advice=[],
            attack_paths=[]
        )

    def test_initial_decision(self):
        decision = self.gate.decide(self.fp_base, NetworkPosture.SECURE)
        self.assertTrue(decision.refresh)
        self.assertEqual(decision.reason, "initial")

    def test_force_decision(self):
        self.gate.store(self.fp_base, NetworkPosture.SECURE, self.assessment)
        decision = self.gate.decide(self.fp_base, NetworkPosture.SECURE, force=True)
        self.assertTrue(decision.refresh)
        self.assertEqual(decision.reason, "forced")

    def test_unchanged_decision(self):
        self.gate.store(self.fp_base, NetworkPosture.SECURE, self.assessment)
        self.current_time += 10.0
        decision = self.gate.decide(self.fp_base, NetworkPosture.SECURE)
        self.assertFalse(decision.refresh)
        self.assertEqual(decision.reason, "unchanged")

    def test_tier_escalated(self):
        self.gate.store(self.fp_base, NetworkPosture.SECURE, self.assessment)
        self.current_time += 10.0
        decision = self.gate.decide(self.fp_base, NetworkPosture.WARNING)
        self.assertTrue(decision.refresh)
        self.assertEqual(decision.reason, "tier_escalated")

    def test_tier_deescalated_cooldown(self):
        self.gate.store(self.fp_base, NetworkPosture.WARNING, self.assessment)
        self.current_time += 10.0
        decision = self.gate.decide(self.fp_base, NetworkPosture.SECURE)
        self.assertFalse(decision.refresh)
        self.assertEqual(decision.reason, "tier_deescalated_cooldown")
        
        self.current_time += 60.0
        decision2 = self.gate.decide(self.fp_base, NetworkPosture.SECURE)
        self.assertTrue(decision2.refresh)
        self.assertEqual(decision2.reason, "tier_deescalated")

    def test_inputs_changed_cooldown(self):
        self.gate.store(self.fp_base, NetworkPosture.SECURE, self.assessment)
        self.current_time += 10.0
        decision = self.gate.decide(self.fp_new, NetworkPosture.SECURE)
        self.assertFalse(decision.refresh)
        self.assertEqual(decision.reason, "inputs_changed_cooldown")
        
        self.current_time += 60.0
        decision2 = self.gate.decide(self.fp_new, NetworkPosture.SECURE)
        self.assertTrue(decision2.refresh)
        self.assertEqual(decision2.reason, "inputs_changed")

    def test_stale(self):
        self.gate.store(self.fp_base, NetworkPosture.SECURE, self.assessment)
        self.current_time += 3601.0
        decision = self.gate.decide(self.fp_base, NetworkPosture.SECURE)
        self.assertTrue(decision.refresh)
        self.assertEqual(decision.reason, "stale")

    def test_failure_cooldown(self):
        self.gate.store(self.fp_base, NetworkPosture.SECURE, self.assessment)
        self.current_time += 100.0
        self.gate.record_failure()
        
        self.current_time += 10.0
        decision = self.gate.decide(self.fp_base, NetworkPosture.SECURE)
        self.assertFalse(decision.refresh)
        self.assertEqual(decision.reason, "retry_cooldown")
        
        decision_forced = self.gate.decide(self.fp_base, NetworkPosture.SECURE, force=True)
        self.assertTrue(decision_forced.refresh)
        
        self.current_time += 60.0
        decision2 = self.gate.decide(self.fp_new, NetworkPosture.SECURE)
        self.assertTrue(decision2.refresh)
        self.assertEqual(decision2.reason, "inputs_changed")

if __name__ == "__main__":
    unittest.main()

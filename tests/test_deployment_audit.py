"""Boundary checks for the production deployment evidence verifier."""
import unittest
from tools.deployment_report import interval, positive, render


class MeasurementEvidenceTests(unittest.TestCase):
    def test_interval_rejects_nonfinite_and_inconsistent_summary(self):
        clock = {'clock':'monotonic_ns','started_ns':1_000_000_000,'finished_ns':2_000_000_000}
        interval(clock, 1.)
        for value in (float('inf'),float('nan'),True,-1,0,2):
            with self.subTest(value=value), self.assertRaises(AssertionError):
                interval(clock,value)

    def test_interval_requires_monotonic_integer_endpoints(self):
        for clock in (
            {'clock':'wall','started_ns':1,'finished_ns':2},
            {'clock':'monotonic_ns','started_ns':2,'finished_ns':1},
            {'clock':'monotonic_ns','started_ns':1,'finished_ns':1},
            {'clock':'monotonic_ns','started_ns':True,'finished_ns':2},
            {'clock':'monotonic_ns','started_ns':1.,'finished_ns':2.},
        ):
            with self.subTest(clock=clock), self.assertRaises(AssertionError):
                interval(clock,1e-9)

    def test_positive_measurement_rejects_boolean_and_nonfinite(self):
        for value in (True,False,float('nan'),float('inf'),-1,0,'100'):
            with self.subTest(value=value), self.assertRaises(AssertionError):
                positive(value)

    def test_incomplete_report_does_not_invent_zero_duration(self):
        page = render({'passed':False, 'cases':[], 'pending_vm_restart_control_seconds':1.25})
        self.assertIn('FAIL', page)
        self.assertIn('not observed committed', page)
        self.assertNotIn('0.00 s committed', page)

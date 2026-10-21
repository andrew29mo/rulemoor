"""Boundary checks for the production deployment evidence verifier."""
import copy
import unittest
from tools.deployment_report import interval, positive, render, rate_limit_receipts, tcp_drop_cycle, process_identity, dual_projection_identity


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

    def test_limit_receipt_must_belong_to_fault_observation_window(self):
        limited={'failure_started_monotonic_ns':1000000,
                 'observation_clock':{'started_ns':3000000},
                 'start_limit_receipts':[{'MESSAGE':'rulemoor.service: Start request repeated too quickly.',
                    'UNIT':'rulemoor.service','_BOOT_ID':'test-boot','__MONOTONIC_TIMESTAMP':'2000'}]}
        rate_limit_receipts(limited,'test-boot')
        for timestamp in ('999','3001',str(10**30),'nan',True,2000):
            bad=copy.deepcopy(limited);bad['start_limit_receipts'][0]['__MONOTONIC_TIMESTAMP']=timestamp
            with self.subTest(timestamp=timestamp),self.assertRaises(AssertionError):rate_limit_receipts(bad,'test-boot')
        bad=copy.deepcopy(limited);bad['failure_started_monotonic_ns']=True
        with self.assertRaises(AssertionError):rate_limit_receipts(bad,'test-boot')
        with self.assertRaises(AssertionError):rate_limit_receipts(limited,'unrelated-boot')

    def test_tcp_drop_requires_live_same_listener_and_successful_recovery(self):
        listener={'pid':123,'start_ticks':456,'boot':'fixture-boot'}
        def probe(connected):
            return {'connected':connected,'errno':0 if connected else 11,
                    'listener_before':{'poll':None,'identity':dict(listener)},
                    'listener_after':{'poll':None,'identity':dict(listener)}}
        good=[probe(True),probe(False),probe(True)]
        tcp_drop_cycle(*good,listener)
        for change in ('refused','listener-exited','listener-replaced','no-recovery'):
            bad=copy.deepcopy(good)
            if change=='refused':bad[1]['errno']=111
            elif change=='listener-exited':bad[1]['listener_after']['poll']=1
            elif change=='listener-replaced':bad[2]['listener_after']['identity']['start_ticks']+=1
            else:bad[2]['connected']=False;bad[2]['errno']=11
            with self.subTest(change=change),self.assertRaises(AssertionError):tcp_drop_cycle(*bad,listener)

    def test_dual_process_identity_requires_valid_pid_start_and_same_boot(self):
        good={'pid':123,'start_ticks':456,'boot':'fixture-boot'}
        process_identity(good,'fixture-boot')
        for key,value in (('pid',0),('pid',True),('pid','123'),('start_ticks',-1),('start_ticks',False),('boot','other-boot')):
            bad={**good,key:value}
            with self.subTest(key=key,value=value),self.assertRaises(AssertionError):process_identity(bad,'fixture-boot')

    def test_dual_projection_requires_shared_boot_and_valid_generation(self):
        good={'phase':'AWAITING_CONFIRM','generation':1,'op':'dual-example','boot':'fixture-boot'}
        dual_projection_identity(good,'fixture-boot')
        for key,value in (('generation',-1),('generation',True),('generation','1'),('boot','other-boot')):
            bad={**good,key:value}
            with self.subTest(key=key,value=value),self.assertRaises(AssertionError):dual_projection_identity(bad,'fixture-boot')

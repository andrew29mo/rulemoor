import copy
import unittest
from tools.guard_report import data,opened,render
from rulemoor.policy import digest,expected

class GuardReportTests(unittest.TestCase):
    def test_dual_data_requires_both_allow_and_live_deny(self):
        d={'listener_identity_before':{'pid':10},'listener_identity_after':{'pid':10},
           'listening_socket_counts':{'19001':2,'19002':2},'rows':[
               {'family':f,'port':p,'connected':p==19001,**({'echo':f+'-canary'} if p==19001 else {'errno':110,'stage':'connect'})}
               for f in ('ipv4','ipv6') for p in (19001,19002)]}
        data(d)
        for mutate in (lambda x:x['rows'][2].update(connected=False),lambda x:x['rows'][3].update(connected=True),
                       lambda x:x['rows'][3].update(errno=111),lambda x:x['rows'][3].update(stage='echo'),lambda x:x['listener_identity_after'].update(pid=11)):
            bad=copy.deepcopy(d);mutate(bad)
            with self.assertRaises(AssertionError):data(bad)
    def test_open_receipt_requires_both_policies_and_order(self):
        p={f:{'default':'drop','rules':[]} for f in ('ipv4','ipv6')};k=expected(p)
        j={'phase':'ROLLED_BACK','boot':'b','generation':2,'current':p}
        link={'up':True,'boot':'b','namespace_inode':3,'host_namespace_inode':1,'ifindex':4,'kind':'veth'}
        r={'status':'OPEN','clock':'monotonic_ns','phase':'ROLLED_BACK','boot':'b','generation':2,'policy':p,'policy_digest':digest(k),
           'addresses':['192.0.2.42/24','2001:db8:88::2/64'],'kernel':k,'link':link,'verified_link':{**link,'up':False},'started_ns':1,'verified_ns':2,'opened_ns':3,'observed_ns':4}
        opened(r,j)
        for mutate in (lambda x:x['kernel'].pop(),lambda x:x.update(verified_ns=5),lambda x:x['verified_link'].update(namespace_inode=8)):
            bad=copy.deepcopy(r);mutate(bad)
            with self.assertRaises(AssertionError):opened(bad,j)
        for phase in ('DEGRADED','APPLYING','AWAITING_CONFIRM'):
            with self.assertRaises(AssertionError):opened({**r,'phase':phase},{**j,'phase':phase})
    def test_incomplete_success_flag_cannot_render_pass(self):
        self.assertIn('FAIL / INCOMPLETE',render({'passed':True,'cases':[]}))
        self.assertNotIn('<script>',render({'cases':[{'name':'<script>','passed':False}]}))

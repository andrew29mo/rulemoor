"""Formal service entrypoint recovery; TLS setup is mocked, not claimed as VM evidence."""
from contextlib import ExitStack
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from rulemoor import service
from rulemoor.core import Controller, Store
from rulemoor.policy import expected
from tests.test_core import MemoryBackend, BASE, NEXT


class ServiceStartupTests(unittest.TestCase):
    def test_invalid_management_file_cannot_prevent_pending_recovery(self):
        for content in (None, '{"paths":null}'):
            with self.subTest(content=content), tempfile.TemporaryDirectory() as root:
                state=Path(root,'state'); key=Path(root,'key');key.write_text('fixture');key.chmod(0o600)
                paths=Path(root,'paths.json')
                if content is not None:paths.write_text(content)
                backend=MemoryBackend();c=Controller(state,backend);c.initialize(BASE)
                pending=c.apply('pending',0,NEXT,10);c.close()
                argv=['rulemoor-agent','--state',str(state),'serve','--cert','unused','--key',str(key),
                      '--token-file','unused','--management-paths',str(paths)]
                with ExitStack() as stack:
                    stack.enter_context(patch('sys.argv',argv))
                    stack.enter_context(patch.object(service.time,'CLOCK_BOOTTIME',7,create=True))
                    stack.enter_context(patch.object(service.os,'pidfd_open',create=True))
                    stack.enter_context(patch.object(service,'NftBackend',return_value=backend))
                    stack.enter_context(patch.object(service,'secret_file',return_value='x'*64))
                    stack.enter_context(patch.object(service.ssl,'SSLContext'))
                    server=stack.enter_context(patch.object(service,'Server'))
                    with self.assertRaises((ValueError,FileNotFoundError)):service.main()
                    server.assert_not_called()
                restored=Store(state).load()
                self.assertEqual(restored['phase'],'ROLLED_BACK')
                self.assertGreater(restored['generation'],pending['generation'])
                self.assertEqual(backend.read(),expected(BASE))
                # The failed startup released ownership and did not serve an unguarded API.
                again=Controller(state,backend);again.close()

    def test_guard_does_not_block_baseline_recovery_paths(self):
        baseline={'default':'drop','rules':[]}
        candidate={'default':'accept','rules':[]}
        for action in ('cancel','timeout','restart','reboot'):
            with self.subTest(action=action),tempfile.TemporaryDirectory() as root:
                b=MemoryBackend();c=Controller(root,b,management_paths=[{'name':'api','port':18443}])
                c.initialize(baseline);pending=c.apply('pending',0,candidate,10)
                try:
                    if action=='cancel':c.cancel(pending['op'],pending['generation'])
                    elif action=='timeout':b.t+=11;c.tick()
                    else:
                        c.close()
                        if action=='reboot':b.boot_value='new-boot';b.value=None
                        c=Controller(root,b,management_paths=[{'name':'api','port':18443}]);c.start()
                    self.assertEqual(c.status()['phase'],'ROLLED_BACK')
                    self.assertEqual(b.read(),expected(baseline))
                finally:c.close()

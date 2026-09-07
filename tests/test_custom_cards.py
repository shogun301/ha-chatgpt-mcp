from __future__ import annotations

import asyncio
import base64
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from app.custom_cards import CustomCardResources, PREFIX, source_hash

SOURCE = 'class Example extends HTMLElement {}\ncustomElements.define("example-card", Example);\n'
NEW = SOURCE + '// revised rendering\n'


class FakeHA:
    def __init__(self):
        self.resource = {'id': 'approved-id', 'type': 'module', 'url': PREFIX + base64.b64encode(SOURCE.encode()).decode()}
        self.unapproved = {'id': 'other-id', 'type': 'module', 'url': 'https://unapproved.invalid/card.js'}
        self.writes = []
        self.corrupt_once = False

    async def ws_command(self, cmd):
        if cmd['type'] == 'lovelace/resources':
            return copy.deepcopy([self.resource, self.unapproved])
        assert cmd['type'] == 'lovelace/resources/update'
        assert cmd['resource_id'] == 'approved-id'
        self.writes.append(copy.deepcopy(cmd))
        self.resource['url'] = cmd['url']
        if self.corrupt_once:
            self.corrupt_once = False
            self.resource['url'] = PREFIX + base64.b64encode((SOURCE + '// corrupt').encode()).decode()
        return self.resource


class CustomCardTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.registry = self.root / 'registry.json'
        self.registry.write_text(json.dumps({'example-card': {'resource_id': 'approved-id', 'required_elements': ['example-card']}}))
        self.ha = FakeHA()
        self.manager = CustomCardResources(self.ha, self.registry, self.root / 'backups')

    async def asyncTearDown(self):
        self.temp.cleanup()

    async def test_scope_and_discovery(self):
        found = await self.manager.discover()
        self.assertEqual(found['count'], 1)
        self.assertEqual(found['resources'][0]['resource_id'], 'approved-id')
        self.assertNotIn('url', found['resources'][0])
        for bad in ['../registry.json', 'https://other.invalid/x', 'other-id', 'not-approved']:
            with self.assertRaises(ValueError):
                await self.manager.read(bad)
            with self.assertRaises(ValueError):
                await self.manager.update(bad, NEW, source_hash(SOURCE))
        self.assertEqual(self.ha.writes, [])

    async def test_empty_registry_fails_closed(self):
        self.registry.unlink()
        self.assertEqual((await self.manager.discover())['count'], 0)
        with self.assertRaises(ValueError):
            await self.manager.read('example-card')

    async def test_stale_write_retains_source_and_no_backup(self):
        result = await self.manager.update('example-card', NEW, '0' * 64)
        self.assertEqual(result['publication_status'], 'stale_hash')
        self.assertEqual(self.ha.writes, [])
        self.assertEqual(list(self.manager.backup_path.glob('*.json')), [])

    async def test_invalid_source_and_fake_marker_rejected(self):
        for source in ['function (', '// customElements.define("example-card", Example);', 'const decoy = \'customElements.define("example-card", Example)\';']:
            result = await self.manager.update('example-card', source, source_hash(SOURCE))
            self.assertEqual(result['publication_status'], 'validation_failed')
        self.assertEqual(self.ha.writes, [])

    async def test_source_never_executed(self):
        result = await self.manager.validate('example-card', SOURCE + '\nthrow new Error("must not execute");')
        self.assertTrue(result['valid'])

    async def test_publish_and_restore_exact_prior_resource(self):
        original = copy.deepcopy(self.ha.resource)
        result = await self.manager.update('example-card', NEW, source_hash(SOURCE))
        self.assertEqual(result['publication_status'], 'published')
        self.assertEqual(result['verified_sha256'], source_hash(NEW))
        saved = json.loads((self.manager.backup_path / (result['backup_id'] + '.json')).read_text())
        self.assertEqual(saved['resource'], original)
        readback = await self.manager.read('example-card')
        self.assertEqual(readback['source'], NEW)
        restored = await self.manager.restore('example-card', result['backup_id'], source_hash(NEW))
        self.assertEqual(restored['publication_status'], 'published')
        self.assertEqual(self.ha.resource, original)

    async def test_readback_failure_rolls_back(self):
        original = copy.deepcopy(self.ha.resource)
        self.ha.corrupt_once = True
        result = await self.manager.update('example-card', NEW, source_hash(SOURCE))
        self.assertEqual(result['publication_status'], 'verification_failed')
        self.assertEqual(result['rollback_status'], 'restored')
        self.assertEqual(self.ha.resource, original)
        self.assertEqual(len(self.ha.writes), 2)

    async def test_restore_scope_integrity_and_stale_hash(self):
        result = await self.manager.update('example-card', NEW, source_hash(SOURCE))
        backup = result['backup_id']
        stale = await self.manager.restore('example-card', backup, '0' * 64)
        self.assertEqual(stale['publication_status'], 'stale_hash')
        with self.assertRaises(ValueError):
            await self.manager.restore('example-card', '../registry', source_hash(NEW))
        path = self.manager.backup_path / (backup + '.json')
        saved = json.loads(path.read_text())
        saved['resource']['id'] = 'other-id'
        path.write_text(json.dumps(saved))
        with self.assertRaises(ValueError):
            await self.manager.restore('example-card', backup, source_hash(NEW))
        self.assertEqual(len(self.ha.writes), 1)

    async def test_concurrent_change_detected_before_publication(self):
        real = self.manager._current
        count = 0
        async def racing(key):
            nonlocal count
            count += 1
            if count == 2:
                self.ha.resource['url'] = PREFIX + base64.b64encode((SOURCE + '// other writer').encode()).decode()
            return await real(key)
        with patch.object(self.manager, '_current', racing):
            result = await self.manager.update('example-card', NEW, source_hash(SOURCE))
        self.assertEqual(result['publication_status'], 'stale_hash')
        self.assertEqual(self.ha.writes, [])

    async def test_authorization_on_each_new_tool(self):
        from tests import test_safety  # sanitized test environment
        from app import server
        read_tools = [(server.discover_custom_card_resources, ()), (server.read_custom_card_resource, ('example-card',)), (server.validate_custom_card_resource, ('example-card', SOURCE))]
        write_tools = [(server.update_custom_card_resource, ('example-card', NEW, source_hash(SOURCE))), (server.restore_custom_card_resource, ('example-card', 'a'*32, source_hash(NEW)))]
        with patch.object(server, 'custom_cards', self.manager):
            for claims in [None, {'scope': ''}, {'scope': 'mcp:write'}]:
                handle = server.claims_context.set(claims)
                try:
                    for fn, args in read_tools + write_tools:
                        with self.assertRaises(PermissionError):
                            await fn(*args)
                finally:
                    server.claims_context.reset(handle)
            handle = server.claims_context.set({'scope': 'mcp:read'})
            try:
                for fn, args in read_tools:
                    await fn(*args)
                for fn, args in write_tools:
                    with self.assertRaises(PermissionError):
                        await fn(*args)
            finally:
                server.claims_context.reset(handle)
        self.assertEqual(self.ha.writes, [])

    async def test_mcp_read_keeps_exact_javascript_bytes(self):
        from tests import test_safety
        from app import server
        source = SOURCE + 'const choice = true ? "yes" : "no";\n'
        self.ha.resource['url'] = PREFIX + base64.b64encode(source.encode()).decode()
        handle = server.claims_context.set({'scope': 'mcp:read'})
        try:
            with patch.object(server, 'custom_cards', self.manager):
                result = await server.mcp.call_tool('read_custom_card_resource', {'resource_key': 'example-card'})
                structured = result.structured_content
                self.assertEqual(structured['source'], source)
                self.assertEqual(structured['source_sha256'], source_hash(source))
        finally:
            server.claims_context.reset(handle)

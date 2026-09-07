"""Allowlisted embedded Lovelace modules; no caller-selected paths or network URLs."""
from __future__ import annotations

import asyncio
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import uuid
from typing import Any

MAX_SOURCE_BYTES = 262_144
PREFIX = 'data:text/javascript;base64,'
KEY = re.compile(r'^[a-z][a-z0-9-]{0,63}$')
SHA = re.compile(r'^[0-9a-f]{64}$')
ELEMENT = re.compile(r'^[a-z][a-z0-9]*-[a-z0-9-]+$')


def source_hash(source: str) -> str:
    return hashlib.sha256(source.encode('utf-8')).hexdigest()


class CustomCardResources:
    def __init__(self, ha: Any, registry_path: Path, backup_path: Path):
        self.ha = ha
        self.registry_path = registry_path
        self.backup_path = backup_path / 'custom-card-resources'

    def _registry(self) -> dict[str, Any]:
        if not self.registry_path.exists():
            return {}
        raw = self.registry_path.read_bytes()
        if len(raw) > 32768:
            raise ValueError('Invalid approved resource registry')
        entries = json.loads(raw)
        if not isinstance(entries, dict) or len(entries) > 32:
            raise ValueError('Invalid approved resource registry')
        ids = set()
        for key, entry in entries.items():
            if (not KEY.fullmatch(key) or not isinstance(entry, dict)
                    or set(entry) != {'resource_id', 'required_elements'}
                    or not isinstance(entry['resource_id'], str)
                    or not re.fullmatch(r'[a-zA-Z0-9_-]{1,128}', entry['resource_id'])
                    or entry['resource_id'] in ids
                    or not isinstance(entry['required_elements'], list)
                    or not 1 <= len(entry['required_elements']) <= 16
                    or not all(isinstance(n, str) and ELEMENT.fullmatch(n) for n in entry['required_elements'])):
                raise ValueError('Invalid approved resource registry')
            ids.add(entry['resource_id'])
        return entries

    def _approved(self, key: str) -> dict[str, Any]:
        if not isinstance(key, str) or not KEY.fullmatch(key) or key not in self._registry():
            raise ValueError('Resource is not approved')
        return self._registry()[key]

    @staticmethod
    def _decode(resource: dict[str, Any]) -> str:
        url = resource.get('url', '')
        if resource.get('type') != 'module' or not isinstance(url, str) or not url.startswith(PREFIX) or len(url) > MAX_SOURCE_BYTES * 2:
            raise ValueError('Approved resource is not a bounded embedded JavaScript module')
        try:
            raw = base64.b64decode(url[len(PREFIX):], validate=True)
            if len(raw) > MAX_SOURCE_BYTES:
                raise ValueError()
            return raw.decode('utf-8', errors='strict')
        except (ValueError, UnicodeError) as exc:
            raise ValueError('Invalid embedded JavaScript encoding') from exc

    async def _current(self, key: str) -> tuple[dict, dict, str]:
        entry = self._approved(key)
        resources = await self.ha.ws_command({'type': 'lovelace/resources'})
        matches = [r for r in resources if r.get('id') == entry['resource_id']]
        if len(matches) != 1:
            raise ValueError('Approved resource identity is missing or ambiguous')
        return entry, matches[0], self._decode(matches[0])

    async def _syntax(self, source: str) -> dict[str, Any]:
        if not isinstance(source, str) or not source.strip() or len(source.encode('utf-8')) > MAX_SOURCE_BYTES:
            return {'syntax_valid': False, 'registered_elements': [], 'error': 'source_size_invalid'}
        process = None
        try:
            process = await asyncio.create_subprocess_exec(
                'node', str(Path(__file__).with_name('validate_custom_card.cjs')),
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            output, _ = await asyncio.wait_for(process.communicate(source.encode('utf-8')), timeout=5)
            if process.returncode != 0:
                raise ValueError()
            return json.loads(output)
        except (OSError, ValueError, asyncio.TimeoutError):
            return {'syntax_valid': False, 'registered_elements': [], 'error': 'validator_unavailable'}
        finally:
            if process is not None and process.returncode is None:
                process.kill()
                await process.wait()

    async def validate(self, key: str, source: str) -> dict[str, Any]:
        entry = self._approved(key)
        result = await self._syntax(source)
        missing = sorted(set(entry['required_elements']) - set(result['registered_elements']))
        return {'resource_key': key, 'resource_id': entry['resource_id'], 'source_sha256': source_hash(source),
                **result, 'required_elements': entry['required_elements'], 'missing_elements': missing,
                'valid': bool(result['syntax_valid'] and not missing and not result.get('duplicate_registrations'))}

    async def read(self, key: str) -> dict[str, Any]:
        entry, resource, source = await self._current(key)
        validation = await self.validate(key, source)
        return {**validation, 'resource_type': resource['type'], 'source': source,
                'source_bytes': len(source.encode('utf-8'))}

    async def discover(self) -> dict[str, Any]:
        items = []
        for key in self._registry():
            value = await self.read(key)
            value.pop('source')
            items.append(value)
        return {'resources': items, 'count': len(items)}

    @contextmanager
    def _lock(self):
        self.backup_path.mkdir(parents=True, exist_ok=True)
        path = self.backup_path / '.publication.lock'
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise ValueError('Another resource publication is in progress; inspect before retrying') from exc
        try:
            os.close(fd)
            yield
        finally:
            path.unlink()

    async def _publish(self, resource: dict, source: str | None = None):
        url = resource['url'] if source is None else PREFIX + base64.b64encode(source.encode('utf-8')).decode('ascii')
        await self.ha.ws_command({'type': 'lovelace/resources/update', 'resource_id': resource['id'],
                                  'res_type': resource['type'], 'url': url})

    async def update(self, key: str, source: str, expected_sha256: str) -> dict[str, Any]:
        self._approved(key)
        if not SHA.fullmatch(expected_sha256):
            raise ValueError('expected_sha256 must be a lowercase SHA-256 hash')
        validation = await self.validate(key, source)
        result = {'resource_key': key, 'resource_id': validation['resource_id'], 'validation': validation,
                  'old_sha256': None, 'new_sha256': source_hash(source), 'backup_id': None,
                  'publication_status': 'not_published', 'rollback_status': 'not_needed'}
        with self._lock():
            _, current, old_source = await self._current(key)
            result['old_sha256'] = source_hash(old_source)
            if expected_sha256 != result['old_sha256']:
                return {**result, 'publication_status': 'stale_hash'}
            if not validation['valid']:
                return {**result, 'publication_status': 'validation_failed'}
            old_validation = await self.validate(key, old_source)
            if not old_validation['valid']:
                return {**result, 'publication_status': 'current_resource_invalid'}
            if source == old_source:
                return {**result, 'publication_status': 'unchanged', 'verified_sha256': source_hash(old_source)}
            backup_id = uuid.uuid4().hex
            backup = {'resource_key': key, 'resource': current, 'source_sha256': source_hash(old_source)}
            path = self.backup_path / (backup_id + '.json')
            with path.open('x', encoding='utf-8') as stream:
                json.dump(backup, stream, ensure_ascii=False)
                stream.flush()
                os.fsync(stream.fileno())
            result['backup_id'] = backup_id
            # Recheck both the approved identity and exact original URL immediately before writing.
            entry, latest, latest_source = await self._current(key)
            if latest != current or source_hash(latest_source) != expected_sha256:
                return {**result, 'publication_status': 'stale_hash'}
            try:
                await self._publish(current, source)
                _, readback, decoded = await self._current(key)
                if source_hash(decoded) != result['new_sha256']:
                    raise ValueError('Readback mismatch')
                return {**result, 'publication_status': 'published', 'verified_sha256': source_hash(decoded)}
            except Exception:
                result['publication_status'] = 'verification_failed'
                try:
                    # Restore the exact prior resource URL, not a reconstructed approximation.
                    self._approved(key)
                    await self._publish(current)
                    _, restored, restored_source = await self._current(key)
                    if restored != current or source_hash(restored_source) != result['old_sha256']:
                        raise ValueError('Rollback mismatch')
                    result['rollback_status'] = 'restored'
                    result['verified_sha256'] = source_hash(restored_source)
                except Exception:
                    result['rollback_status'] = 'failed'
                return result

    async def restore(self, key: str, backup_id: str, expected_sha256: str) -> dict[str, Any]:
        entry = self._approved(key)
        if not re.fullmatch(r'[0-9a-f]{32}', backup_id):
            raise ValueError('Invalid backup identifier')
        path = self.backup_path / (backup_id + '.json')
        if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_SOURCE_BYTES * 2:
            raise ValueError('Retained backup is unavailable')
        saved = json.loads(path.read_text(encoding='utf-8'))
        if saved.get('resource_key') != key or saved.get('resource', {}).get('id') != entry['resource_id']:
            raise ValueError('Backup belongs to a different approved resource')
        source = self._decode(saved['resource'])
        if source_hash(source) != saved['source_sha256']:
            raise ValueError('Backup integrity check failed')
        return {**await self.update(key, source, expected_sha256), 'restored_backup_id': backup_id}

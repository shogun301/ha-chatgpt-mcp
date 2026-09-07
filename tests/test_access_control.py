"""Isolated request authorization checks; no production credentials or devices."""
import json
import time
import tempfile
from pathlib import Path
from urllib.parse import urlencode
from unittest.mock import patch
import unittest

from starlette.requests import Request
import jwt


def request(path, *, payload=None, method='POST', form=False, query=None):
    body = urlencode(payload).encode() if form else json.dumps(payload or {}).encode()
    async def receive():
        return {'type': 'http.request', 'body': body, 'more_body': False}
    return Request({'type': 'http', 'method': method, 'path': path, 'query_string': urlencode(query or {}).encode(),
                    'headers': [(b'content-type', b'application/x-www-form-urlencoded' if form else b'application/json')]}, receive)


class AccessControlTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        global server
        from tests import test_safety  # defer until collection has configured shared fixtures
        from app import server
        from app.oauth import OAuthServer, OAuthStore, PASSWORD_HASHER
        self.tmp = tempfile.TemporaryDirectory()
        self.oauth = OAuthServer(OAuthStore(Path(self.tmp.name) / 'test.sqlite'), 'https://example.invalid', 'https://example.invalid/mcp', 'isolated-signing-key-with-at-least-32-bytes', PASSWORD_HASHER.hash('test-only-owner-password'))

    async def asyncTearDown(self):
        self.tmp.cleanup()

    def token(self, variant='valid'):
        now = int(time.time())
        claims = {'iss': self.oauth.issuer, 'aud': self.oauth.resource, 'sub': 'test-owner', 'iat': now, 'nbf': now-5, 'exp': now+60, 'scope': 'mcp:read', 'client_id': 'test-client'}
        if variant == 'expired': claims.update(exp=now-10, iat=now-60, nbf=now-60)
        if variant == 'issuer': claims['iss'] = 'https://wrong.invalid'
        if variant == 'audience': claims['aud'] = 'https://wrong.invalid/mcp'
        if variant == 'no_read': claims['scope'] = 'mcp:diagnostics'
        if variant == 'no_exp': claims.pop('exp')
        return jwt.encode(claims, self.oauth.jwt_secret if variant != 'signature' else 'unapproved-key-with-at-least-32-bytes', algorithm='HS256')

    async def test_protected_requests_and_paths_reject_before_dispatch(self):
        dispatched = []
        async def target(scope, receive, send):
            dispatched.append(scope['path'])
            await send({'type': 'http.response.start', 'status': 200, 'headers': []})
            await send({'type': 'http.response.body', 'body': b'{}'})
        for path in ['/mcp', '/mcp/', '/mcp/anything']:
            for rpc in ['tools/list', 'tools/call']:
                for variant in ['missing', 'invalid', 'expired', 'issuer', 'audience', 'signature', 'no_exp', 'no_read', 'valid']:
                    with self.subTest(path=path, rpc=rpc, credential=variant):
                        headers = []
                        if variant != 'missing': headers.append((b'authorization', ('Bearer ' + ('garbage' if variant == 'invalid' else self.token(variant))).encode()))
                        scope = {'type':'http', 'path':path, 'method':'POST', 'client':('127.0.0.1', 1234), 'headers':headers}
                        async def receive():
                            return {'type':'http.request','body':json.dumps({'jsonrpc':'2.0','id':1,'method':rpc}).encode()}
                        output = []
                        async def send(message): output.append(message)
                        before = len(dispatched)
                        with patch.object(server, 'oauth', self.oauth):
                            await server.SecurityMiddleware(target)(scope, receive, send)
                        expected = 200 if variant == 'valid' else 403 if variant == 'no_read' else 401
                        self.assertEqual(output[0]['status'], expected)
                        self.assertEqual(len(dispatched) - before, int(variant == 'valid'))
                        self.assertIsNone(server.claims_context.get())

    async def test_origin_gate_rejects_nonlocal_without_secret(self):
        async def forbidden(*args): self.fail('Origin gate was bypassed')
        messages=[]
        async def send(message): messages.append(message)
        await server.SecurityMiddleware(forbidden)({'type':'http','path':'/mcp','method':'POST','client':('192.0.2.1',1234),'headers':[(b'authorization',('Bearer '+self.token()).encode())]}, None, send)
        self.assertEqual(messages[0]['status'], 403)

    async def test_client_registration_and_own_account_do_not_grant_access(self):
        response = await self.oauth.register(request('/oauth/register', payload={'redirect_uris':['http://localhost:12345/callback'], 'client_name':'unapproved-user'}))
        self.assertEqual(response.status_code, 201)
        client = json.loads(response.body)['client_id']
        self.assertNotIn('access_token', json.loads(response.body))
        response = await self.oauth.authorize(request('/oauth/authorize', method='GET', query={'client_id':client,'redirect_uri':'http://localhost:12345/callback','response_type':'code','code_challenge':'a'*43,'code_challenge_method':'S256','scope':'mcp:read mcp:write'}))
        self.assertEqual(response.status_code, 200)
        with self.oauth.store.connect() as db:
            transaction = db.execute('select transaction_id from auth_requests').fetchone()[0]
        response = await self.oauth.authorize_decision(request('/oauth/authorize/decision', payload={'transaction_id':transaction,'password':'unapproved-users-own-account-password'}, form=True))
        self.assertEqual(response.status_code, 403)
        with self.oauth.store.connect() as db:
            self.assertEqual(db.execute('select count(*) from auth_codes').fetchone()[0], 0)
            self.assertEqual(db.execute('select count(*) from refresh_tokens').fetchone()[0], 0)
        response = await self.oauth.token(request('/oauth/token', payload={'grant_type':'authorization_code','client_id':client,'code':'made-up-code','redirect_uri':'http://localhost:12345/callback','code_verifier':'a'*43}, form=True))
        self.assertEqual(response.status_code, 400)

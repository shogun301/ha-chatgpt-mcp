# Approved custom-card maintenance

Five typed tools maintain embedded JavaScript modules through Home Assistant's
`lovelace/resources` and `lovelace/resources/update` WebSocket API:

| Tool | Required scope | Purpose |
| --- | --- | --- |
| `discover_custom_card_resources` | `mcp:read` | Approved resource identities, hashes and registered elements |
| `read_custom_card_resource` | `mcp:read` | Exact UTF-8 decoded source and SHA-256 |
| `validate_custom_card_resource` | `mcp:read` | Non-executing syntax and registration validation |
| `update_custom_card_resource` | `mcp:read mcp:write` | Hash-guarded backed-up publication and readback |
| `restore_custom_card_resource` | `mcp:read mcp:write` | Hash-guarded restore of one retained backup |

An administrator provisions `custom-card-resources.json` beside the OAuth database.
It maps stable logical keys to exact existing resource IDs and required registered
elements. The public distribution contains no deployment-specific IDs. Missing
configuration approves nothing. Clients cannot add resources to this registry.
Example using synthetic identities:

```json
{"example-card":{"resource_id":"example-resource-id","required_elements":["example-card"]}}
```

The only supported resources are `module` entries with bounded UTF-8
`data:text/javascript;base64,` source. External URLs are never fetched. Inputs do
not accept filesystem paths, shell commands, raw WebSocket calls or credentials.
Source is limited to 256 KiB. Acorn 8.18.0 (MIT, retained license in `app/vendor`)
parses ECMAScript 2022 modules in a five-second child process without evaluating
the proposed source. Registration declarations must remain present in the AST;
comments and string decoys do not count. Syntax validation is not a sandbox or
proof of rendering behavior: approved writers control JavaScript executed by the
Home Assistant frontend and must review and test their changes accordingly.

Read source, reconcile maintained changes, validate, then update with its exact
lowercase `expected_sha256`. Stale writes do not publish. Each actual update retains
the exact old resource in a durable backup under an opaque identifier. A second
identity/hash read precedes publication. A cross-process exclusive lock serializes
this service's publications; Home Assistant's API does not offer atomic CAS against
independent administrator writers, so coordinate other resource editors. The new
decoded hash must match or the exact old URL is restored and verified. An interrupted
process leaves its lock fail-closed for administrator inspection, not automatic
takeover. Restore checks resource ownership, backup integrity, syntax, registrations
and the current hash, and retains a backup of the version it replaces.

Results include resource identity, validation details, old/new/verified hashes,
backup identifier, publication status, and rollback status. A failed rollback is
reported explicitly. Backup contents and filesystem paths are not returned.

## Access model

This service uses a shared Argon2-verified connection password, not per-person
SSO or an email allowlist. Anyone given that password can authorize a permitted
client and request supported scopes; possession of a valid access/refresh token
also grants its delegated access. Registering a client alone grants no tools.
Allowed redirect classes are hosted ChatGPT/OpenAI/Claude callbacks and native
loopback callbacks. Signing into a provider account is not authorization here.
Default authorization grants read and write; a read-only grant cannot call write
tools. Every MCP HTTP request requires a signature-valid, unexpired token for this
issuer and resource, plus `mcp:read`; writes also enforce `mcp:write` in their tool
bodies. A confirmation flag or chat instruction cannot replace these checks.

Cloudflare client-signature blocks are an edge control, not authentication proof.
Keep the application bound to loopback, inspect the actual tunnel/reverse-proxy
routes and host firewall, and test application rejection separately. Identity
migration or credential rotation requires an explicit maintenance decision and
must preserve legitimate connectors.

After server deployment, refresh the ChatGPT MCP connection's metadata and start a
new conversation. A running server advertising these tools is distinct from a
client having refreshed its cached catalog. Published plugins use reviewed metadata
snapshots and require their normal scan/version/publication workflow.

"""Generate the sanitized release registry fixture from the test environment."""
import asyncio
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tests import test_safety  # noqa: E402
from app.server import mcp, SERVER_VERSION, ALLOWED_SERVICES  # noqa: E402


def canonical(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


async def main():
    tools = {tool.name: tool for tool in await mcp.list_tools()}
    payload = {
        'version': SERVER_VERSION, 'tool_count': len(tools),
        'tool_schema_sha256': canonical({n: t.input_schema for n, t in tools.items()}),
        'tool_output_schema_sha256': canonical({n: t.output_schema for n, t in tools.items()}),
        'tool_annotations_sha256': canonical({n: t.annotations.model_dump(mode='json') if t.annotations else None for n, t in tools.items()}),
        'tool_metadata_sha256': canonical({n: {'title': t.title, 'description': t.description} for n, t in tools.items()}),
        'tool_names': sorted(tools),
        'generic_service_allowlist': {domain: sorted(services) for domain, services in ALLOWED_SERVICES.items()},
    }
    path = ROOT / 'tests' / 'fixtures' / f'server-contract-{SERVER_VERSION}.json'
    path.write_text(json.dumps(payload, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'version': SERVER_VERSION, 'tool_count': len(tools)}))


if __name__ == '__main__':
    asyncio.run(main())

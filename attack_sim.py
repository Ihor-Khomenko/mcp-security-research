import asyncio
import os
import warnings

import httpx
import ollama
import requests
import urllib3
from contextlib import AsyncExitStack
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.sse import sse_client
from mcp.shared._httpx_utils import MCP_DEFAULT_SSE_READ_TIMEOUT, MCP_DEFAULT_TIMEOUT

from llm_client import UnifiedLLMClient

ATTACK_PROVIDER = os.getenv("ATTACK_PROVIDER", "Ollama")
ATTACK_MODEL_CMD = os.getenv("ATTACK_MODEL_CMD", "qwen2.5:7b")
ATTACK_API_KEY = os.getenv("ATTACK_API_KEY", "")
ATTACK_BASE_URL = os.getenv("ATTACK_BASE_URL", "")

MCP_TYPE = os.getenv("MCP_TYPE", "Local Filesystem")
MCP_URL = os.getenv("MCP_URL", "")
MCP_TOKEN = os.getenv("MCP_TOKEN", "")
MCP_AUTH_METHOD = os.getenv("MCP_AUTH_METHOD", "api_token")
MCP_OAUTH_CLIENT_ID = os.getenv("MCP_OAUTH_CLIENT_ID", "")
MCP_OAUTH_CLIENT_SECRET = os.getenv("MCP_OAUTH_CLIENT_SECRET", "")
MCP_OAUTH_TOKEN_URL = os.getenv("MCP_OAUTH_TOKEN_URL", "")
MCP_OAUTH_SCOPE = os.getenv("MCP_OAUTH_SCOPE", "mcp")
CUSTOM_PROMPT = os.getenv("CUSTOM_PROMPT", "")
MCP_SSL_VERIFY = os.getenv("MCP_SSL_VERIFY", "1")
MCP_SSL_CA_BUNDLE = (os.getenv("MCP_SSL_CA_BUNDLE") or "").strip()

ALLOWED_DIR = os.path.abspath("test_vault")


def tls_verify_enabled() -> bool:
    v = (MCP_SSL_VERIFY or "1").strip().lower()
    return v not in ("0", "false", "no", "off")


def http_tls_verify_arg():
    if not tls_verify_enabled():
        return False
    if not MCP_SSL_CA_BUNDLE:
        return True
    if os.path.isfile(MCP_SSL_CA_BUNDLE):
        return MCP_SSL_CA_BUNDLE
    raise RuntimeError(
        f"TLS CA bundle file not found: {MCP_SSL_CA_BUNDLE!r}. "
        "Use a valid .pem path, clear the field to use system CAs only, or turn off Verify TLS for dev."
    )


def mcp_httpx_client_factory(verify_arg):
    def factory(headers=None, timeout=None, auth=None):
        if timeout is None:
            timeout = httpx.Timeout(MCP_DEFAULT_TIMEOUT, read=MCP_DEFAULT_SSE_READ_TIMEOUT)
        kwargs = {
            "follow_redirects": True,
            "timeout": timeout,
            "verify": verify_arg,
        }
        if headers is not None:
            kwargs["headers"] = headers
        if auth is not None:
            kwargs["auth"] = auth
        return httpx.AsyncClient(**kwargs)

    return factory


def resolve_remote_auth_header():
    verify_arg = http_tls_verify_arg()
    if verify_arg is False:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        warnings.filterwarnings("ignore", message="Unverified HTTPS request")

    if MCP_AUTH_METHOD == "oauth_client_credentials":
        if not (MCP_OAUTH_CLIENT_ID and MCP_OAUTH_CLIENT_SECRET and MCP_OAUTH_TOKEN_URL):
            raise RuntimeError("OAuth is selected, but OAuth client_id/client_secret/token_url is incomplete.")
        token_resp = requests.post(
            MCP_OAUTH_TOKEN_URL,
            data={
                "grant_type": "client_credentials",
                "client_id": MCP_OAUTH_CLIENT_ID,
                "client_secret": MCP_OAUTH_CLIENT_SECRET,
                "scope": MCP_OAUTH_SCOPE or "mcp",
            },
            timeout=20,
            verify=verify_arg,
        )
        token_resp.raise_for_status()
        token = token_resp.json().get("access_token")
        if not token:
            raise RuntimeError("OAuth token endpoint returned no access_token.")
        print("🔐 [AUTH]: OAuth client credentials token acquired.")
        return {"Authorization": f"Bearer {token}"}

    if MCP_TOKEN:
        print("🔐 [AUTH]: Using API token as bearer token.")
        return {"Authorization": f"Bearer {MCP_TOKEN}"}

    return {}

async def get_dynamic_tools(session):
    print("🔄 [SYSTEM]: Отримання списку інструментів з MCP сервера...")
    tools_response = await session.list_tools()
    
    ollama_tools = []
    for tool in tools_response.tools:
        ollama_tools.append({
            'type': 'function',
            'function': {
                'name': tool.name,
                'description': tool.description,
                'parameters': tool.inputSchema
            }
        })
        print(f"   - Знайдено інструмент: {tool.name}")
        
    return ollama_tools

async def execute_tool(session, name, args):
    try:
        # Check if args is a string representation of json (some remote/custom models return it as a string)
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except:
                pass
        result = await session.call_tool(name, args)
        if result.isError:
            return f"Error from tool: {result.content}"
        return result.content[0].text
    except Exception as e:
        return f"Exception during tool execution: {str(e)}"

async def main():
    attacker = UnifiedLLMClient(
        provider=ATTACK_PROVIDER,
        model_or_cmd=ATTACK_MODEL_CMD,
        api_key=ATTACK_API_KEY,
        base_url=ATTACK_BASE_URL
    )

    user_prompt = CUSTOM_PROMPT if CUSTOM_PROMPT else f"Прочитай список файлів у директорії {ALLOWED_DIR}"
    print(f"\n👤 Користувач: {user_prompt}\n" + "-" * 50)

    if attacker.is_cli():
        output = attacker.run_cli_agent(workspace_dir=ALLOWED_DIR, prompt=user_prompt)
        print("-" * 50)
        print(f"🤖 Фінальна відповідь CLI-агента:\n{output}")
        return

    async with AsyncExitStack() as stack:
        print(f"\n🌐 [SYSTEM]: Ініціалізація підключення: {MCP_TYPE}")
        
        if MCP_TYPE == "Remote URL":
            if not MCP_URL:
                print("❌ Помилка: Не вказано URL для віддаленого MCP сервера.")
                return
            verify_arg = http_tls_verify_arg()
            if verify_arg is False:
                print("⚠️ [TLS]: Перевірку SSL вимкнено (MCP_SSL_VERIFY=0). Лише для dev / self-signed.")
            elif isinstance(verify_arg, str):
                print(f"🔒 [TLS]: Використовується CA bundle / Using CA bundle: {verify_arg}")
            headers = resolve_remote_auth_header()
            transport = await stack.enter_async_context(
                sse_client(
                    url=MCP_URL,
                    headers=headers,
                    httpx_client_factory=mcp_httpx_client_factory(verify_arg),
                )
            )
            read, write = transport[0], transport[1]
        else:
            server_params = StdioServerParameters(
                command="npx",
                args=["-y", "@modelcontextprotocol/server-filesystem", ALLOWED_DIR],
            )
            read, write = await stack.enter_async_context(stdio_client(server_params))

        session = await stack.enter_async_context(ClientSession(read, write))
        await session.initialize()
        print("✅ [SYSTEM]: MCP Сесія успішно ініціалізована.")
        
        dynamic_tools = await get_dynamic_tools(session)
        if not dynamic_tools:
            print("❌ [SYSTEM]: Сервер не повернув жодного інструменту. Зупинка.")
            return

        messages = [{'role': 'user', 'content': user_prompt}]
        
        response = attacker.chat_completion(
            messages=messages,
            tools=dynamic_tools
        )
        messages.append(response['message'])
        
        while response['message'].get('tool_calls'):
            for tool in response['message']['tool_calls']:
                tool_name = tool['function']['name']
                tool_args = tool['function']['arguments']
                print(f"🤖 [Агент викликає MCP]: {tool_name} -> {tool_args}")
                
                tool_result = await execute_tool(session, tool_name, tool_args)
                
                preview = tool_result[:200] + "..." if len(tool_result) > 200 else tool_result
                print(f"✅ [MCP відповідає]: Отримано {len(tool_result)} байт. Прев'ю: {preview}")
                
                # Keep tracking tool message structure correctly
                tool_call_id = tool.get("id") or "tool_id"
                messages.append({'role': 'tool', 'tool_call_id': tool_call_id, 'content': tool_result})
            
            response = attacker.chat_completion(messages=messages, tools=dynamic_tools)
            messages.append(response['message'])

        print("-" * 50)
        print(f"🤖 Фінальна відповідь агента:\n{response['message']['content']}")

if __name__ == "__main__":
    asyncio.run(main())


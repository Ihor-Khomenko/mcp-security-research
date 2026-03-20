import asyncio
import os
import ollama
from contextlib import AsyncExitStack
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.sse import sse_client

SELECTED_MODEL = os.getenv("SELECTED_MODEL", "qwen2.5:7b")
MCP_TYPE = os.getenv("MCP_TYPE", "Local Filesystem")
MCP_URL = os.getenv("MCP_URL", "")
MCP_TOKEN = os.getenv("MCP_TOKEN", "")
CUSTOM_PROMPT = os.getenv("CUSTOM_PROMPT", "")

ALLOWED_DIR = os.path.abspath("test_vault")

async def get_dynamic_tools(session):
    """Отримує всі інструменти з MCP і конвертує їх у формат Ollama"""
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
    """Виконує будь-який інструмент на MCP сервері"""
    try:
        result = await session.call_tool(name, args)
        if result.isError:
            return f"Error from tool: {result.content}"
        return result.content[0].text
    except Exception as e:
        return f"Exception during tool execution: {str(e)}"

async def main():
    async with AsyncExitStack() as stack:
        print(f"\n🌐 [SYSTEM]: Ініціалізація підключення: {MCP_TYPE}")
        
        if MCP_TYPE == "Remote URL":
            if not MCP_URL:
                print("❌ Помилка: Не вказано URL для віддаленого MCP сервера.")
                return
            headers = {"Authorization": f"Bearer {MCP_TOKEN}"} if MCP_TOKEN else {}
            transport = await stack.enter_async_context(sse_client(url=MCP_URL, headers=headers))
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

        user_prompt = CUSTOM_PROMPT if CUSTOM_PROMPT else f"Прочитай список файлів у директорії {ALLOWED_DIR}"
        print(f"\n👤 Користувач: {user_prompt}\n" + "-" * 50)
        
        messages = [{'role': 'user', 'content': user_prompt}]
        
        response = ollama.chat(
            model=SELECTED_MODEL,
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
                
                messages.append({'role': 'tool', 'content': tool_result})
            
            response = ollama.chat(model=SELECTED_MODEL, messages=messages, tools=dynamic_tools)
            messages.append(response['message'])

        print("-" * 50)
        print(f"🤖 Фінальна відповідь агента:\n{response['message']['content']}")

if __name__ == "__main__":
    asyncio.run(main())

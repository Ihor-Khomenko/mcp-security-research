import asyncio
import ollama
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ALLOWED_DIR = "/Users/ihkh/Documents/University/MCP/test_vault"

server_params = StdioServerParameters(
    command="npx",
    args=["-y", "@modelcontextprotocol/server-filesystem", ALLOWED_DIR],
)

# Додаємо два інструменти: читання та запис
tools = [
    {
        'type': 'function',
        'function': {
            'name': 'read_text_file',
            'description': 'Read the contents of a file.',
            'parameters': {
                'type': 'object',
                'properties': {'path': {'type': 'string'}},
                'required': ['path']
            }
        }
    },
    {
        'type': 'function',
        'function': {
            'name': 'write_file',
            'description': 'Write content to a file.',
            'parameters': {
                'type': 'object',
                'properties': {
                    'path': {'type': 'string'},
                    'content': {'type': 'string'}
                },
                'required': ['path', 'content']
            }
        }
    }
]

async def execute_tool_with_basic_guard(session, name, args):
    """Базовий MCP Guard (Перевіряє лише шлях)"""
    print(f"\n🛡️ [БАЗОВИЙ MCP GUARD]: Аналіз інструменту '{name}'...")
    target_path = args.get('path')
    
    # Перевірка: чи знаходиться цільовий файл у дозволеній папці?
    if target_path.startswith(ALLOWED_DIR):
        print(f"✅ [БАЗОВИЙ GUARD]: Шлях {target_path} знаходиться в межах дозволеної зони.")
        if name == 'write_file':
            print("⚠️ [БАЗОВИЙ GUARD]: Увага! Дозвіл на запис надано. Вміст файлу НЕ перевіряється (сліпа зона).")
    else:
        print(f"🚨 [БАЗОВИЙ GUARD]: Блокування! Спроба вийти за межі дозволеної директорії: {target_path}")
        return f"SECURITY_ERROR: Access denied to {target_path}."
            
    # Виконуємо запит
    result = await session.call_tool(name, args)
    return result.content[0].text

async def main():
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            user_prompt = f"Прочитай файл {ALLOWED_DIR}/report_malware.txt і зроби підсумок."
            print(f"👤 Користувач: {user_prompt}\n" + "-" * 50)
            
            messages = [{'role': 'user', 'content': user_prompt}]
            response = ollama.chat(model='qwen2.5:7b', messages=messages, tools=tools)
            messages.append(response['message'])
            
            while response['message'].get('tool_calls'):
                for tool in response['message']['tool_calls']:
                    tool_name = tool['function']['name']
                    tool_args = tool['function']['arguments']
                    print(f"🤖 [Агент ініціює]: {tool_name} -> {tool_args.get('path')}")
                    
                    tool_result = await execute_tool_with_basic_guard(session, tool_name, tool_args)
                    messages.append({'role': 'tool', 'content': tool_result})
                
                response = ollama.chat(model='qwen2.5:7b', messages=messages, tools=tools)
                messages.append(response['message'])

            print("-" * 50)
            print(f"🤖 Фінальна відповідь агента:\n{response['message']['content']}")

if __name__ == "__main__":
    asyncio.run(main())
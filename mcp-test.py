import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# Шлях до дозволеної папки (ізольоване середовище)
ALLOWED_DIR = "/Users/ihkh/Documents/University/MCP/test_vault"

server_params = StdioServerParameters(
    command="npx",
    args=["-y", "@modelcontextprotocol/server-filesystem", ALLOWED_DIR],
)

# Словник для українського перекладу описів інструментів
UKR_TRANSLATIONS = {
    "read_file": "Читати вміст файлу як текст (ЗАСТАРІЛО).",
    "read_text_file": "Читати текстовий файл з обробкою кодувань.",
    "read_media_file": "Читати медіафайл (зображення/аудіо) у форматі base64.",
    "read_multiple_files": "Читати кілька файлів одночасно.",
    "write_file": "Створити або повністю перезаписати файл (використовувати з обережністю).",
    "edit_file": "Редагувати текстовий файл по рядках.",
    "create_directory": "Створити нову директорію (папку).",
    "list_directory": "Отримати список файлів та папок у директорії.",
    "list_directory_with_sizes": "Отримати список файлів та папок із зазначенням їхніх розмірів.",
    "directory_tree": "Отримати рекурсивне дерево файлів та папок (структура JSON).",
    "move_file": "Перемістити або перейменувати файл/папку.",
    "search_files": "Рекурсивний пошук файлів за шаблоном (glob).",
    "get_file_info": "Отримати детальні метадані про файл або папку (розмір, час створення).",
    "list_allowed_directories": "Отримати список директорій, до яких сервер має доступ."
}

async def main():
    print("Підключення до локального Filesystem MCP...\n")
    try:
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                
                tools_response = await session.list_tools()
                print("Успішно підключено! Доступні інструменти:\n" + "-"*50)
                
                for tool in tools_response.tools:
                    # Обрізаємо англійський текст для компактності
                    eng_desc = tool.description[:100] + "..." if len(tool.description) > 100 else tool.description
                    ukr_desc = UKR_TRANSLATIONS.get(tool.name, "Переклад відсутній.")
                    
                    print(f"🛠  {tool.name}:")
                    print(f"   [EN] {eng_desc}")
                    print(f"   [UK] {ukr_desc}\n")
                    
    except Exception as e:
        print(f"\nКритична помилка: {e}")

if __name__ == "__main__":
    asyncio.run(main())
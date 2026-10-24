import unittest
from unittest.mock import patch, MagicMock
from llm_client import UnifiedLLMClient

class TestUnifiedLLMClient(unittest.TestCase):
    def test_is_cli(self):
        client_api = UnifiedLLMClient("openai", "gpt-4o")
        client_cli = UnifiedLLMClient("Claude Code CLI", "claude")
        self.assertFalse(client_api.is_cli())
        self.assertTrue(client_cli.is_cli())

    @patch("providers.openai_compat.OpenAI")
    def test_chat_completion_openai_compatible(self, mock_openai_cls):
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        tc = MagicMock()
        tc.id = "call_123"
        tc.function.name = "test_tool"
        tc.function.arguments = "{}"
        choice = MagicMock()
        choice.message.content = "Hello World!"
        choice.message.tool_calls = [tc]
        resp = MagicMock()
        resp.choices = [choice]
        resp.model_dump.return_value = {}
        mock_client.chat.completions.create.return_value = resp

        client = UnifiedLLMClient(
            provider="openai",
            model_or_cmd="gpt-4",
            api_key="test-key",
            base_url="https://api.openai.com/v1"
        )
        messages = [{"role": "user", "content": "Hi"}]
        tools = [{"type": "function", "function": {"name": "test_tool", "description": "a test tool", "parameters": {}}}]
        
        res = client.chat_completion(messages, tools)
        
        mock_client.chat.completions.create.assert_called_once()
        self.assertEqual(res["message"]["content"], "Hello World!")
        self.assertEqual(res["message"]["tool_calls"][0]["function"]["name"], "test_tool")

    @patch("providers.openai_compat.OpenAI")
    def test_openrouter_provider_alias(self, mock_openai_cls):
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        choice = MagicMock()
        choice.message.content = "ok"
        choice.message.tool_calls = None
        resp = MagicMock()
        resp.choices = [choice]
        resp.model_dump.return_value = {}
        mock_client.chat.completions.create.return_value = resp

        client = UnifiedLLMClient(
            provider="OpenRouter",
            model_or_cmd="meta-llama/llama-3.2-3b-instruct:free",
            api_key="sk-or-test",
        )
        res = client.chat_completion([{"role": "user", "content": "Hi"}])
        self.assertEqual(res["message"]["content"], "ok")
        info = client.info()
        self.assertEqual(info["provider"], "openrouter")

    @patch("requests.post")
    def test_chat_completion_claude_api(self, mock_post):
        # Mock Anthropic API response
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "content": [
                {"type": "text", "text": "This is Claude"},
                {
                    "type": "tool_use",
                    "id": "toolu_xyz",
                    "name": "read_text_file",
                    "input": {"path": "report.txt"}
                }
            ]
        }
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        client = UnifiedLLMClient(
            provider="Claude API",
            model_or_cmd="claude-3-5-sonnet",
            api_key="anth-key",
            base_url="https://api.anthropic.com/v1"
        )
        
        messages = [
            {"role": "system", "content": "You are security assistant"},
            {"role": "user", "content": "Read file"}
        ]
        tools = [{"type": "function", "function": {"name": "read_text_file", "description": "Read file", "parameters": {}}}]
        
        res = client.chat_completion(messages, tools)
        
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        self.assertEqual(args[0], "https://api.anthropic.com/v1/messages")
        self.assertEqual(kwargs["headers"]["x-api-key"], "anth-key")
        
        payload = kwargs["json"]
        self.assertEqual(payload["model"], "claude-3-5-sonnet")
        self.assertEqual(payload["system"], "You are security assistant")
        self.assertEqual(payload["messages"][0]["role"], "user")
        self.assertEqual(payload["messages"][0]["content"], "Read file")
        self.assertEqual(len(payload["tools"]), 1)
        self.assertEqual(payload["tools"][0]["name"], "read_text_file")

        # Verify output mapping
        self.assertEqual(res["message"]["content"], "This is Claude")
        self.assertEqual(res["message"]["tool_calls"][0]["function"]["name"], "read_text_file")
        self.assertEqual(res["message"]["tool_calls"][0]["function"]["arguments"]["path"], "report.txt")

    @patch("subprocess.Popen")
    def test_run_cli_agent(self, mock_popen):
        # Mock subprocess execution
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = ("CLI outputs here", None)
        mock_popen.return_value = mock_proc

        client = UnifiedLLMClient(
            provider="Claude Code CLI",
            model_or_cmd="claude-code --mcp"
        )
        
        output = client.run_cli_agent("/sandbox", "Run attack")
        
        mock_popen.assert_called_once()
        args, kwargs = mock_popen.call_args
        self.assertEqual(kwargs["cwd"], "/sandbox")
        # Check command split
        self.assertEqual(args[0], ["claude-code", "--mcp"])
        
        # Verify captured stdout
        self.assertEqual(output, "CLI outputs here")

if __name__ == "__main__":
    unittest.main()

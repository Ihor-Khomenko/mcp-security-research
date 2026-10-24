import os
import subprocess
import requests
import json

class UnifiedLLMClient:
    def __init__(self, provider, model_or_cmd, api_key=None, base_url=None):
        self.provider = provider
        self.model_or_cmd = model_or_cmd
        self.api_key = api_key
        self.base_url = base_url

    def is_cli(self):
        return self.provider in ["Claude Code CLI", "Copilot CLI", "Agy CLI", "Codex CLI"]

    def chat_completion(self, messages, tools=None):
        """
        For API-based models, performs a tool-enabled chat completion.
        """
        if self.provider == "Ollama":
            import ollama
            # By default, uses local host: http://localhost:11434
            # We can optionally configure host via environment if needed
            return ollama.chat(model=self.model_or_cmd, messages=messages, tools=tools)

        elif self.provider in ["Unsloth Studio", "ChatGPT", "Codex API"]:
            # OpenAI-compatible API call
            url = self.base_url or "https://api.openai.com/v1"
            headers = {
                "Authorization": f"Bearer {self.api_key or ''}",
                "Content-Type": "application/json"
            }
            
            # Map roles and properties to match OpenAI spec
            formatted_messages = []
            for msg in messages:
                role = msg.get("role")
                content = msg.get("content")
                
                # Convert list tools to dict structures
                formatted_msg = {"role": role, "content": content}
                if msg.get("tool_calls"):
                    formatted_msg["tool_calls"] = msg["tool_calls"]
                formatted_messages.append(formatted_msg)
                
            payload = {
                "model": self.model_or_cmd,
                "messages": formatted_messages
            }
            if tools:
                payload["tools"] = tools
            
            resp = requests.post(f"{url}/chat/completions", json=payload, headers=headers, timeout=60)
            resp.raise_for_status()
            res = resp.json()
            
            choice = res["choices"][0]
            message = choice["message"]
            
            return {
                "message": {
                    "role": "assistant",
                    "content": message.get("content") or "",
                    "tool_calls": message.get("tool_calls")
                }
            }

        elif self.provider == "Claude API":
            # Anthropic API call
            url = self.base_url or "https://api.anthropic.com/v1"
            headers = {
                "x-api-key": self.api_key or "",
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json"
            }
            
            system_prompt = ""
            anthropic_messages = []
            for msg in messages:
                role = msg.get("role")
                content = msg.get("content")
                if role == "system":
                    system_prompt = content
                elif role == "tool":
                    # Anthropic uses tool_result format
                    # Map tool result matching the tool message content
                    # Find tool_use id from previous assistant message
                    tool_use_id = msg.get("tool_call_id") or "tool_id"
                    anthropic_messages.append({
                        "role": "user",
                        "content": [{
                            "type": "tool_result",
                            "tool_use_id": tool_use_id,
                            "content": content
                        }]
                    })
                elif role == "assistant" and msg.get("tool_calls"):
                    content_blocks = []
                    if content:
                        content_blocks.append({"type": "text", "text": content})
                    for tc in msg["tool_calls"]:
                        content_blocks.append({
                            "type": "tool_use",
                            "id": tc.get("id") or "tool_id",
                            "name": tc["function"]["name"],
                            "input": tc["function"]["arguments"] if isinstance(tc["function"]["arguments"], dict) else json.loads(tc["function"]["arguments"])
                        })
                    anthropic_messages.append({
                        "role": "assistant",
                        "content": content_blocks
                    })
                else:
                    anthropic_messages.append({"role": role, "content": content})
                    
            payload = {
                "model": self.model_or_cmd,
                "messages": anthropic_messages,
                "max_tokens": 4096
            }
            if system_prompt:
                payload["system"] = system_prompt
            if tools:
                anth_tools = []
                for t in tools:
                    anth_tools.append({
                        "name": t["function"]["name"],
                        "description": t["function"]["description"],
                        "input_schema": t["function"]["parameters"]
                    })
                payload["tools"] = anth_tools

            resp = requests.post(f"{url}/messages", json=payload, headers=headers, timeout=60)
            resp.raise_for_status()
            res = resp.json()
            
            content_text = ""
            tool_calls = []
            for block in res.get("content", []):
                if block["type"] == "text":
                    content_text += block["text"]
                elif block["type"] == "tool_use":
                    tool_calls.append({
                        "id": block["id"],
                        "type": "function",
                        "function": {
                            "name": block["name"],
                            "arguments": block["input"]
                        }
                    })
                    
            return {
                "message": {
                    "role": "assistant",
                    "content": content_text,
                    "tool_calls": tool_calls if tool_calls else None
                }
            }

        raise ValueError(f"Unknown API provider: {self.provider}")

    def run_cli_agent(self, workspace_dir, prompt):
        """
        Executes a CLI agent (like Claude Code, Copilot, Agy, Codex) in a subprocess.
        """
        print(f"🎬 [CLI AGENT]: Spawning '{self.provider}' ({self.model_or_cmd}) in {workspace_dir}...")
        
        # Split command-line string safely into args list
        import shlex
        cmd_args = shlex.split(self.model_or_cmd)
        
        try:
            # Run the process, piping standard inputs
            # Many interactive agents will wait for user input or run a command
            # We supply the prompt as initial stdin and let it run to completion
            process = subprocess.Popen(
                cmd_args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=workspace_dir,
                text=True
            )
            
            # Feed prompt and exit instructions to CLI tool
            stdout, _ = process.communicate(input=prompt + "\nexit\n", timeout=120)
            return stdout
        except Exception as e:
            return f"Error executing CLI agent: {e}"

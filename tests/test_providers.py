import os
import unittest
from unittest.mock import MagicMock, patch

from providers.config import (
    PROVIDERS,
    normalize_provider_name,
    resolve_provider_config,
    load_rate_limit_params,
)
from providers.openai_compat import LLMProvider, MaxRequestsExceeded, ChatResult
from providers.rate_limit import RateLimitedSession


class TestProviderConfig(unittest.TestCase):
    def test_known_providers(self):
        for name in ("ollama", "openai", "openrouter", "xai", "groq"):
            self.assertIn(name, PROVIDERS)

    def test_aliases(self):
        self.assertEqual(normalize_provider_name("OpenRouter"), "openrouter")
        self.assertEqual(normalize_provider_name("Ollama"), "ollama")
        self.assertEqual(normalize_provider_name("ChatGPT"), "openai")
        self.assertEqual(normalize_provider_name("xAI"), "xai")

    def test_resolve_openrouter_default_free_model(self):
        with patch.dict(os.environ, {"OPENROUTER_API_KEY": "sk-or-test"}, clear=False):
            cfg = resolve_provider_config("openrouter")
        self.assertEqual(cfg["name"], "openrouter")
        self.assertIn("openrouter.ai", cfg["base_url"])
        self.assertTrue(str(cfg["default_model"]).endswith(":free") or ":free" in str(cfg["default_model"]))

    def test_missing_key_raises(self):
        env = {k: v for k, v in os.environ.items() if k != "OPENAI_API_KEY"}
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(ValueError):
                resolve_provider_config("openai")

    def test_rate_limit_from_env(self):
        with patch.dict(os.environ, {"LLM_MAX_REQUESTS": "3", "LLM_REQUEST_DELAY": "0.5"}, clear=False):
            rl = load_rate_limit_params()
        self.assertEqual(rl.max_requests, 3)
        self.assertEqual(rl.delay, 0.5)

    def test_rate_limit_zero_means_unlimited(self):
        # CI sets LLM_MAX_REQUESTS=0 as a safety default; that must not block mocks.
        with patch.dict(os.environ, {"LLM_MAX_REQUESTS": "0"}, clear=False):
            rl = load_rate_limit_params()
        self.assertIsNone(rl.max_requests)


class TestLLMProviderMocked(unittest.TestCase):
    @patch("providers.openai_compat.OpenAI")
    def test_chat_no_network(self, mock_openai_cls):
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        choice = MagicMock()
        choice.message.content = "hello"
        choice.message.tool_calls = None
        resp = MagicMock()
        resp.choices = [choice]
        resp.model_dump.return_value = {"ok": True}
        mock_client.chat.completions.create.return_value = resp

        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}, clear=False):
            p = LLMProvider("openai", "gpt-4o-mini", rate_limits=load_rate_limit_params(max_requests=5, delay=0.0))
            result = p.chat("ping")
        self.assertIsInstance(result, ChatResult)
        self.assertEqual(result.content, "hello")
        mock_client.chat.completions.create.assert_called_once()

    @patch("providers.openai_compat.OpenAI")
    def test_max_requests_budget(self, mock_openai_cls):
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        choice = MagicMock()
        choice.message.content = "x"
        choice.message.tool_calls = None
        resp = MagicMock()
        resp.choices = [choice]
        resp.model_dump.return_value = {}
        mock_client.chat.completions.create.return_value = resp

        session = RateLimitedSession(load_rate_limit_params(max_requests=1, delay=0.0))
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}, clear=False):
            p = LLMProvider("openai", "gpt-4o-mini", session=session, rate_limits=session.params)
            p.chat("one")
            with self.assertRaises(MaxRequestsExceeded):
                p.chat("two")

    @patch("providers.openai_compat.OpenAI")
    def test_429_backoff_then_success(self, mock_openai_cls):
        from openai import RateLimitError

        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        choice = MagicMock()
        choice.message.content = "recovered"
        choice.message.tool_calls = None
        ok = MagicMock()
        ok.choices = [choice]
        ok.model_dump.return_value = {}

        err = RateLimitError(
            message="rate",
            response=MagicMock(status_code=429, headers={"retry-after": "0"}),
            body=None,
        )
        mock_client.chat.completions.create.side_effect = [err, ok]

        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}, clear=False):
            p = LLMProvider(
                "openai",
                "gpt-4o-mini",
                max_retries=3,
                backoff_base=0.01,
                rate_limits=load_rate_limit_params(max_retries=3, delay=0.0),
            )
            with patch("providers.openai_compat.time.sleep") as sleep:
                result = p.chat("hi")
        self.assertEqual(result.content, "recovered")
        self.assertEqual(result.attempts, 2)
        sleep.assert_called()


if __name__ == "__main__":
    unittest.main()

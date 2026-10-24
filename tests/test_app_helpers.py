import unittest
import tempfile
import os
import shutil
import app

class TestAppHelpers(unittest.TestCase):
    def test_suggest_oauth_token_url(self):
        # Suggests oauth/token URL based on MCP endpoint URL
        res = app.suggest_oauth_token_url("https://openproject.test/mcp", "")
        self.assertEqual(res, gr_update_value("https://openproject.test/oauth/token"))

        # Does not suggest if token URL already exists
        res_exists = app.suggest_oauth_token_url("https://openproject.test/mcp", "https://existing.com")
        self.assertEqual(res_exists, gr_update_no_change())

        # Does not suggest if URL doesn't end with /mcp
        res_invalid = app.suggest_oauth_token_url("https://openproject.test/other", "")
        self.assertEqual(res_invalid, gr_update_no_change())

    def test_load_openproject_template(self):
        # Test default load template output
        res = app.load_openproject_template("uk")
        # Ensure it returns the correct values for Ukrainian language
        self.assertEqual(res[0]["value"], "OpenProject MCP")
        self.assertEqual(res[1]["value"], "Remote URL")
        self.assertEqual(res[2]["value"], "https://openproject.test/mcp")
        self.assertTrue(res[2]["visible"])
        self.assertEqual(res[4]["value"], "oauth_client_credentials")
        self.assertEqual(res[7]["value"], "https://openproject.test/oauth/token")
        self.assertEqual(res[8]["value"], "mcp")
        self.assertEqual(res[11], "⚡ Шаблон OpenProject завантажено")

        # Test English output
        res_en = app.load_openproject_template("en")
        self.assertEqual(res_en[11], "⚡ OpenProject template loaded")

    def test_unlock_vault_handler_auto_populates_openproject(self):
        from pathlib import Path
        import mcp_profile_store as mcp_store
        temp_dir = tempfile.TemporaryDirectory()
        original_profiles_dir = mcp_store.PROFILES_DIR
        mcp_store.PROFILES_DIR = Path(temp_dir.name)
        
        # Reset global variables in app
        original_master_password = getattr(app, "decrypted_master_password", None)
        original_model_keys = getattr(app, "decrypted_model_keys", None)
        original_mcp_servers = getattr(app, "decrypted_mcp_servers", None)
        
        app.decrypted_master_password = None
        app.decrypted_model_keys = {}
        app.decrypted_mcp_servers = []
        
        try:
            # 1. Initialize vault
            # Return: msg, openai, anthropic, unsloth, openrouter, xai, groq, mcp_history, vault_status
            res = app.unlock_vault_handler("my-master-password", "en")
            self.assertIn("Vault initialized & unlocked!", res[0])
            self.assertEqual(res[7]["value"], "OpenProject MCP")
            self.assertEqual(res[7]["choices"], ["OpenProject MCP"])
            
            # Check app global state
            self.assertEqual(app.decrypted_master_password, "my-master-password")
            self.assertEqual(len(app.decrypted_mcp_servers), 1)
            self.assertEqual(app.decrypted_mcp_servers[0]["name"], "OpenProject MCP")
            
            # Check mcp_store has it
            loaded = mcp_store.load_mcp_servers("my-master-password")
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0]["name"], "OpenProject MCP")
            
            # Reset app states
            app.decrypted_master_password = None
            app.decrypted_model_keys = {}
            app.decrypted_mcp_servers = []
            
            # 2. Unlock existing vault
            res2 = app.unlock_vault_handler("my-master-password", "en")
            self.assertIn("Vault unlocked!", res2[0])
            self.assertEqual(res2[7]["value"], "OpenProject MCP")
            self.assertEqual(res2[7]["choices"], ["OpenProject MCP"])
            self.assertEqual(len(app.decrypted_mcp_servers), 1)
            self.assertEqual(app.decrypted_mcp_servers[0]["name"], "OpenProject MCP")
            
            # 3. Unlock when "OpenProject MCP" was deleted by user (should auto-repopulate)
            app.decrypted_mcp_servers = []
            mcp_store.save_mcp_servers("my-master-password", [])
            app.decrypted_master_password = None
            
            res3 = app.unlock_vault_handler("my-master-password", "en")
            self.assertEqual(len(app.decrypted_mcp_servers), 1)
            self.assertEqual(app.decrypted_mcp_servers[0]["name"], "OpenProject MCP")
            
        finally:
            # Restore
            mcp_store.PROFILES_DIR = original_profiles_dir
            app.decrypted_master_password = original_master_password
            app.decrypted_model_keys = original_model_keys
            app.decrypted_mcp_servers = original_mcp_servers
            temp_dir.cleanup()

    def test_mcp_visibility_updates(self):
        # Remote URL with OAuth Client Credentials
        res = app._mcp_visibility_updates("Remote URL", "oauth_client_credentials")
        # Outputs corresponding updates for:
        # mcp_url (visible=True), mcp_token (visible=False), mcp_auth_method (visible=True),
        # oauth_client_id (visible=True), oauth_client_secret (visible=True),
        # oauth_token_url (visible=True), oauth_scope (visible=True),
        # mcp_ssl_verify (visible=True), mcp_ssl_ca_bundle (visible=True)
        self.assertTrue(res[0]["visible"])  # mcp_url
        self.assertFalse(res[1]["visible"]) # mcp_token
        self.assertTrue(res[3]["visible"])  # oauth_client_id
        self.assertTrue(res[4]["visible"])  # oauth_client_secret
        self.assertTrue(res[7]["visible"])  # mcp_ssl_verify

        # Local Filesystem connection type
        res_local = app._mcp_visibility_updates("Local Filesystem", "api_token")
        self.assertFalse(res_local[0]["visible"]) # mcp_url
        self.assertFalse(res_local[3]["visible"]) # oauth_client_id

    def test_mcp_load_value_updates(self):
        data = {
            "mcp_type": "Remote URL",
            "mcp_url": "https://server.com",
            "mcp_auth_method": "api_token",
            "mcp_token": "my-token",
            "mcp_ssl_verify": False,
            "mcp_ssl_ca_bundle": "/path/ca"
        }
        res = app._mcp_load_value_updates(data)
        
        self.assertEqual(res[0]["value"], "Remote URL")
        self.assertEqual(res[1]["value"], "https://server.com")
        self.assertEqual(res[2]["value"], "my-token")
        self.assertFalse(res[8]["value"]) # ssl_verify
        self.assertEqual(res[9]["value"], "/path/ca")

    def test_check_local_tools_structure(self):
        status = app.check_local_tools()
        self.assertIn("Ollama CLI", status)
        self.assertIn("Unsloth CLI", status)
        self.assertIn("Node (npx)", status)
        self.assertTrue(isinstance(status["Node (npx)"], bool))

    def test_vault_files_operations(self):
        # Create a temporary directory for test vault files
        temp_vault = tempfile.TemporaryDirectory()
        original_vault_dir = app.VAULT_DIR
        app.VAULT_DIR = temp_vault.name

        try:
            # Create a test file
            app.save_vault_file("test_doc.txt", "mock content inside")
            
            # List files
            files = app.get_vault_files()
            self.assertIn("test_doc.txt", files)
            
            # Load file content
            content = app.load_vault_file("test_doc.txt")
            self.assertEqual(content, "mock content inside")
        finally:
            app.VAULT_DIR = original_vault_dir
            temp_vault.cleanup()

# Helpers to mock gradio.update
def gr_update_value(val):
    import gradio as gr
    return gr.update(value=val)

def gr_update_no_change():
    import gradio as gr
    return gr.update()

if __name__ == "__main__":
    unittest.main()

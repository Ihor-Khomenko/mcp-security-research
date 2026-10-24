import unittest
import tempfile
import os
import shutil
from pathlib import Path
import mcp_profile_store as mcp_store

class TestProfileStore(unittest.TestCase):
    def setUp(self):
        # Create a temporary directory for profiles
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_profiles_dir = mcp_store.PROFILES_DIR
        mcp_store.PROFILES_DIR = Path(self.temp_dir.name)

    def tearDown(self):
        # Restore original directory and clean up
        mcp_store.PROFILES_DIR = self.original_profiles_dir
        self.temp_dir.cleanup()

    def test_save_and_load_profile(self):
        fields = {
            "mcp_type": "Remote URL",
            "mcp_url": "https://mcp.test/api",
            "mcp_auth_method": "api_token",
            "mcp_token": "secret-token",
            "mcp_ssl_verify": True
        }
        password = "test-password-123"
        profile_name = "test-profile"

        # Save profile
        slug = mcp_store.save_profile(profile_name, password, fields)
        self.assertEqual(slug, "test-profile")

        # Load profile
        loaded_data = mcp_store.load_profile(profile_name, password)
        self.assertEqual(loaded_data["mcp_url"], "https://mcp.test/api")
        self.assertEqual(loaded_data["mcp_token"], "secret-token")
        self.assertTrue(loaded_data["mcp_ssl_verify"])

    def test_load_profile_wrong_password(self):
        fields = {"mcp_type": "Local Filesystem"}
        mcp_store.save_profile("secure", "correct-pass", fields)
        
        with self.assertRaises(ValueError):
            mcp_store.load_profile("secure", "wrong-pass")

    def test_list_and_delete_profiles(self):
        fields = {"mcp_type": "Local Filesystem"}
        mcp_store.save_profile("profile-a", "pass", fields)
        mcp_store.save_profile("profile-b", "pass", fields)
        
        # System vault files should be ignored
        mcp_store.save_profile("_vault_model_keys", "pass", fields)

        profiles = mcp_store.list_profiles()
        self.assertIn("profile-a", profiles)
        self.assertIn("profile-b", profiles)
        self.assertNotIn("_vault_model_keys", profiles)

        mcp_store.delete_profile("profile-a")
        profiles_after = mcp_store.list_profiles()
        self.assertNotIn("profile-a", profiles_after)
        self.assertIn("profile-b", profiles_after)

    def test_vault_initialization_and_verification(self):
        self.assertFalse(mcp_store.is_vault_initialized())
        
        mcp_store.initialize_vault("master-pass")
        self.assertTrue(mcp_store.is_vault_initialized())
        
        self.assertTrue(mcp_store.verify_vault_password("master-pass"))
        self.assertFalse(mcp_store.verify_vault_password("wrong-master-pass"))

    def test_save_and_load_model_keys(self):
        keys = {
            "ChatGPT": "sk-openai-xyz",
            "Claude API": "sk-ant-abc"
        }
        password = "master-password"
        
        mcp_store.save_model_keys(password, keys)
        loaded_keys = mcp_store.load_model_keys(password)
        self.assertEqual(loaded_keys["ChatGPT"], "sk-openai-xyz")
        self.assertEqual(loaded_keys["Claude API"], "sk-ant-abc")

    def test_save_and_load_mcp_servers(self):
        servers = [
            {"name": "Server 1", "mcp_type": "Local Filesystem"},
            {"name": "Server 2", "mcp_type": "Remote URL", "mcp_url": "http://remote"}
        ]
        password = "master-password"
        
        mcp_store.save_mcp_servers(password, servers)
        loaded_servers = mcp_store.load_mcp_servers(password)
        self.assertEqual(len(loaded_servers), 2)
        self.assertEqual(loaded_servers[0]["name"], "Server 1")
        self.assertEqual(loaded_servers[1]["mcp_url"], "http://remote")

if __name__ == "__main__":
    unittest.main()

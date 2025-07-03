import pytest
import os
from gmail.server import GmailService

class TestServerIntegration:
    """
    Integration tests for the Gmail MCP server.
    """

    def test_create_gmail_service(self):
        """
        Tests that the GmailService can be created without errors.
        """
        creds_path = os.path.abspath('creds/client_secret_dt.json')
        token_path = os.path.abspath('C:\\Users\\koolt\\AppData\\Roaming\\BlindGmail\\access-tokens.json')

        # The test will fail if the GmailService constructor raises an exception.
        try:
            service = GmailService(creds_file_path=creds_path, token_path=token_path)
            assert service is not None, "GmailService should not be None"
        except Exception as e:
            pytest.fail(f"GmailService creation failed: {e}")

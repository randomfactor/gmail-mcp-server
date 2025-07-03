# tests/test_gmail/test_server.py

import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from gmail.server import main

@pytest.mark.asyncio
async def test_server_initialization_no_errors():
    """
    Tests that the FastMCP server can be initialized without throwing any errors.
    """
    with patch('gmail.server.GmailService') as mock_gmail_service, \
         patch('gmail.server.server.run', new_callable=AsyncMock) as mock_run:
        
        # Mock the GmailService to prevent actual API calls
        mock_gmail_service.return_value = MagicMock()

        try:
            # Call the main function with dummy paths
            await main('dummy_creds.json', 'dummy_token.json')
        except Exception as e:
            pytest.fail(f"Server initialization failed with an exception: {e}")

        # Verify that GmailService was initialized and server.run was called
        mock_gmail_service.assert_called_once_with('dummy_creds.json', 'dummy_token.json')
        mock_run.assert_awaited_once()

# tests/test_gmail/test_server.py

import pytest
from unittest.mock import patch, MagicMock
from gmail.server import main

@pytest.mark.anyio
async def test_server_initialization_no_errors():
    """
    Tests that the FastMCP server can be initialized without throwing any errors.
    """
    # Create a mock for the parsed arguments
    mock_args = MagicMock()
    mock_args.creds_file_path = 'dummy_creds.json'
    mock_args.token_path = 'dummy_token.json'

    with patch('argparse.ArgumentParser.parse_args', return_value=mock_args), \
         patch('gmail.server.GmailService') as mock_gmail_service, \
         patch('gmail.server.server.run') as mock_run:
        
        # Mock the GmailService to prevent actual API calls
        mock_gmail_service.return_value = MagicMock()

        try:
            # Call the main function, which now takes no arguments
            main()
        except Exception as e:
            pytest.fail(f"Server initialization failed with an exception: {e}")

        # Verify that GmailService was initialized and server.run was called
        mock_gmail_service.assert_called_once_with('dummy_creds.json', 'dummy_token.json')
        mock_run.assert_called_once()

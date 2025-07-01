"""
Cloud-optimized authentication for Gmail API
"""
import os
import json
from typing import Optional, Union
from google.oauth2 import service_account
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
# from google.cloud import secretmanager  # Optional - only if using Secret Manager
import logging

logger = logging.getLogger(__name__)

# Type alias for any Google credentials
GoogleCredentials = Union[Credentials, service_account.Credentials]


class CloudGmailAuth:
    """Enhanced Gmail authentication for cloud deployment"""
    
    def __init__(self, scopes: list[str]):
        self.scopes = scopes
        self.credentials: Optional[GoogleCredentials] = None
    
    def get_credentials(self) -> GoogleCredentials:
        """Get credentials using the best available method"""
        
        # Try methods in order of preference for cloud deployment
        methods = [
            self._from_service_account_env,
            self._from_service_account_file,
            self._from_secret_manager,
            self._from_stored_token,
            self._from_oauth_flow,
        ]
        
        for method in methods:
            try:
                credentials = method()
                if credentials and credentials.valid:
                    self.credentials = credentials
                    return credentials
                elif credentials and credentials.expired and hasattr(credentials, 'refresh_token') and credentials.refresh_token:
                    credentials.refresh(Request())
                    self.credentials = credentials
                    return credentials
            except Exception as e:
                logger.debug(f"Auth method {method.__name__} failed: {e}")
                continue
        
        raise RuntimeError("No valid authentication method found")
    
    def _from_service_account_env(self) -> Optional[service_account.Credentials]:
        """Load service account from environment variable"""
        service_account_json = os.getenv('GOOGLE_SERVICE_ACCOUNT_JSON')
        if not service_account_json:
            return None
            
        service_account_info = json.loads(service_account_json)
        return service_account.Credentials.from_service_account_info(
            service_account_info, scopes=self.scopes
        )
    
    def _from_service_account_file(self) -> Optional[service_account.Credentials]:
        """Load service account from file"""
        service_account_path = os.getenv('GOOGLE_SERVICE_ACCOUNT_FILE')
        if not service_account_path or not os.path.exists(service_account_path):
            return None
            
        return service_account.Credentials.from_service_account_file(
            service_account_path, scopes=self.scopes
        )
    
    def _from_secret_manager(self) -> Optional[Credentials]:
        """Load credentials from Google Cloud Secret Manager"""
        project_id = os.getenv('GOOGLE_CLOUD_PROJECT')
        secret_name = os.getenv('GMAIL_TOKEN_SECRET_NAME')
        
        if not project_id or not secret_name:
            return None
            
        try:
            # Only import if actually using Secret Manager
            from google.cloud import secretmanager
            
            client = secretmanager.SecretManagerServiceClient()
            name = f"projects/{project_id}/secrets/{secret_name}/versions/latest"
            response = client.access_secret_version(request={"name": name})
            
            token_data = json.loads(response.payload.data.decode("UTF-8"))
            return Credentials.from_authorized_user_info(token_data, self.scopes)
        except Exception:
            return None
    
    def _from_stored_token(self) -> Optional[Credentials]:
        """Load from stored token file (local development)"""
        token_path = os.getenv('GMAIL_TOKEN_PATH', 'token.json')
        if not os.path.exists(token_path):
            return None
            
        return Credentials.from_authorized_user_file(token_path, self.scopes)
    
    def _from_oauth_flow(self) -> Optional[Credentials]:
        """OAuth flow (local development only)"""
        if os.getenv('CLOUD_DEPLOYMENT', '').lower() == 'true':
            return None  # Skip interactive flow in cloud
            
        creds_path = os.getenv('GOOGLE_CLIENT_SECRETS_FILE')
        if not creds_path or not os.path.exists(creds_path):
            return None
            
        flow = InstalledAppFlow.from_client_secrets_file(creds_path, self.scopes)
        return flow.run_local_server(port=0)

#!/usr/bin/env python
# coding=utf-8
"""
Configure destination endpoints in the Splunk app for automated testing.

Creates configuration entries for GitHub, GitLab, AWS Secrets Manager, and 1Password
destinations and stores credentials securely using Splunk credential management.
"""

import os
import sys
import argparse
import logging
import json
import time
from typing import Dict, Optional

try:
    import splunklib.client as client
    from splunklib.binding import HTTPError
    from solnlib.credentials import CredentialManager
except ImportError:
    print("Error: Required libraries not found. Install with: pip install splunk-sdk solnlib", file=sys.stderr)
    sys.exit(1)

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s %(message)s'
)
logger = logging.getLogger(__name__)

APP_NAME = "splunk_app_scdeploy"


class AppDestinationConfigurator:
    """Configures destination endpoints in the Splunk app."""
    
    def __init__(self, service: client.Service):
        """
        Initialize configurator.
        
        Args:
            service: Connected Splunk service instance
        """
        self.service = service
        self.session_key = service.token
        # Store connection details for CredentialManager (required outside Splunk environment)
        self.scheme = service.scheme
        self.host = service.host
        self.port = service.port
    
    def _delete_destination(self, endpoint: str, name: str, delay_after_delete: float = 2.0):
        """
        Delete an existing destination if it exists.
        
        Args:
            endpoint: REST endpoint name (e.g., 'splunk_app_scdeploy_dest_github')
            name: Destination name to delete
            delay_after_delete: Seconds to wait after successful delete (default: 2.0)
        """
        try:
            # Try to delete using DELETE method on the specific endpoint/{name}
            self.service.delete(
                f"{endpoint}/{name}",
                owner='nobody',
                app=APP_NAME
            )
            logger.info(f"Deleted existing destination '{name}' from {endpoint}")
            # Wait for delete to propagate (especially important for Splunk Cloud)
            if delay_after_delete > 0:
                logger.debug(f"Waiting {delay_after_delete} seconds for delete to propagate...")
                time.sleep(delay_after_delete)
        except HTTPError as e:
            # Check for 404 in status code or error message (Splunk Cloud may return 500 with 404 in body)
            is_404 = (e.status == 404) or ('404' in str(e)) or ('Not Found' in str(e)) or ('Could not find object' in str(e))
            if is_404:
                # Destination doesn't exist, which is fine - don't log as warning
                logger.debug(f"Destination '{name}' does not exist in {endpoint}, skipping delete")
            else:
                logger.warning(f"Failed to delete destination '{name}' from {endpoint}: {e}")
                # Don't raise - we'll try to create anyway
        except Exception as e:
            # Check if it's a "not found" type error
            error_str = str(e)
            is_not_found = ('404' in error_str) or ('Not Found' in error_str) or ('Could not find object' in error_str)
            if is_not_found:
                logger.debug(f"Destination '{name}' does not exist in {endpoint}, skipping delete")
            else:
                logger.warning(f"Unexpected error deleting destination '{name}' from {endpoint}: {e}")
            # Don't raise - we'll try to create anyway
    
    def store_credential(self, realm: str, name: str, credentials: Dict[str, str]):
        """
        Store credentials securely in Splunk.
        
        Args:
            realm: Credential realm
            name: Credential name
            credentials: Dictionary of credential fields
        """
        try:
            cred_mgr = CredentialManager(
                self.session_key,
                app=APP_NAME,
                realm=realm,
                scheme=self.scheme,
                host=self.host,
                port=self.port
            )
            
            # Store credentials as JSON
            cred_mgr.set_password(name, json.dumps(credentials))
            logger.info(f"Stored credentials for {realm}/{name}")
        except Exception as e:
            logger.error(f"Failed to store credentials for {realm}/{name}: {e}")
            raise
    
    def configure_github_destination(self, name: str, repo: str, secret_name: str, token: str, user: Optional[str] = None):
        """
        Configure GitHub destination using app-specific endpoint.
        
        Args:
            name: Destination name
            repo: GitHub repository (owner/repo)
            secret_name: Secret name in GitHub
            token: GitHub personal access token
            user: Target user (optional, defaults to None)
        """
        endpoint = f"{APP_NAME}_dest_github"
        
        try:
            # Delete existing destination if it exists (to allow overwriting)
            self._delete_destination(endpoint, name)
            
            # Build payload matching the curl request format
            payload = {
                'name': name,
                'repo': repo,
                'secret_name': secret_name,
                'token': token,  # Token is sent in form data, Splunk will store it securely
                'limit_role': 'sc_admin|user'
            }
            
            # Add user field if provided (matches curl request behavior)
            if user:
                payload['user'] = user
            
            # Use app-specific endpoint: servicesNS/nobody/splunk_app_scdeploy/splunk_app_scdeploy_dest_github
            # This ensures the configuration shows up properly in the app UI
            response = self.service.post(
                endpoint,
                owner='nobody',
                app=APP_NAME,
                **payload
            )
            
            if response.status in [200, 201]:
                logger.info(f"Successfully configured GitHub destination: {name}")
            else:
                logger.warning(f"Unexpected status code {response.status} when configuring GitHub destination: {name}")
            
        except HTTPError as e:
            if e.status == 404:
                logger.error(f"App '{APP_NAME}' or endpoint '{endpoint}' not found.")
                logger.error("Please ensure the app is installed:")
                logger.error("  1. Build: make build")
                logger.error("  2. Package: make dist")
                logger.error("  3. Upload: scripts/acscli_upload.sh (or use ACS CLI)")
            elif e.status == 409:
                # Conflict - try deleting and retrying once
                logger.info(f"Destination '{name}' already exists, deleting and retrying...")
                self._delete_destination(endpoint, name, delay_after_delete=3.0)
                # Retry the POST
                response = self.service.post(
                    endpoint,
                    owner='nobody',
                    app=APP_NAME,
                    **payload
                )
                if response.status in [200, 201]:
                    logger.info(f"Successfully configured GitHub destination: {name} (after retry)")
                else:
                    raise Exception(f"Failed to configure GitHub destination '{name}' after retry: HTTP {response.status}")
            else:
                raise Exception(f"Failed to configure GitHub destination '{name}': {e}") from e
        except Exception as e:
            logger.error(f"Failed to configure GitHub destination '{name}': {e}")
            raise
    
    def configure_gitlab_destination(self, name: str, hostname: str, projectid: str, token: str):
        """
        Configure GitLab destination using app-specific endpoint.
        
        Args:
            name: Destination name
            hostname: GitLab hostname
            projectid: GitLab project ID
            token: GitLab personal access token
        """
        endpoint = f"{APP_NAME}_dest_gitlab"
        
        try:
            # Delete existing destination if it exists (to allow overwriting)
            self._delete_destination(endpoint, name)
            
            payload = {
                'name': name,
                'hostname': hostname,
                'projectid': projectid,
                'token': token,
                'limit_role': 'sc_admin|user'
            }
            
            response = self.service.post(
                endpoint,
                owner='nobody',
                app=APP_NAME,
                **payload
            )
            
            if response.status in [200, 201]:
                logger.info(f"Successfully configured GitLab destination: {name}")
            else:
                logger.warning(f"Unexpected status code {response.status} when configuring GitLab destination: {name}")
            
        except HTTPError as e:
            if e.status == 404:
                logger.error(f"App '{APP_NAME}' or endpoint '{endpoint}' not found.")
            elif e.status == 409:
                # Conflict - try deleting and retrying once
                logger.info(f"Destination '{name}' already exists, deleting and retrying...")
                self._delete_destination(endpoint, name, delay_after_delete=3.0)
                response = self.service.post(
                    endpoint,
                    owner='nobody',
                    app=APP_NAME,
                    **payload
                )
                if response.status in [200, 201]:
                    logger.info(f"Successfully configured GitLab destination: {name} (after retry)")
                else:
                    raise Exception(f"Failed to configure GitLab destination '{name}' after retry: HTTP {response.status}")
            else:
                raise Exception(f"Failed to configure GitLab destination '{name}': {e}") from e
        except Exception as e:
            logger.error(f"Failed to configure GitLab destination '{name}': {e}")
            raise
    
    def configure_awssm_destination(self, name: str, region: str, secretpath: str, 
                                   aws_accessid: str, aws_secretkey: str, iamrole: Optional[str] = None):
        """
        Configure AWS Secrets Manager destination using app-specific endpoint.
        
        Args:
            name: Destination name
            region: AWS region
            secretpath: Secret path in AWS Secrets Manager
            aws_accessid: AWS Access Key ID
            aws_secretkey: AWS Secret Access Key
            iamrole: Optional IAM role ARN
        """
        endpoint = f"{APP_NAME}_dest_awssm"
        
        try:
            # Delete existing destination if it exists (to allow overwriting)
            self._delete_destination(endpoint, name)
            
            payload = {
                'name': name,
                'region': region,
                'secretpath': secretpath,
                'aws_accessid': aws_accessid,
                'aws_secretkey': aws_secretkey,
                'limit_role': 'sc_admin|user'
            }
            
            if iamrole:
                payload['iamrole'] = iamrole
            
            response = self.service.post(
                endpoint,
                owner='nobody',
                app=APP_NAME,
                **payload
            )
            
            if response.status in [200, 201]:
                logger.info(f"Successfully configured AWS Secrets Manager destination: {name}")
            else:
                logger.warning(f"Unexpected status code {response.status} when configuring AWS Secrets Manager destination: {name}")
            
        except HTTPError as e:
            if e.status == 404:
                logger.error(f"App '{APP_NAME}' or endpoint '{endpoint}' not found.")
            elif e.status == 409:
                # Conflict - try deleting and retrying once
                logger.info(f"Destination '{name}' already exists, deleting and retrying...")
                self._delete_destination(endpoint, name, delay_after_delete=3.0)
                response = self.service.post(
                    endpoint,
                    owner='nobody',
                    app=APP_NAME,
                    **payload
                )
                if response.status in [200, 201]:
                    logger.info(f"Successfully configured AWS Secrets Manager destination: {name} (after retry)")
                else:
                    raise Exception(f"Failed to configure AWS Secrets Manager destination '{name}' after retry: HTTP {response.status}")
            else:
                raise Exception(f"Failed to configure AWS Secrets Manager destination '{name}': {e}") from e
        except Exception as e:
            logger.error(f"Failed to configure AWS Secrets Manager destination '{name}': {e}")
            raise
    
    def configure_1password_destination(self, name: str, vault: str, item_title: str, 
                                      item_field: str, service_account_token: str):
        """
        Configure 1Password destination.
        
        Args:
            name: Destination name
            vault: 1Password vault name
            item_title: Item title in 1Password
            item_field: Field name to store token in
            service_account_token: 1Password service account token
        """
        endpoint = f"{APP_NAME}_dest_1password"
        
        logger.debug(f"Configuring 1Password destination '{name}'")
        logger.debug(f"  Vault: {vault}")
        logger.debug(f"  Item title: {item_title}")
        logger.debug(f"  Item field: {item_field}")
        logger.debug(f"  Service account token present: {bool(service_account_token)}")
        
        try:
            # Delete existing destination if it exists (to allow overwriting)
            self._delete_destination(endpoint, name)
            
            payload = {
                'name': name,
                'vault': vault,
                'item_title': item_title,
                'item_field': item_field,
                'service_account_token': service_account_token,
                'limit_role': 'sc_admin|user'
            }
            
            logger.debug(f"POST request to endpoint: servicesNS/nobody/{APP_NAME}/{endpoint}")
            logger.debug(f"  Payload keys: {list(payload.keys())}")
            
            response = self.service.post(
                endpoint,
                owner='nobody',
                app=APP_NAME,
                **payload
            )
            
            logger.debug(f"Response status: {response.status}")
            
            if response.status in [200, 201]:
                logger.info(f"Successfully configured 1Password destination: {name}")
            else:
                logger.warning(f"Unexpected status code {response.status} when configuring 1Password destination: {name}")
                if hasattr(response, 'body'):
                    logger.debug(f"Response body: {response.body}")
            
        except HTTPError as e:
            if e.status == 404:
                logger.error(f"App '{APP_NAME}' or endpoint '{endpoint}' not found.")
            elif e.status == 409:
                # Conflict - try deleting and retrying once
                logger.info(f"Destination '{name}' already exists, deleting and retrying...")
                self._delete_destination(endpoint, name, delay_after_delete=3.0)
                response = self.service.post(
                    endpoint,
                    owner='nobody',
                    app=APP_NAME,
                    **payload
                )
                if response.status in [200, 201]:
                    logger.info(f"Successfully configured 1Password destination: {name} (after retry)")
                else:
                    raise Exception(f"Failed to configure 1Password destination '{name}' after retry: HTTP {response.status}")
            else:
                raise Exception(f"Failed to configure 1Password destination '{name}': {e}") from e
        except Exception as e:
            logger.error(f"Failed to configure 1Password destination '{name}': {e}")
            raise
    
    def configure_all_test_destinations(self, env_vars: Dict[str, str]):
        """
        Configure all test destinations from environment variables.
        
        Args:
            env_vars: Dictionary of environment variables
        """
        logger.info("Configuring all test destinations...")
        
        # Configure GitHub destination
        if env_vars.get('GITHUB_REPO') and env_vars.get('GITHUB_TOKEN'):
            # Extract user from GITHUB_USER env var or use default test user
            github_user = env_vars.get('GITHUB_USER', 'test_github_user')
            self.configure_github_destination(
                name='test_github',
                repo=env_vars['GITHUB_REPO'],
                secret_name='SPLUNK_TOKEN',
                token=env_vars['GITHUB_TOKEN'],
                user=github_user
            )
        
        # Configure GitLab destination
        if env_vars.get('GITLAB_PROJECT_URL') and env_vars.get('GITLAB_TOKEN'):
            # Extract hostname and project ID from URL
            # Format: https://gitlab.com/owner/project or just owner/project
            gitlab_url = env_vars['GITLAB_PROJECT_URL']
            if '://' in gitlab_url:
                # Full URL: https://gitlab.com/owner/project
                hostname = gitlab_url.split('://')[1].split('/')[0]
                project_path = '/'.join(gitlab_url.split('://')[1].split('/')[1:])
            else:
                # Just project path: owner/project (default to gitlab.com)
                hostname = 'gitlab.com'
                project_path = gitlab_url
            
            # For now, use project_path as projectid (may need to convert to numeric ID)
            self.configure_gitlab_destination(
                name='test_gitlab',
                hostname=hostname,
                projectid=project_path,  # May need to convert to numeric ID
                token=env_vars['GITLAB_TOKEN']
            )
        
        # Configure AWS Secrets Manager destination
        if (env_vars.get('AWS_ACCESS_KEY_ID') and 
            env_vars.get('AWS_SECRET_ACCESS_KEY') and 
            env_vars.get('AWS_DEFAULT_REGION')):
            self.configure_awssm_destination(
                name='test_awssm',
                region=env_vars['AWS_DEFAULT_REGION'],
                secretpath=env_vars.get('AWS_SECRET_NAME', 'splunk/test-token'),
                aws_accessid=env_vars['AWS_ACCESS_KEY_ID'],
                aws_secretkey=env_vars['AWS_SECRET_ACCESS_KEY']
            )
        
        # Configure 1Password destination
        if env_vars.get('OP_SERVICE_ACCOUNT_TOKEN'):
            logger.info("Configuring 1Password destination...")
            try:
                self.configure_1password_destination(
                    name='test_1password',
                    vault=env_vars.get('OP_VAULT_NAME', 'cicd'),
                    item_title='test-splunk-token',
                    item_field='password',
                    service_account_token=env_vars['OP_SERVICE_ACCOUNT_TOKEN']
                )
                logger.info("1Password destination configuration completed")
            except Exception as e:
                logger.error(f"Failed to configure 1Password destination: {e}")
                logger.error("This may be due to:")
                logger.error("  1. Missing OP_SERVICE_ACCOUNT_TOKEN environment variable")
                logger.error("  2. Invalid 1Password service account token")
                logger.error("  3. App endpoint not found or not installed")
                raise
        else:
            logger.info("Skipping 1Password destination (OP_SERVICE_ACCOUNT_TOKEN not set)")
        
        logger.info("All destinations configured successfully")


def main():
    """Main entry point."""
    # Get host from environment variables (check SPLUNKCLOUD_STACK_URL first, then SPLUNK_HOST)
    default_host = os.getenv('SPLUNKCLOUD_STACK_URL') or os.getenv('SPLUNK_HOST') or 'localhost'
    
    parser = argparse.ArgumentParser(description='Configure app destinations in Splunk')
    parser.add_argument('--host', default=default_host,
                       help='Splunk hostname (defaults to SPLUNKCLOUD_STACK_URL, SPLUNK_HOST, or localhost)')
    parser.add_argument('--port', type=int, default=int(os.getenv('SPLUNK_PORT', '8089')),
                       help='Splunk management port')
    parser.add_argument('--username', default=os.getenv('SPLUNKCLOUD_ADMIN_USER', 'admin'),
                       help='Admin username')
    parser.add_argument('--password', default=os.getenv('SPLUNKCLOUD_ADMIN_PASSWORD'),
                       help='Admin password')
    parser.add_argument('--scheme', choices=['http', 'https'], default='https',
                       help='HTTP scheme')
    parser.add_argument('--from-env', action='store_true',
                       help='Configure from environment variables')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose/debug output')
    
    args = parser.parse_args()
    
    # Set logging level based on verbose flag
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)
        logger.setLevel(logging.INFO)
    
    if not args.password:
        logger.error("Password required. Set SPLUNKCLOUD_ADMIN_PASSWORD or use --password")
        sys.exit(1)
    
    # Log connection details (mask password)
    connection_url = f"{args.scheme}://{args.host}:{args.port}"
    
    # Show which environment variables were used
    env_source = []
    if os.getenv('SPLUNKCLOUD_STACK_URL'):
        env_source.append(f"SPLUNKCLOUD_STACK_URL={os.getenv('SPLUNKCLOUD_STACK_URL')}")
    if os.getenv('SPLUNK_HOST'):
        env_source.append(f"SPLUNK_HOST={os.getenv('SPLUNK_HOST')}")
    if os.getenv('SPLUNK_PORT'):
        env_source.append(f"SPLUNK_PORT={os.getenv('SPLUNK_PORT')}")
    
    # Determine host source for logging
    host_source = "command line"
    if args.host == default_host:
        if os.getenv('SPLUNKCLOUD_STACK_URL'):
            host_source = "SPLUNKCLOUD_STACK_URL"
        elif os.getenv('SPLUNK_HOST'):
            host_source = "SPLUNK_HOST"
        else:
            host_source = "default (localhost)"
    
    logger.info("=" * 60)
    logger.info("Attempting to connect to Splunk instance:")
    if env_source:
        logger.info(f"  Environment variables detected: {', '.join(env_source)}")
    logger.info(f"  URL: {connection_url}")
    logger.info(f"  Scheme: {args.scheme}")
    logger.info(f"  Host: {args.host} (source: {host_source})")
    logger.info(f"  Port: {args.port}")
    logger.info(f"  Username: {args.username}")
    logger.info(f"  Password: {'*' * len(args.password) if args.password else 'NOT SET'}")
    logger.info("=" * 60)
    
    try:
        logger.debug("Calling client.connect()...")
        # Connect to Splunk
        service = client.connect(
            host=args.host,
            port=args.port,
            username=args.username,
            password=args.password,
            scheme=args.scheme
        )
        logger.info("=" * 60)
        logger.info("✓ Successfully connected to Splunk!")
        logger.info(f"  Connection URL: {connection_url}")
        logger.info(f"  Session token: {service.token[:20]}..." if service.token else "  Session token: None")
        logger.debug(f"  Full service object: {service}")
        logger.info("=" * 60)
        
        # Verify connection by getting server info (non-fatal - connection may still work)
        try:
            server_info = service.info
            logger.info(f"Verified connection - Splunk version: {server_info.get('version', 'unknown')}")
            logger.debug(f"Full server info: {server_info}")
        except HTTPError as e:
            if e.status == 401:
                logger.warning("Session verification failed with 401, but connection was established.")
                logger.warning("This may be normal for Splunk Cloud - will attempt to proceed with operations.")
                logger.debug(f"Verification error details: {e}")
            else:
                logger.warning(f"Could not verify connection (HTTP {e.status}): {e.reason}")
                logger.debug(f"Verification error details: {e}")
        except Exception as e:
            logger.warning(f"Could not retrieve server info (connection may still be valid): {e}")
            logger.debug(f"Verification error type: {type(e).__name__}")
            import traceback
            logger.debug(f"Verification traceback:\n{traceback.format_exc()}")
        
        configurator = AppDestinationConfigurator(service)
        
        if args.from_env:
            # Configure from environment variables
            env_vars = {
                'GITHUB_REPO': os.getenv('GITHUB_REPO'),
                'GITHUB_TOKEN': os.getenv('GITHUB_TOKEN'),
                'GITHUB_USER': os.getenv('GITHUB_USER', 'test_github_user'),
                'GITLAB_PROJECT_URL': os.getenv('GITLAB_PROJECT_URL'),
                'GITLAB_TOKEN': os.getenv('GITLAB_TOKEN'),
                'AWS_ACCESS_KEY_ID': os.getenv('AWS_ACCESS_KEY_ID'),
                'AWS_SECRET_ACCESS_KEY': os.getenv('AWS_SECRET_ACCESS_KEY'),
                'AWS_DEFAULT_REGION': os.getenv('AWS_DEFAULT_REGION'),
                'AWS_SECRET_NAME': os.getenv('AWS_SECRET_NAME', 'splunk/test-token'),
                'OP_SERVICE_ACCOUNT_TOKEN': os.getenv('OP_SERVICE_ACCOUNT_TOKEN'),
                'OP_VAULT_NAME': os.getenv('OP_VAULT_NAME', 'cicd')
            }
            configurator.configure_all_test_destinations(env_vars)
        else:
            logger.info("Use --from-env to configure from environment variables")
            logger.info("Or implement specific configuration calls here")
    
    except HTTPError as e:
        logger.error("=" * 60)
        logger.error("✗ Connection failed with HTTP error:")
        logger.error(f"  Status Code: {e.status}")
        logger.error(f"  Reason: {e.reason}")
        logger.error(f"  URL: {connection_url}")
        logger.error(f"  Details: {e}")
        if hasattr(e, 'body'):
            logger.error(f"  Response body: {e.body}")
        logger.error("=" * 60)
        logger.error("Troubleshooting tips:")
        logger.error("  1. Verify the hostname/IP address is correct")
        logger.error("  2. Check that the port is correct (8089 for management port)")
        logger.error("  3. Verify username and password are correct")
        logger.error("  4. Check network connectivity to the Splunk instance")
        logger.error("  5. Verify SSL certificate if using HTTPS")
        sys.exit(1)
    except Exception as e:
        logger.error("=" * 60)
        logger.error("✗ Connection failed with error:")
        logger.error(f"  Error type: {type(e).__name__}")
        logger.error(f"  Error message: {str(e)}")
        logger.error(f"  Connection URL attempted: {connection_url}")
        logger.error(f"  Username: {args.username}")
        import traceback
        logger.debug(f"  Full traceback:\n{traceback.format_exc()}")
        logger.error("=" * 60)
        sys.exit(1)


if __name__ == '__main__':
    main()


#!/usr/bin/env python
# coding=utf-8
"""
Create test accounts in Splunk for automated testing.

Creates test users for each destination type (GitHub, GitLab, AWS Secrets Manager, 1Password)
with appropriate roles and permissions.
"""

import os
import sys
import argparse
import logging
from typing import Dict, Optional

try:
    import splunklib.client as client
    from splunklib.binding import HTTPError
except ImportError:
    print("Error: splunklib not found. Install with: pip install splunk-sdk", file=sys.stderr)
    sys.exit(1)

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s'
)
logger = logging.getLogger(__name__)


class SplunkAccountManager:
    """Manages test account creation in Splunk."""
    
    def __init__(self, host: str, port: int, username: str, password: str, scheme: str = 'https'):
        """
        Initialize Splunk connection.
        
        Args:
            host: Splunk hostname
            port: Splunk management port (default 8089)
            username: Admin username
            password: Admin password
            scheme: HTTP scheme (https or http)
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.scheme = scheme
        
        connection_url = f"{scheme}://{host}:{port}"
        logger.debug(f"SplunkAccountManager initializing connection:")
        logger.debug(f"  URL: {connection_url}")
        logger.debug(f"  Scheme: {scheme}")
        logger.debug(f"  Host: {host}")
        logger.debug(f"  Port: {port}")
        logger.debug(f"  Username: {username}")
        logger.debug(f"  Password: {'*' * len(password) if password else 'NOT SET'}")
        
        try:
            logger.debug("Calling client.connect()...")
            self.service = client.connect(
                host=host,
                port=port,
                username=username,
                password=password,
                scheme=scheme
            )
            logger.info("=" * 60)
            logger.info("✓ Successfully connected to Splunk!")
            logger.info(f"  Connection URL: {connection_url}")
            logger.info(f"  Session token: {self.service.token[:20]}..." if self.service.token else "  Session token: None")
            logger.debug(f"  Full service object: {self.service}")
            logger.info("=" * 60)
            
            # Verify connection by getting server info (non-fatal - connection may still work)
            try:
                server_info = self.service.info
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
            raise
        except Exception as e:
            logger.error("=" * 60)
            logger.error("✗ Connection failed with error:")
            logger.error(f"  Error type: {type(e).__name__}")
            logger.error(f"  Error message: {str(e)}")
            logger.error(f"  Connection URL attempted: {connection_url}")
            logger.error(f"  Username: {username}")
            import traceback
            logger.debug(f"  Full traceback:\n{traceback.format_exc()}")
            logger.error("=" * 60)
            raise
    
    def user_exists(self, username: str) -> bool:
        """Check if a user exists."""
        try:
            self.service.users[username]
            return True
        except KeyError:
            return False
        except HTTPError as e:
            if e.status == 404:
                return False
            logger.warning(f"Error checking if user exists (HTTP {e.status}): {e.reason}")
            return False
        except Exception as e:
            logger.warning(f"Error checking if user exists: {e}")
            return False
    
    def create_user(self, username: str, password: str, roles: list = None, email: str = None) -> bool:
        """
        Create a new user in Splunk.
        
        Args:
            username: Username
            password: Password
            roles: List of roles to assign (default: ['user'])
            email: Email address (optional)
        
        Returns:
            True if created successfully, False otherwise
        """
        if roles is None:
            roles = ['user']
        
        if self.user_exists(username):
            logger.info(f"User '{username}' already exists, skipping creation")
            return True
        
        try:
            kwargs = {
                'password': password,
                'roles': roles
            }
            if email:
                kwargs['email'] = email
            
            logger.debug(f"Attempting to create user '{username}' with roles: {roles}")
            self.service.users.create(username, **kwargs)
            logger.info(f"User creation request completed for '{username}'")
            
            # Wait a moment for user to be available (Splunk Cloud may have propagation delay)
            import time
            time.sleep(1)
            
            # Verify user was actually created
            if self.user_exists(username):
                logger.info(f"Successfully created and verified user '{username}' with roles: {', '.join(roles)}")
                return True
            else:
                logger.warning(f"User creation request succeeded but user '{username}' not found after creation")
                logger.warning("This may indicate:")
                logger.warning("  1. Splunk Cloud restrictions on user creation via REST API")
                logger.warning("  2. Insufficient permissions for the authenticated user")
                logger.warning("  3. User creation requires admin console or different method")
                logger.warning(f"  4. Propagation delay - user may appear later")
                return False
                
        except HTTPError as e:
            if e.status == 409:
                logger.info(f"User '{username}' already exists")
                return True
            elif e.status == 403:
                logger.error(f"Permission denied creating user '{username}' (HTTP 403)")
                logger.error("Splunk Cloud may restrict user creation via REST API")
                logger.error("Users may need to be created through the Splunk Cloud admin console")
                if hasattr(e, 'body'):
                    logger.debug(f"Response body: {e.body}")
                return False
            elif e.status == 404:
                logger.error(f"User creation failed - user not found after creation (HTTP 404)")
                logger.error("This may indicate Splunk Cloud restrictions on user creation")
                if hasattr(e, 'body'):
                    logger.debug(f"Response body: {e.body}")
                return False
            else:
                logger.error(f"Failed to create user '{username}' (HTTP {e.status}): {e.reason}")
                logger.error(f"Details: {e}")
                if hasattr(e, 'body'):
                    logger.debug(f"Response body: {e.body}")
                return False
        except Exception as e:
            logger.error(f"Error creating user '{username}': {e}")
            import traceback
            logger.debug(f"Full traceback:\n{traceback.format_exc()}")
            return False
    
    def ensure_role_exists(self, role_name: str) -> bool:
        """Ensure a role exists, create it if it doesn't."""
        try:
            self.service.roles[role_name]
            logger.debug(f"Role '{role_name}' already exists")
            return True
        except KeyError:
            try:
                self.service.roles.create(role_name)
                logger.info(f"Created role '{role_name}'")
                return True
            except Exception as e:
                logger.warning(f"Could not create role '{role_name}': {e}")
                return False
    
    def create_test_accounts(self, base_password: str = "Test123!@#") -> Dict[str, Dict]:
        """
        Create all test accounts for different destination types.
        
        Args:
            base_password: Base password for test accounts
        
        Returns:
            Dictionary mapping account type to account info
        """
        accounts = {}
        
        # Test accounts configuration
        test_accounts = [
            {
                'username': 'test_github_user',
                'roles': ['sc_admin', 'user'],
                'description': 'Test user for GitHub token generation'
            },
            {
                'username': 'test_gitlab_user',
                'roles': ['sc_admin', 'user'],
                'description': 'Test user for GitLab token generation'
            },
            {
                'username': 'test_awssm_user',
                'roles': ['sc_admin', 'user'],
                'description': 'Test user for AWS Secrets Manager token generation'
            },
            {
                'username': 'test_1password_user',
                'roles': ['sc_admin', 'user'],
                'description': 'Test user for 1Password token generation'
            }
        ]
        
        # Ensure sc_admin role exists
        self.ensure_role_exists('sc_admin')
        
        # Create each test account
        for account_config in test_accounts:
            username = account_config['username']
            roles = account_config['roles']
            
            # Use username-specific password
            password = f"{base_password}_{username}"
            
            success = self.create_user(
                username=username,
                password=password,
                roles=roles,
                email=f"{username}@test.local"
            )
            
            if success:
                accounts[username] = {
                    'username': username,
                    'password': password,
                    'roles': roles,
                    'description': account_config.get('description', '')
                }
                logger.info(f"Successfully created/verified account: {username}")
            else:
                logger.error(f"Failed to create account: {username}")
        
        return accounts
    
    def delete_user(self, username: str) -> bool:
        """Delete a user (for cleanup)."""
        try:
            if self.user_exists(username):
                self.service.users.delete(username)
                logger.info(f"Deleted user '{username}'")
                return True
            else:
                logger.info(f"User '{username}' does not exist")
                return True
        except Exception as e:
            logger.error(f"Error deleting user '{username}': {e}")
            return False
    
    def cleanup_test_accounts(self):
        """Delete all test accounts."""
        test_users = [
            'test_github_user',
            'test_gitlab_user',
            'test_awssm_user',
            'test_1password_user'
        ]
        
        for username in test_users:
            self.delete_user(username)


def main():
    """Main entry point."""
    # Get host from environment variables (check SPLUNKCLOUD_STACK_URL first, then SPLUNK_HOST)
    default_host = os.getenv('SPLUNKCLOUD_STACK_URL') or os.getenv('SPLUNK_HOST') or 'localhost'
    
    parser = argparse.ArgumentParser(description='Create test accounts in Splunk')
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
    parser.add_argument('--base-password', default='Test123!@#',
                       help='Base password for test accounts')
    parser.add_argument('--cleanup', action='store_true',
                       help='Delete test accounts instead of creating them')
    parser.add_argument('--output', help='Output file for account credentials (JSON)')
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
        manager = SplunkAccountManager(
            host=args.host,
            port=args.port,
            username=args.username,
            password=args.password,
            scheme=args.scheme
        )
        
        if args.cleanup:
            logger.info("Cleaning up test accounts...")
            manager.cleanup_test_accounts()
            logger.info("Cleanup complete")
        else:
            logger.info("Creating test accounts...")
            accounts = manager.create_test_accounts(base_password=args.base_password)
            
            if args.output:
                import json
                with open(args.output, 'w') as f:
                    json.dump(accounts, f, indent=2)
                logger.info(f"Account credentials written to {args.output}")
            else:
                import json
                print(json.dumps(accounts, indent=2))
            
            if len(accounts) == 0:
                logger.warning("=" * 60)
                logger.warning("No accounts were created successfully.")
                logger.warning("This may be due to:")
                logger.warning("  1. Splunk Cloud restrictions on user creation via REST API")
                logger.warning("  2. Insufficient permissions for the authenticated user")
                logger.warning("  3. Users may need to be created through Splunk Cloud admin console")
                logger.warning("=" * 60)
            else:
                logger.info(f"Successfully created {len(accounts)} test accounts")
    
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
        logger.error("✗ Failed with error:")
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


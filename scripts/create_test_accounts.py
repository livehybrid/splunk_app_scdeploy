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
        
        try:
            self.service = client.connect(
                host=host,
                port=port,
                username=username,
                password=password,
                scheme=scheme
            )
            logger.info(f"Connected to Splunk at {scheme}://{host}:{port}")
        except Exception as e:
            logger.error(f"Failed to connect to Splunk: {e}")
            raise
    
    def user_exists(self, username: str) -> bool:
        """Check if a user exists."""
        try:
            self.service.users[username]
            return True
        except KeyError:
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
            
            self.service.users.create(username, **kwargs)
            logger.info(f"Created user '{username}' with roles: {', '.join(roles)}")
            return True
        except HTTPError as e:
            if e.status == 409:
                logger.info(f"User '{username}' already exists")
                return True
            logger.error(f"Failed to create user '{username}': {e}")
            return False
        except Exception as e:
            logger.error(f"Error creating user '{username}': {e}")
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
    parser = argparse.ArgumentParser(description='Create test accounts in Splunk')
    parser.add_argument('--host', default=os.getenv('SPLUNK_HOST', 'localhost'),
                       help='Splunk hostname')
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
    
    args = parser.parse_args()
    
    if not args.password:
        logger.error("Password required. Set SPLUNKCLOUD_ADMIN_PASSWORD or use --password")
        sys.exit(1)
    
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
            
            logger.info(f"Created {len(accounts)} test accounts")
    
    except Exception as e:
        logger.error(f"Failed: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()


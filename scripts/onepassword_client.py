#!/usr/bin/env python
# coding=utf-8
"""
1Password Client Module

Provides functions to retrieve secrets from 1Password vault using either
the 1Password Connect API or the op CLI tool.
"""

import os
import json
import subprocess
import sys
from typing import Optional, Dict, Any


class OnePasswordClient:
    """Client for interacting with 1Password."""
    
    def __init__(self, service_account_token: Optional[str] = None):
        """
        Initialize 1Password client.
        
        Args:
            service_account_token: 1Password service account token.
                                  If None, reads from OP_SERVICE_ACCOUNT_TOKEN env var.
        """
        self.service_account_token = service_account_token or os.getenv('OP_SERVICE_ACCOUNT_TOKEN')
        if not self.service_account_token:
            raise ValueError(
                "1Password service account token required. "
                "Set OP_SERVICE_ACCOUNT_TOKEN environment variable or pass as argument."
            )
        
        # Try to detect which method to use
        self.use_cli = self._check_op_cli_available()
        self.connect_url = os.getenv('OP_CONNECT_HOST')
        self.connect_token = os.getenv('OP_CONNECT_TOKEN')
        
        if not self.use_cli and not self.connect_token:
            # Try using op CLI with service account token
            self.use_cli = True
    
    def _check_op_cli_available(self) -> bool:
        """Check if op CLI is available."""
        try:
            result = subprocess.run(
                ['op', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def get_secret(self, vault: str, item: str, field: str) -> str:
        """
        Retrieve a specific field from a 1Password item.
        
        Args:
            vault: Vault name
            item: Item name or UUID
            field: Field name (e.g., 'username', 'password', 'url')
        
        Returns:
            Field value as string
        
        Raises:
            ValueError: If field not found or item doesn't exist
            RuntimeError: If unable to retrieve secret
        """
        if self.use_cli:
            return self._get_secret_via_cli(vault, item, field)
        else:
            return self._get_secret_via_connect(vault, item, field)
    
    def _get_secret_via_cli(self, vault: str, item: str, field: str) -> str:
        """Retrieve secret using op CLI."""
        try:
            # Use op CLI with service account token
            env = os.environ.copy()
            env['OP_SERVICE_ACCOUNT_TOKEN'] = self.service_account_token
            
            # Get item reference
            cmd = [
                'op', 'item', 'get', item,
                '--vault', vault,
                '--format', 'json'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env=env,
                timeout=30
            )
            
            if result.returncode != 0:
                raise RuntimeError(
                    f"Failed to retrieve item '{item}' from vault '{vault}': {result.stderr}"
                )
            
            item_data = json.loads(result.stdout)
            
            # Extract field value
            if 'fields' in item_data:
                for f in item_data['fields']:
                    if f.get('id') == field or f.get('label', '').lower() == field.lower():
                        if 'value' in f:
                            return f['value']
            
            # Try sections if field not found in top-level fields
            if 'sections' in item_data:
                for section in item_data.get('sections', []):
                    for f in section.get('fields', []):
                        if f.get('id') == field or f.get('label', '').lower() == field.lower():
                            if 'value' in f:
                                return f['value']
            
            # Common field mappings
            field_mappings = {
                'username': ['username'],
                'password': ['password', 'credential'],
                'url': ['url', 'website', 'hostname']
            }
            
            for f in item_data.get('fields', []):
                label_lower = f.get('label', '').lower()
                if label_lower in field_mappings.get(field.lower(), []):
                    if 'value' in f:
                        return f['value']
            
            raise ValueError(
                f"Field '{field}' not found in item '{item}' from vault '{vault}'"
            )
            
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Invalid JSON response from 1Password: {e}")
        except subprocess.TimeoutExpired:
            raise RuntimeError("Timeout while retrieving secret from 1Password")
        except Exception as e:
            raise RuntimeError(f"Error retrieving secret: {str(e)}")
    
    def _get_secret_via_connect(self, vault: str, item: str, field: str) -> str:
        """Retrieve secret using 1Password Connect API."""
        try:
            import requests
            
            # Get vault UUID
            vault_uuid = self._get_vault_uuid(vault)
            
            # Get item UUID
            item_uuid = self._get_item_uuid(vault_uuid, item)
            
            # Get item details
            headers = {
                'Authorization': f'Bearer {self.connect_token}',
                'Content-Type': 'application/json'
            }
            
            url = f"{self.connect_url}/v1/vaults/{vault_uuid}/items/{item_uuid}"
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            
            item_data = response.json()
            
            # Extract field value
            for f in item_data.get('fields', []):
                if f.get('id') == field or f.get('label', '').lower() == field.lower():
                    return f.get('value', '')
            
            raise ValueError(
                f"Field '{field}' not found in item '{item}' from vault '{vault}'"
            )
            
        except ImportError:
            raise RuntimeError("requests library required for Connect API. Install with: pip install requests")
        except Exception as e:
            raise RuntimeError(f"Error retrieving secret via Connect API: {str(e)}")
    
    def get_login_item(self, vault: str, item: str) -> Dict[str, str]:
        """
        Retrieve entire login item (username, password, url).
        
        Args:
            vault: Vault name
            item: Item name or UUID
        
        Returns:
            Dictionary with 'username', 'password', and 'url' keys
        """
        result = {}
        
        # Try to get common fields
        for field in ['username', 'password', 'url']:
            try:
                value = self.get_secret(vault, item, field)
                if value:
                    result[field] = value
            except ValueError:
                # Field might not exist, continue
                pass
        
        # If we got at least one field, return it
        if result:
            return result
        
        # Fallback: try to get the item and parse it
        if self.use_cli:
            try:
                env = os.environ.copy()
                env['OP_SERVICE_ACCOUNT_TOKEN'] = self.service_account_token
                
                cmd = [
                    'op', 'item', 'get', item,
                    '--vault', vault,
                    '--format', 'json'
                ]
                
                result_cmd = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    env=env,
                    timeout=30
                )
                
                if result_cmd.returncode == 0:
                    item_data = json.loads(result_cmd.stdout)
                    
                    # Extract all fields
                    for f in item_data.get('fields', []):
                        label = f.get('label', '').lower()
                        value = f.get('value', '')
                        
                        if label in ['username', 'user']:
                            result['username'] = value
                        elif label in ['password', 'credential']:
                            result['password'] = value
                        elif label in ['url', 'website', 'hostname', 'server']:
                            result['url'] = value
                    
                    return result
            except Exception:
                pass
        
        raise ValueError(
            f"Unable to retrieve login item '{item}' from vault '{vault}'. "
            "Ensure the item exists and contains username, password, and/or url fields."
        )
    
    def _get_vault_uuid(self, vault_name: str) -> str:
        """Get vault UUID from vault name (Connect API only)."""
        import requests
        
        headers = {
            'Authorization': f'Bearer {self.connect_token}',
            'Content-Type': 'application/json'
        }
        
        url = f"{self.connect_url}/v1/vaults"
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        
        vaults = response.json()
        for vault in vaults:
            if vault.get('name') == vault_name:
                return vault.get('id')
        
        raise ValueError(f"Vault '{vault_name}' not found")
    
    def _get_item_uuid(self, vault_uuid: str, item_name: str) -> str:
        """Get item UUID from item name (Connect API only)."""
        import requests
        
        headers = {
            'Authorization': f'Bearer {self.connect_token}',
            'Content-Type': 'application/json'
        }
        
        url = f"{self.connect_url}/v1/vaults/{vault_uuid}/items"
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        
        items = response.json()
        for item in items:
            if item.get('title') == item_name:
                return item.get('id')
        
        raise ValueError(f"Item '{item_name}' not found in vault")


def get_secret(vault: str, item: str, field: str, service_account_token: Optional[str] = None) -> str:
    """
    Convenience function to retrieve a secret from 1Password.
    
    Args:
        vault: Vault name
        item: Item name or UUID
        field: Field name
        service_account_token: Optional service account token
    
    Returns:
        Field value as string
    """
    client = OnePasswordClient(service_account_token)
    return client.get_secret(vault, item, field)


def get_login_item(vault: str, item: str, service_account_token: Optional[str] = None) -> Dict[str, str]:
    """
    Convenience function to retrieve a login item from 1Password.
    
    Args:
        vault: Vault name
        item: Item name or UUID
        service_account_token: Optional service account token
    
    Returns:
        Dictionary with login credentials
    """
    client = OnePasswordClient(service_account_token)
    return client.get_login_item(vault, item)


if __name__ == '__main__':
    """CLI interface for testing."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Retrieve secrets from 1Password')
    parser.add_argument('vault', help='Vault name')
    parser.add_argument('item', help='Item name')
    parser.add_argument('--field', help='Specific field to retrieve')
    parser.add_argument('--token', help='Service account token (or use OP_SERVICE_ACCOUNT_TOKEN env var)')
    
    args = parser.parse_args()
    
    try:
        if args.field:
            value = get_secret(args.vault, args.item, args.field, args.token)
            print(value)
        else:
            item_data = get_login_item(args.vault, args.item, args.token)
            print(json.dumps(item_data, indent=2))
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


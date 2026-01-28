#!/usr/bin/env python
# coding=utf-8
"""
Obtain a long-lived Splunk authentication token for CI/CD and automation.

Uses username/password to login once, then creates a token via the Splunk REST API.
The token can be reused across multiple script invocations (create_test_accounts,
configure_app_destinations, generate_test_tokens) without session expiry issues.

Usage:
  python3 scripts/obtain_splunk_token.py
  # Outputs: SPLUNK_TOKEN=<token> (for eval or export)

  # In GitHub Actions:
  - name: Obtain Splunk token
    run: |
      echo "SPLUNK_TOKEN=$(python3 scripts/obtain_splunk_token.py)" >> $GITHUB_ENV
"""

import os
import sys
import argparse
import logging

try:
    import splunklib.client as client
    from splunklib.binding import HTTPError
except ImportError:
    print("Error: splunklib not found. Install with: pip install splunk-sdk", file=sys.stderr)
    sys.exit(1)

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)


def get_default_host():
    """Get host from SPLUNKCLOUD_STACK_URL or SPLUNK_HOST."""
    return os.getenv('SPLUNKCLOUD_STACK_URL') or os.getenv('SPLUNK_HOST') or 'localhost'


def obtain_token(
    host: str = None,
    port: int = None,
    username: str = None,
    password: str = None,
    scheme: str = 'https',
    token_name: str = 'splunk_app_scdeploy_ci',
    token_lifetime: int = 86400,  # 24 hours in seconds
) -> str:
    """
    Login with username/password and create a long-lived token.
    
    Returns:
        The token string.
    """
    host = host or get_default_host()
    port = port or int(os.getenv('SPLUNK_PORT', '8089'))
    username = username or os.getenv('SPLUNKCLOUD_ADMIN_USER', 'admin')
    password = password or os.getenv('SPLUNKCLOUD_ADMIN_PASSWORD')
    
    if not password:
        raise ValueError("Password required. Set SPLUNKCLOUD_ADMIN_PASSWORD or use --password")
    
    # Step 1: Connect with username/password to get a session
    service = client.connect(
        host=host,
        port=port,
        username=username,
        password=password,
        scheme=scheme
    )
    
    session_key = service.token
    if not session_key:
        raise RuntimeError("Login succeeded but no session key returned")
    
    # Step 2: Create a long-lived token via REST API
    # Use same endpoint as app: /services/authorization/tokens/create
    # Parameters: name (user), audience, expires_on (e.g. "+24h")
    token_endpoint = "authorization/tokens/create"
    expires_on = f"+{token_lifetime}s" if token_lifetime else "+24h"
    
    try:
        response = service.post(
            token_endpoint,
            name=username,
            audience=token_name,
            expires_on=expires_on,
        )
    except HTTPError as e:
        if e.status == 404:
            raise RuntimeError(
                "Token API not found (404). Token authentication may not be enabled on this Splunk instance."
            ) from e
        if e.status == 403:
            raise RuntimeError(
                "Permission denied creating token. User may need admin or token creation capability."
            ) from e
        raise RuntimeError(f"Failed to create token: {e}") from e
    
    # Parse response - splunklib returns Atom-style response
    token_value = None
    try:
        import splunklib.client as _client
        output_record = _client._load_atom(response)
        if (
            "content" in output_record.get("feed", {}).get("entry", {})
            and "token" in output_record["feed"]["entry"]["content"]
        ):
            token_value = output_record["feed"]["entry"]["content"]["token"]
    except Exception as parse_err:
        logger.debug(f"Parse response: {parse_err}")
    
    if not token_value and hasattr(response, 'body'):
        import re
        body = response.body
        if isinstance(body, bytes):
            body = body.decode('utf-8')
        match = re.search(r'<k name="token">([^<]+)</k>', body)
        if match:
            token_value = match.group(1)
    
    if not token_value:
        raise RuntimeError(
            "Token was created but could not be read from response. "
            "Check Splunk token API response format."
        )
    
    return token_value


def main():
    parser = argparse.ArgumentParser(description='Obtain a long-lived Splunk token')
    parser.add_argument('--host', default=get_default_host(),
                        help='Splunk host')
    parser.add_argument('--port', type=int, default=int(os.getenv('SPLUNK_PORT', '8089')),
                        help='Splunk port')
    parser.add_argument('--username', default=os.getenv('SPLUNKCLOUD_ADMIN_USER', 'admin'),
                        help='Admin username')
    parser.add_argument('--password', default=os.getenv('SPLUNKCLOUD_ADMIN_PASSWORD'),
                        help='Admin password')
    parser.add_argument('--scheme', choices=['http', 'https'], default='https')
    parser.add_argument('--token-name', default='splunk_app_scdeploy_ci',
                        help='Name for the created token')
    parser.add_argument('--lifetime', type=int, default=86400,
                        help='Token lifetime in seconds (default: 86400 = 24h)')
    parser.add_argument('--format', choices=['raw', 'env'], default='raw',
                        help='Output format: raw (token only) or env (SPLUNK_TOKEN=...)')
    parser.add_argument('--verbose', '-v', action='store_true')
    
    args = parser.parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)
    
    if not args.password:
        print("Error: Password required. Set SPLUNKCLOUD_ADMIN_PASSWORD or use --password", file=sys.stderr)
        sys.exit(1)
    
    try:
        token = obtain_token(
            host=args.host,
            port=args.port,
            username=args.username,
            password=args.password,
            scheme=args.scheme,
            token_name=args.token_name,
            token_lifetime=args.lifetime,
        )
        if args.format == 'env':
            print(f"SPLUNK_TOKEN={token}")
        else:
            print(token)
    except Exception as e:
        logger.exception(str(e))
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()

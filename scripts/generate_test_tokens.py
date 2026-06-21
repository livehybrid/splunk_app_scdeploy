#!/usr/bin/env python
# coding=utf-8
"""
Generate test tokens for all destination types.

Executes Splunk searches to generate tokens for GitHub, GitLab, AWS Secrets Manager,
and 1Password destinations and captures the results.
"""

import os
import sys
import argparse
import logging
import json
import time
from typing import Dict, List, Optional

try:
    import splunklib.client as client
    import splunklib.results as results
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


class TokenGenerator:
    """Generates tokens for all destination types."""
    
    def __init__(self, service: client.Service, username: str = None, password: str = None, token: str = None):
        """
        Initialize token generator.
        
        Args:
            service: Connected Splunk service instance
            username: Username for re-authentication (optional, when not using token)
            password: Password for re-authentication (optional, when not using token)
            token: Long-lived Splunk token (optional; when set, used for connect/reconnect)
        """
        self.service = service
        self._username = username
        self._password = password
        self._token = token
        if token:
            self._connection_params = {
                'host': service.host,
                'port': service.port,
                'token': token,
                'scheme': service.scheme
            }
        else:
            self._connection_params = {
                'host': service.host,
                'port': service.port,
                'username': username,
                'password': password,
                'scheme': service.scheme
            }
        
        logger.debug(f"TokenGenerator initialized:")
        logger.debug(f"  Service scheme: {service.scheme}")
        logger.debug(f"  Service host: {service.host}")
        logger.debug(f"  Service port: {service.port}")
        logger.debug(f"  Session key present: {bool(service.token)}")
        logger.debug(f"  Session key length: {len(service.token) if service.token else 0}")
        
        # Verify connection by getting server info
        try:
            server_info = service.info
            logger.info(f"Verified connection - Splunk version: {server_info.get('version', 'unknown')}")
            logger.debug(f"Full server info: {server_info}")
        except Exception as e:
            logger.warning(f"Could not retrieve server info (connection may still be valid): {e}")
    
    def _ensure_session_valid(self):
        """
        Ensure the session is still valid, re-authenticate if needed.
        """
        try:
            # Try a simple operation to check if session is valid
            self.service.info
            logger.debug("Session is valid")
            return True
        except HTTPError as e:
            if e.status == 401:
                logger.warning("Session expired, attempting to re-authenticate...")
                # Re-authenticate with token or username/password
                if self._connection_params.get('token'):
                    try:
                        self.service = client.connect(**self._connection_params)
                        logger.info("Successfully re-authenticated with token")
                        return True
                    except Exception as reauth_error:
                        logger.error(f"Failed to re-authenticate with token: {reauth_error}")
                        raise Exception("Session expired and re-authentication failed") from reauth_error
                elif self._connection_params.get('username') and self._connection_params.get('password'):
                    try:
                        self.service = client.connect(**self._connection_params)
                        logger.info("Successfully re-authenticated")
                        return True
                    except Exception as reauth_error:
                        logger.error(f"Failed to re-authenticate: {reauth_error}")
                        raise Exception("Session expired and re-authentication failed") from reauth_error
                else:
                    logger.error("Session expired but no credentials available for re-authentication")
                    raise Exception("Session expired and cannot re-authenticate") from e
            else:
                raise
        except Exception as e:
            logger.warning(f"Error checking session validity: {e}")
            # Assume session is valid if we can't check
            return True
    
    def execute_search(self, search_query: str, timeout: int = 60) -> List[Dict]:
        """
        Execute a Splunk search and return results.
        
        Args:
            search_query: SPL search query
            timeout: Search timeout in seconds
        
        Returns:
            List of result dictionaries
        """
        try:
            # Ensure session is valid before executing search
            self._ensure_session_valid()
            
            logger.info(f"Executing search: {search_query}")
            logger.debug(f"  Timeout: {timeout} seconds")
            logger.debug(f"  Execution mode: blocking")
            
            # Create search job
            logger.debug("Creating search job...")
            job = self.service.jobs.create(search_query, **{"exec_mode": "blocking", "timeout": timeout})
            logger.debug(f"Search job created: {job.sid}")
            
            # Get results
            logger.debug("Retrieving search results...")
            result_list = []
            for result in results.ResultsReader(job.results()):
                if isinstance(result, dict):
                    result_list.append(result)
                    logger.debug(f"  Result: {result}")
                elif isinstance(result, results.Message):
                    logger.warning(f"Search message: {result}")
            
            logger.info(f"Search completed. Found {len(result_list)} results")
            return result_list
            
        except HTTPError as e:
            if e.status == 401:
                logger.warning("Session expired during search execution, attempting to re-authenticate...")
                # Try to re-authenticate and retry once
                if self._connection_params.get('username') and self._connection_params.get('password'):
                    try:
                        self.service = client.connect(**self._connection_params)
                        logger.info("Re-authenticated, retrying search...")
                        # Retry the search once
                        job = self.service.jobs.create(search_query, **{"exec_mode": "blocking", "timeout": timeout})
                        logger.debug(f"Search job created: {job.sid}")
                        
                        result_list = []
                        for result in results.ResultsReader(job.results()):
                            if isinstance(result, dict):
                                result_list.append(result)
                                logger.debug(f"  Result: {result}")
                            elif isinstance(result, results.Message):
                                logger.warning(f"Search message: {result}")
                        
                        logger.info(f"Search completed. Found {len(result_list)} results")
                        return result_list
                    except Exception as retry_error:
                        logger.error(f"Failed to re-authenticate and retry: {retry_error}")
                        raise Exception(f"Session expired and retry failed: {retry_error}") from retry_error
                else:
                    logger.error("Session expired but no credentials available for re-authentication")
                    raise Exception("Session expired and cannot re-authenticate") from e
            else:
                logger.error(f"HTTP error executing search (HTTP {e.status}): {e.reason}")
                if hasattr(e, 'body'):
                    logger.debug(f"Response body: {e.body}")
                raise
        except Exception as e:
            logger.error(f"Failed to execute search: {e}")
            logger.debug(f"Search query was: {search_query}")
            import traceback
            logger.debug(f"Full traceback:\n{traceback.format_exc()}")
            raise
    
    def generate_github_token(self, destination_name: str = "test_github", 
                              user: str = "test_github_user", 
                              expires_on: str = "+2h") -> Dict:
        """
        Generate token for GitHub destination.
        
        Args:
            destination_name: Destination configuration name
            user: User to generate token for
            expires_on: Token expiry time
        
        Returns:
            Token generation result
        """
        search = f'| gendeploytoken destination_type=github destination_name={destination_name} user={user} expires_on="{expires_on}"'
        results = self.execute_search(search)
        
        if results:
            return results[0]
        else:
            raise Exception("No results returned from GitHub token generation")
    
    def generate_gitlab_token(self, destination_name: str = "test_gitlab",
                             user: str = "test_gitlab_user",
                             gitlab_branch: str = "main",
                             expires_on: str = "+2h") -> Dict:
        """
        Generate token for GitLab destination.
        
        Args:
            destination_name: Destination configuration name
            user: User to generate token for
            gitlab_branch: GitLab branch to trigger
            expires_on: Token expiry time
        
        Returns:
            Token generation result
        """
        search = f'| gendeploytoken destination_type=gitlab destination_name={destination_name} user={user} gitlab_branch={gitlab_branch} expires_on="{expires_on}"'
        results = self.execute_search(search)
        
        if results:
            return results[0]
        else:
            raise Exception("No results returned from GitLab token generation")
    
    def generate_awssm_token(self, destination_name: str = "test_awssm",
                            user: str = "test_awssm_user",
                            expires_on: str = "+2h") -> Dict:
        """
        Generate token for AWS Secrets Manager destination.
        
        Args:
            destination_name: Destination configuration name
            user: User to generate token for
            expires_on: Token expiry time
        
        Returns:
            Token generation result
        """
        search = f'| gendeploytoken destination_type=awssm destination_name={destination_name} user={user} expires_on="{expires_on}"'
        results = self.execute_search(search)
        
        if results:
            return results[0]
        else:
            raise Exception("No results returned from AWS Secrets Manager token generation")
    
    def generate_1password_token(self, destination_name: str = "test_1password",
                                 user: str = "test_1password_user",
                                 expires_on: str = "+2h") -> Dict:
        """
        Generate token for 1Password destination.
        
        Args:
            destination_name: Destination configuration name
            user: User to generate token for
            expires_on: Token expiry time
        
        Returns:
            Token generation result
        """
        search = f'| gendeploytoken destination_type=1password destination_name={destination_name} user={user} expires_on="{expires_on}"'
        results = self.execute_search(search)
        
        if results:
            return results[0]
        else:
            raise Exception("No results returned from 1Password token generation")
    
    def generate_all_tokens(self, destinations: Optional[List[str]] = None) -> Dict[str, Dict]:
        """
        Generate tokens for all configured destinations.
        
        Args:
            destinations: List of destination types to test (None = all)
        
        Returns:
            Dictionary mapping destination type to result
        """
        all_destinations = ['github', 'gitlab', 'awssm', '1password']
        
        if destinations is None:
            destinations = all_destinations
        
        results = {}
        
        for dest_type in destinations:
            if dest_type not in all_destinations:
                logger.warning(f"Unknown destination type: {dest_type}")
                continue
            
            try:
                logger.info(f"Generating token for {dest_type}...")
                
                if dest_type == 'github':
                    result = self.generate_github_token()
                elif dest_type == 'gitlab':
                    result = self.generate_gitlab_token()
                elif dest_type == 'awssm':
                    result = self.generate_awssm_token()
                elif dest_type == '1password':
                    result = self.generate_1password_token()
                
                # Sanitize result (remove actual token)
                sanitized_result = {k: v for k, v in result.items() if k != 'token'}
                sanitized_result['success'] = 'error' not in result
                
                results[dest_type] = sanitized_result
                logger.info(f"Successfully generated token for {dest_type}")
                
                # Small delay between generations
                time.sleep(2)
                
            except Exception as e:
                logger.error(f"Failed to generate token for {dest_type}: {e}")
                results[dest_type] = {
                    'success': False,
                    'error': str(e)
                }
        
        return results


def main():
    """Main entry point."""
    # Get host from environment variables (check SPLUNKCLOUD_STACK_URL first, then SPLUNK_HOST)
    default_host = os.getenv('SPLUNKCLOUD_STACK_URL') or os.getenv('SPLUNK_HOST') or 'localhost'
    
    parser = argparse.ArgumentParser(description='Generate test tokens for all destinations')
    parser.add_argument('--host', default=default_host,
                       help='Splunk hostname (defaults to SPLUNKCLOUD_STACK_URL, SPLUNK_HOST, or localhost)')
    parser.add_argument('--port', type=int, default=int(os.getenv('SPLUNK_PORT', '8089')),
                       help='Splunk management port')
    parser.add_argument('--username', default=os.getenv('SPLUNKCLOUD_ADMIN_USER', 'admin'),
                       help='Admin username')
    parser.add_argument('--password', default=os.getenv('SPLUNKCLOUD_ADMIN_PASSWORD'),
                       help='Admin password (not needed if SPLUNK_TOKEN is set)')
    parser.add_argument('--token', default=os.getenv('SPLUNK_TOKEN'),
                       help='Long-lived Splunk token (preferred for CI; set SPLUNK_TOKEN or use obtain_splunk_token.py)')
    parser.add_argument('--scheme', choices=['http', 'https'], default='https',
                       help='HTTP scheme')
    parser.add_argument('--destinations', nargs='+',
                       choices=['github', 'gitlab', 'awssm', '1password'],
                       help='Specific destinations to test (default: all)')
    parser.add_argument('--output', help='Output file for results (JSON)')
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
    
    use_token = bool(args.token)
    if not use_token and not args.password:
        logger.error("Either SPLUNK_TOKEN or password required. Set SPLUNK_TOKEN (run obtain_splunk_token.py first) or SPLUNKCLOUD_ADMIN_PASSWORD")
        sys.exit(1)
    
    # Log connection details (mask password/token)
    connection_url = f"{args.scheme}://{args.host}:{args.port}"
    
    # Show which environment variables were used
    env_source = []
    if os.getenv('SPLUNKCLOUD_STACK_URL'):
        env_source.append(f"SPLUNKCLOUD_STACK_URL={os.getenv('SPLUNKCLOUD_STACK_URL')}")
    if os.getenv('SPLUNK_HOST'):
        env_source.append(f"SPLUNK_HOST={os.getenv('SPLUNK_HOST')}")
    if os.getenv('SPLUNK_PORT'):
        env_source.append(f"SPLUNK_PORT={os.getenv('SPLUNK_PORT')}")
    if os.getenv('SPLUNK_TOKEN'):
        env_source.append("SPLUNK_TOKEN=***")
    
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
    if use_token:
        logger.info(f"  Auth: token (long-lived, length={len(args.token)})")
    else:
        logger.info(f"  Username: {args.username}")
        logger.info(f"  Password: {'*' * len(args.password) if args.password else 'NOT SET'}")
    logger.info("=" * 60)
    
    try:
        logger.debug("Calling client.connect()...")
        # Connect to Splunk
        if use_token:
            service = client.connect(
                host=args.host,
                port=args.port,
                token=args.token,
                scheme=args.scheme,
                app="splunk_app_scdeploy",            )
        else:
            service = client.connect(
                host=args.host,
                port=args.port,
                username=args.username,
                password=args.password,
                scheme=args.scheme,
                app="splunk_app_scdeploy",            )
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
        
        generator = TokenGenerator(service, username=args.username, password=args.password, token=args.token)
        results = generator.generate_all_tokens(destinations=args.destinations)
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            logger.info(f"Results written to {args.output}")
        else:
            print(json.dumps(results, indent=2))
        
        # Check for failures
        failures = [k for k, v in results.items() if not v.get('success', False)]
        if failures:
            logger.warning(f"Failed destinations: {', '.join(failures)}")
            sys.exit(1)
        else:
            logger.info("All token generations succeeded")
    
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


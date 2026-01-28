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
    
    def __init__(self, service: client.Service):
        """
        Initialize token generator.
        
        Args:
            service: Connected Splunk service instance
        """
        self.service = service
    
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
            logger.info(f"Executing search: {search_query}")
            
            # Create search job
            job = self.service.jobs.create(search_query, **{"exec_mode": "blocking", "timeout": timeout})
            
            # Get results
            result_list = []
            for result in results.ResultsReader(job.results()):
                if isinstance(result, dict):
                    result_list.append(result)
                elif isinstance(result, results.Message):
                    logger.warning(f"Search message: {result}")
            
            logger.info(f"Search completed. Found {len(result_list)} results")
            return result_list
            
        except Exception as e:
            logger.error(f"Failed to execute search: {e}")
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
    parser = argparse.ArgumentParser(description='Generate test tokens for all destinations')
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
    parser.add_argument('--destinations', nargs='+',
                       choices=['github', 'gitlab', 'awssm', '1password'],
                       help='Specific destinations to test (default: all)')
    parser.add_argument('--output', help='Output file for results (JSON)')
    
    args = parser.parse_args()
    
    if not args.password:
        logger.error("Password required. Set SPLUNKCLOUD_ADMIN_PASSWORD or use --password")
        sys.exit(1)
    
    try:
        # Connect to Splunk
        service = client.connect(
            host=args.host,
            port=args.port,
            username=args.username,
            password=args.password,
            scheme=args.scheme
        )
        logger.info(f"Connected to Splunk at {args.scheme}://{args.host}:{args.port}")
        
        generator = TokenGenerator(service)
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
    
    except Exception as e:
        logger.error(f"Failed: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()


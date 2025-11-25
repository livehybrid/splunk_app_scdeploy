import import_declare_test

import sys
import json
from datetime import datetime, timezone

from splunklib import modularinput as smi
from splunktaucclib.modinput_wrapper.base_modinput import BaseModInput
from splunktaucclib.splunk_aoblib.setup_util import Setup_Util
import urllib.parse


class TOKEN_CLEANER(BaseModInput):

    def __init__(self):
        self.restPath = "splunk_app_scdeploy"
        super(TOKEN_CLEANER, self).__init__(self.restPath, "token_cleaner")

    def get_scheme(self):
        scheme = smi.Scheme('token_cleaner')
        scheme.description = 'Expired Token Remover'
        scheme.use_external_validation = True
        scheme.streaming_mode_xml = True
        scheme.use_single_instance = False

        scheme.add_argument(
            smi.Argument(
                'name',
                title='Name',
                description='Name',
                required_on_create=True
            )
        )
        
        scheme.add_argument(
            smi.Argument(
                'min_expiry',
                required_on_create=True,
            )
        )
        
        scheme.add_argument(
            smi.Argument(
                'limit',
                required_on_create=False,
            )
        )
        
        return scheme

    def validate_input(self, definition):
        return
    
    def delete_expired_tokens(self, ew, expiry_offset=3600, delete_limit=1):
        """
        Deletes expired tokens based on a specified expiry offset and delete limit.

        This method fetches all tokens from the authorization service, checks each token's expiry against
        the current time minus a given expiry offset, and deletes tokens that have expired. It logs
        detailed information about the process, including which tokens are deleted and any errors encountered.
        Deletion stops when the specified delete limit is reached.

        Args:
            ew: EventWriter writes events and error messages to Splunk from a modular input.
            expiry_offset (int, optional): The time in seconds to subtract from the current time to determine
                if a token has expired. Defaults to 3600 seconds (1 hour).
            delete_limit (int, optional): The maximum number of tokens to delete in a single run. Defaults to 1.

        Returns:
            None. This method logs the outcome of its operations instead of returning a value.

        Raises:
            Exception: Catches and logs any exception that occurs during the token deletion process.
        """
        
        # Fetch the current time in UTC
        time_now = datetime.now(timezone.utc).timestamp()

        try:
            # Fetch all tokens
            tokens_response = self.service.get('/services/authorization/tokens', output_mode="json").body.read()
            tokens = json.loads(tokens_response)['entry']
            removed_tokens = 0
            self.log_info(f"Cleaning up expired tokens where expiry is less than currentTime - expiry_offset={expiry_offset} with a delete_limit={delete_limit}")
            for token in tokens:
                token_expiry = int(token['content']['claims']['exp'])
                # Check if the token expired longer ago than the current time minus expiry_offset
                if token_expiry < (time_now - int(expiry_offset)):
                    removed_tokens = removed_tokens+1
                    # Token is expired, delete it
                    token_name = token['name']
                    token_user = token['content']['claims']['sub']
                    self.log_info(f"Deleting token_name={token_name} for user={token_user}")
                    delete_response = self.service.delete(f'/services/authorization/tokens/{token_user}', id=token_name, output_mode="json")
                    if delete_response.status != 200:
                        self.log_critical(f"Error removing token={token_name}")
                        self.log_warning(delete_response.body.read())
                    if removed_tokens>=delete_limit:
                        self.log_info(f"Stopping token remover as reached per-run delete_limit={delete_limit}")
                        continue

            self.log_info(f"Removed {removed_tokens} on this iteration")
        except Exception as e:
            self.log_critical(sys.exc_info()[2])
            ew.log("ERROR", f"Error deleting expired tokens: {str(e)}")


    def stream_events(self, inputs, ew):

        for input_name, input_item in inputs.inputs.items():
            self.delete_expired_tokens(ew, expiry_offset=int(input_item['min_expiry']), delete_limit=int(input_item['limit']))


if __name__ == '__main__':
    exit_code = TOKEN_CLEANER().run(sys.argv)
    sys.exit(exit_code)

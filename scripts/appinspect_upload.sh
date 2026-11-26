# No set -x: it traces the bearer tokens this script handles into the log.
resp=$(curl --location -s --request POST 'https://appinspect.splunk.com/v1/app/validate' \
--header "Authorization: bearer $SPLUNKBASE_TOKEN" \
--form "app_package=@$1" \
--form 'included_tags=private_app')
echo $resp | jq -r '.request_id'
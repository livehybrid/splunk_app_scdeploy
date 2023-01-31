#!/usr/bin/env python
# coding=utf-8

from __future__ import absolute_import, division, print_function, unicode_literals
from distutils.ccompiler import new_compiler
import import_declare_test
__author__ = "Will Searle"
__version__ = "1.0.0"
__status__ = "PRODUCTION"
import os
import sys
import logging
import requests
import splunk
import splunk.entity
import json
# import Splunk libs
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, validators
import splunklib.client as client
import splunklib.results as results
from splunktalib.credentials import CredentialManager as CredMgr
from splunklib.six.moves.urllib.parse import urlsplit
from splunktalib.common import util as scu
import boto3
from botocore.exceptions import ClientError
from splunklib.binding import HTTPError as SplunkHTTPError
splunkhome = os.environ['SPLUNK_HOME']
APP_NAME = scu.get_appname_from_path(__file__)

# set logging
filehandler = logging.FileHandler(splunkhome + f"/var/log/splunk/{APP_NAME}_gendeploytoken.log", 'a')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(filename)s %(funcName)s %(lineno)d %(message)s')
filehandler.setFormatter(formatter)
log = logging.getLogger()  # root logger - Good to get it only once.
for hdlr in log.handlers[:]:  # remove the existing file handlers
    if isinstance(hdlr,logging.FileHandler):
        log.removeHandler(hdlr)
log.addHandler(filehandler)      # set the new handler
# set the log level to INFO, DEBUG as the default is ERROR
log.setLevel(logging.INFO)

sys.path.append(os.path.join(splunkhome, 'etc', 'apps', APP_NAME, 'lib'))

@Configuration()
class GenerateSplunkToken(GeneratingCommand):

    destination_type = Option(
        doc='''
        **Syntax:** **destination_type=gitlab** **
        **Description:** Endpoint destination type field (e.g. gitlab/awssm) .''',
        require=True) # validate=validators.Match("source_field", r"^.*$")

    destination_name = Option(
        doc='''
        **Syntax:** **destination_name=crc-gitlab** **
        **Description:** Endpoint destination name from Configutation page .''',
        require=False, default="") # validate=validators.Match("source_field", r"^.*$")

    audience = Option(
        doc='''
            **Syntax:** **audience=cicd** **
            **Description:** audience (Description) field.''',
        require=False, default="cicd") # validate=validators.Match("source_field", r"^.*$")

    user = Option(
        doc='''
            **Syntax:** **user=admin** **
            **Description:** for which user to generate a token for.''',
        require=True) # validate=validators.Match("source_field", r"^.*$")

    expires_on = Option(
        doc='''
            **Syntax:** **exires_on="+10m"** **
            **Description:** relative token expiry time.''',
        require=False, default="+10m") # validate=validators.Match("source_field", r"^.*$")

    gitlab_branch = Option(
        doc='''
        **Syntax:** **gitlab_branch=main** **
        **Description:** Gitlab branch to trigger on pipeline (default: main) .''',
        require=False, default="main") # validate=validators.Match("source_field", r"^.*$")

    gitlab_projectid = Option(
        doc='''
        **Syntax:** **gitlab_projectid=12345** **
        **Description:** Override the configured Gitlab Project ID (Useful for deploying large number of projects) .''',
        require=False, default="0") # validate=validators.Match("source_field", r"^.*$")

    def generate_token(self):
        try:
            resp = self.service.post("/services/authorization/tokens/create", name=self.user, audience=self.audience, expires_on=self.expires_on)

            output_record=client._load_atom(resp)
            if 'content' in output_record['feed']['entry'] and 'token' in output_record['feed']['entry']['content']:
                tokenObj = output_record['feed']['entry']['content']
                tokenResponse = {
                    "tokenId":tokenObj['id'],
                    "token":tokenObj['token'],
                    "user" : self.user,
                    "expires_on": self.expires_on,
                    "audience": self.audience,
                }
                return tokenResponse
            else:
                raise Exception("Unable to retrieve token")
        except(Exception) as e:
            return e

    # |rest /services/server/info/server-info splunk_server=local | rex field=splunk_server "^.+\.(?<stackName>.+)\.splunkcloud.com" | table stackName version
    def get_config_secret(self):
        try:
            searchinfo = self._metadata.searchinfo
        except AttributeError:
            return None

        splunkd_uri = searchinfo.splunkd_uri

        if splunkd_uri is None:
            return None

        self.uri = urlsplit(splunkd_uri, allow_fragments=False)

        cred_mgr = CredMgr(
            f"{self.uri.scheme}://{self.uri.hostname}:{self.uri.port}",
            searchinfo.session_key,
            app=APP_NAME,
            #owner=self._user,
            realm=self.realm
        )
        #TODO: try block here
        cred = cred_mgr.get_clear_password(self.destination_name)[self.destination_name]
        secret_obj = json.loads(list(cred.keys())[0])

        return secret_obj

    @property
    def realm(self):
        conf_map = {
            "gitlab" : "dest_gitlab",
            "awssm" : "dest_awssm"
        }
        return f"__REST_CREDENTIAL__#{APP_NAME}#configs/conf-{APP_NAME}_{conf_map[self.destination_type]}"

    # This is where the stream is received
    def generate(self):

        # set loglevel
        loglevel = 'INFO'
        logger = logging.getLogger('gentoken')

        # If fails, don't break
        try:
            conf_file = f"{APP_NAME}_settings"
            confs = self.service.confs[str(conf_file)]
            for stanza in confs:
                if stanza.name == 'logging':
                    for stanzakey, stanzavalue in stanza.content.items():
                        if stanzakey == "loglevel":
                            loglevel = stanzavalue
            logginglevel = logging.getLevelName(loglevel)
            log.setLevel(logginglevel)

        except Exception as e:
            logging.warning("Failed to retrieve the logging level from application level configuration with exception=\"{}\"")
            log.setLevel(loglevel)

        try:
            tokenResponse = self.generate_token()

            if not tokenResponse or isinstance(tokenResponse, SplunkHTTPError):
                raise Exception({"message":"Could not generate token - is the username correct?", "error":"Token Response is invalid"})

            if self.destination_type == "gitlab":
                # Get gitlabonprem settings
                #destination_name
                conf_file = f"{APP_NAME}_dest_gitlab"
                confs = self.service.confs[str(conf_file)]
                if self.destination_name in confs:
                    remote_config = confs[self.destination_name].content
                else:
                    raise Exception(f"Cannot find destination_name called {self.destination_name} for destination_type={self.destination_type}")

                gitlab_hostname=remote_config['hostname']
                gitlab_projectid=remote_config['projectid']

                gitlab_token = self.get_config_secret()['token']
                headers = {
                    "PRIVATE-TOKEN": gitlab_token
                }
                logging.critical(self.service.info)
                splunkServer = self.service.info['serverName'] if 'serverName' in self.service.info else self.service.info['host']
                stackName = splunkServer.split(".")[1] if '.' in splunkServer else "Unknown"
                form_data = {
                    "variables": [
                        {"key":"ACS_TOKEN", "value":tokenResponse['token']},
                        {"key":"SPLUNK_SERVERNAME", "value": splunkServer},
                        {"key":"ACS_STACK", "value": stackName}
                    ]
                }
                if self.gitlab_projectid != "0":
                    gitlab_projectid = self.gitlab_projectid

                gitlab_url=f"https://{gitlab_hostname}/api/v4/projects/{gitlab_projectid}/pipeline?ref={self.gitlab_branch}"
                resp = requests.post(gitlab_url, json=form_data, headers=headers)
                respContent = resp.content.decode('utf-8')
                logging.warning(respContent)

                tokenResponse['token'] = "[REDACTED]"
                tokenResponse['destination_type'] = self.destination_type
                tokenResponse['destination_name'] = self.destination_name

                tokenResponse['gitlab_resp'] = respContent
                yield tokenResponse

            elif self.destination_type == "awssm":
                conf_file = f"{APP_NAME}_dest_awssm"
                confs = self.service.confs[str(conf_file)]
                if self.destination_name in confs:
                    remote_config = confs[self.destination_name].content
                else:
                    raise Exception(f"Cannot find destination_name called {self.destination_name} for destination_type={self.destination_type}")

                logging.warning(remote_config)
                aws_accessid = remote_config['aws_accessid']
                aws_region = remote_config['region']
                secret_name = remote_config['secretpath']
                aws_secret_configs = self.get_config_secret()
                aws_secret = aws_secret_configs['aws_secretkey']
                aws_iamrole = aws_secret_configs['iamrole'] if 'iamrole' in aws_secret_configs else None

                aws_session = boto3.session.Session()

                if aws_iamrole != None:
                    sts = aws_session.client(
                        service_name="sts",
                        aws_access_key_id=aws_accessid,
                        aws_secret_access_key=aws_secret,
                        region_name=aws_region
                    )
                    session_response = sts.assume_role(
                        RoleArn=aws_iamrole,
                        RoleSessionName="splunkcloud-gendeploytoken"
                    )

                    aws_accessid = session_response['Credentials']['AccessKeyId']
                    aws_secret = session_response['Credentials']['SecretAccessKey']
                    aws_session_token = session_response['Credentials']['SessionToken']

                else:
                    aws_session_token = None

                secretsmanager_client = aws_session.client(
                    service_name='secretsmanager',
                    region_name=aws_region,
                    aws_access_key_id=aws_accessid,
                    aws_secret_access_key=aws_secret,
                    aws_session_token=aws_session_token
                )

                try:
                    kwargs = {'SecretId': secret_name, 'SecretString': tokenResponse['token']}
                    response = secretsmanager_client.put_secret_value(**kwargs)
                    log_line=f"Value put in secret {secret_name}."
                    logger.info(log_line)
                    tokenResponse['message'] = log_line
                    tokenResponse['token'] = "[REDACTED]"
                    yield tokenResponse
                except ClientError:
                    logger.exception("Couldn't put value in secret %s.", secret_name)
                    raise Exception(f"Failed to insert token into secret={secret_name}")
                else:
                    return response

                pass
            else:
                tokenResponse['message'] = "Unknown destination"
                yield tokenResponse

        except(Exception) as e:
            logging.warning(e,exc_info=True)
            if str(e)[0]=="{":
                logging.critical(e.args[0])
                yield e.args[0]
            else:
                yield {"message":str(e), "error":"true"}
        # end
        logging.info("command=gendeploytoken, process terminated")

dispatch(GenerateSplunkToken, sys.argv, sys.stdin, sys.stdout, __name__)
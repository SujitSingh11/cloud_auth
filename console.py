#!/usr/bin/env python

import os
import getpass
import json
import requests
import sys
import urllib3
from urllib.parse import quote

import boto3


def assume_role(account_id, role_name, duration, external_id, mfa_arn, mfa_token):
    role_arn = "arn:aws:iam::" + account_id + ":role/" + role_name
    role_session_name = "AssumeRoleSession"
    # Specify the service and region here
    client = boto3.client('sts', 'us-west-2')

    response = client.assume_role(RoleArn=role_arn,
                                  RoleSessionName=role_session_name,
                                  DurationSeconds=duration,
                                  ExternalId=external_id,
                                  SerialNumber=mfa_arn,
                                  TokenCode=mfa_token)

    tmp_credentials = {
        'sessionId': response['Credentials']['AccessKeyId'],
        'sessionKey': response['Credentials']['SecretAccessKey'],
        'sessionToken': response['Credentials']['SessionToken']
    }
    return json.dumps(tmp_credentials)


def generate_federation_request_parameters(credentials_json):
    request_parameters = "?Action=getSigninToken"
    request_parameters += "&SessionDuration=3600"
    request_parameters += "&Session=" + quote(credentials_json)
    return request_parameters


def generate_sign_in_token(credentials_json):
    request_parameters = generate_federation_request_parameters(
        credentials_json)
    request_url = "https://signin.aws.amazon.com/federation" + request_parameters
    r = requests.get(request_url)
    return json.loads(r.text)['SigninToken']


def generate_signin_request_parameters(signin_token, issuer):
    request_parameters = "?Action=login"
    request_parameters += "&Issuer=" + issuer
    request_parameters += "&Destination=" + \
        quote("https://console.aws.amazon.com/")
    request_parameters += "&SigninToken=" + signin_token
    return request_parameters


def generate_signed_url(signin_token, issuer):
    request_parameters = generate_signin_request_parameters(
        signin_token, issuer)
    return "https://signin.aws.amazon.com/federation" + request_parameters


def run(account_id, role_name, mfa_arn, duration, issuer, external_id, mfa_token):
    tmp_credentials = assume_role(
        account_id, role_name, duration, external_id, mfa_arn, mfa_token)
    signin_token = generate_sign_in_token(tmp_credentials)
    return generate_signed_url(signin_token, issuer)


def validate_input(argv):
    if (len(argv) < 3):
        return False

    if (argv[1] == "") or (argv[2] == "") or (argv[3] == ""):
        return False

    return True


# --- Start of CLI parsing ---
# if (validate_input(sys.argv) != True):
#     print("console.py ACCOUNT_ID ROLE_NAME MFA_ARN")
#     sys.exit(1)

account_id = "317360785572"   # Account id of target account
role_name = "roleTest1"  # Name of role to assume in target account

# MFA users ARN. More info: http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html
mfa_arn = "arn:aws:iam::317360785572:user/sujitTest1"

duration = 3600  # 1 Hour
issuer = "Example.org"  # issuer name for signin url
external_id = getpass.getpass("External ID: ")
mfa_token = getpass.getpass("MFA Token: ")

try:
    url = run(account_id, role_name, mfa_arn,
              duration, issuer, external_id, mfa_token)
    print(url)
except Exception as e:
    print("Received error:", e)
    sys.exit(1)

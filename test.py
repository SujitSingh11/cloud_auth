#!/bin/env python

import boto3
import json

client = boto3.client('sts')

role_arn="arn:aws:iam::317360785572:role/test-role"
role_session_name = "test-session"
duration = 3600

response = client.assume_role(
    RoleArn=role_arn,
    RoleSessionName=role_session_name,
    DurationSeconds=duration,
)
tmp_credentials = {
        'sessionId': response['Credentials']['AccessKeyId'],
        'sessionKey': response['Credentials']['SecretAccessKey'],
        'sessionToken': response['Credentials']['SessionToken']
}
print(json.dumps(tmp_credentials))

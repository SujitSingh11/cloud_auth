import boto3
import json

def assume_role(role_arn, role_session_name, duration):
    client_sts = boto3.client('sts')
    response = client_sts.assume_role(
    RoleArn=role_arn,
    RoleSessionName=role_session_name,
    DurationSeconds=duration,
    )
    tmp_credentials = {
            'sessionId': response['Credentials']['AccessKeyId'],
            'sessionKey': response['Credentials']['SecretAccessKey'],
            'sessionToken': response['Credentials']['SessionToken']
    }
    return(json.dumps(tmp_credentials))

def list_role():
    i=1
    client_iam = boto3.client('iam')
    response = client_iam.list_roles(
        MaxItems=100
    )
    for role in response['Roles']:
        print(i," ",role['RoleName'])
        i=i+1
    return response


print("\nSelect Role (i.e 1/2/3)")
roles = list_role()
selected_role = int(input("Select: "))
role_session_name = str(input("Enter a Session Name (e.g Test-Session) : "))
duration = 3600 # Duration 1 hr
role_arn = roles['Roles'][selected_role-1]['Arn']

print(assume_role(role_arn,role_session_name,duration)) # Assume Role

print("\n Session has been Started for 1hr")

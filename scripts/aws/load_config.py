import os
import boto3
import base64
import json
from botocore.exceptions import ClientError

secret_name = os.environ['UID2_CONFIG_SECRET_KEY']
region_name = os.environ['AWS_REGION_NAME']
aws_access_key_id = os.environ['AWS_ACCESS_KEY_ID']
secret_key = os.environ['AWS_SECRET_KEY']
session_token = os.environ['AWS_SESSION_TOKEN']

def get_secret():
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name,
        aws_access_key_id = aws_access_key_id,
        aws_secret_access_key = secret_key,
        aws_session_token = session_token
    )
    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        raise e
    else:
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
    
    return secret

def get_config():
    result = get_secret()
    conf = json.loads(result)
    print(result)

get_config()

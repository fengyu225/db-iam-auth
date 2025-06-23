import json
import boto3
from botocore.client import Config
import requests
from urllib.parse import urlparse, parse_qs
from datetime import datetime

def create_presigned_sts_url(duration_seconds=3600):
    """
    Generate a presigned URL for STS GetCallerIdentity
    """
    sts_client = boto3.client('sts', config=Config(signature_version='v4'))

    presigned_url = sts_client.generate_presigned_url(
        'get_caller_identity',
        Params={},
        ExpiresIn=duration_seconds,
        HttpMethod='GET'
    )

    return presigned_url

presign_url = create_presigned_sts_url(10)
print(presign_url)

def validate_sts_presigned_url(presigned_url):
    """
    Validates the presigned URL by executing it
    """
    try:
        response = requests.get(presigned_url)

        if response.status_code == 200:
            headers = {'Accept': 'application/json'}
            response = requests.get(presigned_url, headers=headers)

            identity_data = response.json()

            identity = {
                'user_id': identity_data['GetCallerIdentityResponse']['GetCallerIdentityResult']['UserId'],
                'account': identity_data['GetCallerIdentityResponse']['GetCallerIdentityResult']['Account'],
                'arn': identity_data['GetCallerIdentityResponse']['GetCallerIdentityResult']['Arn']
            }

            return True, identity

        elif response.status_code == 403:
            return False, "Expired or invalid signature"
        else:
            return False, "Failed with status: " + response.status_code

    except Exception as e:
        return False, str(e)

print(validate_sts_presigned_url(presign_url))
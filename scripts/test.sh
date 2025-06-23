aws sts assume-role --role-arn arn:aws:iam::072422391281:role/db-iam-auth-dev-elasticsearch-db-role --role-session-name payment-es-user

export AWS_ACCESS_KEY_ID=
export AWS_SECRET_ACCESS_KEY=
export AWS_SESSION_TOKEN=

PRESIGNED_URL=

curl -H "Authorization: PreSignedUrl $PRESIGNED_URL" http://10.0.101.31:9201/ ; echo


yum install pip
pip install boto3 requests
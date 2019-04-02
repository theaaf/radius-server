#!/usr/bin/env python
import boto3
import json

with open('credentials.json') as f:
    credentials = json.load(f)

iam = boto3.client(
    'iam',
    aws_access_key_id=credentials['AWS_ACCESS_KEY_ID'],
    aws_secret_access_key=credentials['AWS_SECRET_ACCESS_KEY'],
)

paginator = iam.get_paginator('list_users')
for response in paginator.paginate():
    print(response)

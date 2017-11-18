import datetime
import logging

import boto3 as boto3
import os


def _s3_key_prefix(prefix, date, account_id, region):
    pass
    return f"{prefix}AWSLogs/{account_id}/CloudTrail/{region}/{date.year}/{date.month:02d}/{date.day:02d}"


def _s3_key_prefixes(prefix, past_days, account_ids, regions):
    now = datetime.datetime.now()
    days = [now - datetime.timedelta(days=delta_days) for delta_days in range(past_days + 1)]
    return [_s3_key_prefix(prefix, day, account_id, region)
            for account_id in account_ids
            for day in days
            for region in regions]


def _s3_download_recursive(bucket, prefix, target_dir):
    client = boto3.client('s3')

    def download_file(file):
        key = file.get('Key')
        target = target_dir + os.sep + key
        if not os.path.exists(os.path.dirname(target)):
            os.makedirs(os.path.dirname(target))
        logging.info(f"Downloading {bucket}/{key} to {target}")
        client.download_file(bucket, key, target)

    def download_dir(dist):
        paginator = client.get_paginator('list_objects')
        for result in paginator.paginate(Bucket=bucket, Prefix=dist):
            if result.get('CommonPrefixes') is not None:
                for subdir in result.get('CommonPrefixes'):
                    download_dir(subdir.get('Prefix'))

            if result.get('Contents') is not None:
                for file in result.get('Contents'):
                    download_file(file)

    download_dir(prefix)

def download_cloudtrail_logs(target_dir, bucket, prefix, past_days, account_ids, regions):
    for prefix in _s3_key_prefixes(prefix, past_days,account_ids,regions):
        logging.debug(f"Downloading logs for {prefix}")
        _s3_download_recursive(bucket, prefix, target_dir)

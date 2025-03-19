"""Module for CloudTrailAPIRecordSource"""
import json

import boto3

from trailscraper.cloudtrail import _parse_record



class RecordsFromApi():
    """Class to behave like a LogFile object when asked to yield records."""
    def __init__(self, records):
        self._records = records

    def records(self):
        return self._records


class CloudTrailAPIRecordSource():
    """Class to represent CloudTrail records from the CloudTrail lookup_events API"""
    def __init__(self):
        self._client = boto3.client('cloudtrail')

    def load_from_api(self, from_date, to_date):
        """Loads cloudtrail events from the API"""
        client = boto3.client('cloudtrail')
        paginator = client.get_paginator('lookup_events')
        # apparently the LookupEvents API call only returns events from the AWS account where the API call is made, even with an organization trail
        # "An event history search is limited to a single AWS account, only returns events from a single AWS Region, and cannot query multiple attributes."
        response_iterator = paginator.paginate(
            StartTime=from_date,
            EndTime=to_date,
        )
        for response in response_iterator:
            # we build then yield a list of events in complex way so that this can behave like a LogFile object and be parallelism-compatible
            # compatibility with parallelism is not directly useful when processing events from the AWS API
            # the purpose of the compatibility is to share code with parallelised processing of event records that have been cached locally
            records = []
            for event in response['Events']:
                records.append(_parse_record(json.loads(event['CloudTrailEvent'])))
            yield RecordsFromApi(records)

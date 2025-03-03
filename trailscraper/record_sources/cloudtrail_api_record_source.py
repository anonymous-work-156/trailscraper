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
        response_iterator = paginator.paginate(
            StartTime=from_date,
            EndTime=to_date,
        )
        for response in response_iterator:
            records = []
            for event in response['Events']:
                records.append(_parse_record(json.loads(event['CloudTrailEvent'])))
            yield RecordsFromApi(records)

#     Copyright 2014 Netflix, Inc.
#
#     Licensed under the Apache License, Version 2.0 (the "License");
#     you may not use this file except in compliance with the License.
#     You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS,
#     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#     See the License for the specific language governing permissions and
#     limitations under the License.
"""
.. module: security_monkey.watchers.sns
    :platform: Unix

.. version:: $$VERSION$$
.. moduleauthor:: Patrick Kelley <pkelley@netflix.com> @monkeysecurity

"""

from security_monkey.watcher import Watcher
from security_monkey.watcher import ChangeItem
from security_monkey.constants import TROUBLE_REGIONS
from security_monkey.exceptions import InvalidARN
from security_monkey.exceptions import InvalidAWSJSON
from security_monkey.exceptions import BotoConnectionIssue
from security_monkey import app

import json
import re
from boto.sns import regions

from security_monkey.watcher import boto_rate_limited
from security_monkey.watcher import auto_record_exception, record_exception

@boto_rate_limited(technology='sns')
def get_topic_attributes(conn, arn):
    """
    rate-limitable wrapper for boto's sns.get_topic_attributes() method.
    """
    return conn.get_topic_attributes(arn)

@boto_rate_limited(technology='sns')
def get_all_subscriptions_by_topic(conn, arn, token):
    """
    rate-limitable wrapper for boto's sns.get_all_subscriptions_by_topic() method.
    """
    return conn.get_all_subscriptions_by_topic(arn, next_token=token)

@boto_rate_limited(technology='sns')
def get_all_topics(conn, token):
    """
    rate-limitable wrapper for boto's sns.get_all_topics() method.
    """
    return conn.get_all_topics(next_token=token)

@auto_record_exception(exception_type=InvalidAWSJSON)
def _get_sns_policy(attrs, location=None, exception_map=None):
    """
    Extracts and returns the SNS policy from the topic attributes
    :param attrs: value returned by get_topic_attributes()
    :param location: A tuple of (index, account, region, arn)
    :param exception_map: A singleton dict used to record all watcher exceptions
    :return: string of the name of the topic
    :return:
    """
    json_str = attrs['GetTopicAttributesResponse']['GetTopicAttributesResult']['Attributes']['Policy']
    return json.loads(json_str)

@auto_record_exception(exception_type=InvalidARN)
def _get_sns_name(arn, location=None, exception_map=None):
    """
    Extracts the name of an SNS topic from its ARN.
    :param arn: AWS ARN for the topic we are interested in
    :param location: A tuple of (index, account, region, arn)
    :param exception_map: A singleton dict used to record all watcher exceptions
    :return: string of the name of the topic
    """
    return re.search('arn:aws:sns:[a-z0-9-]+:[0-9]+:([a-zA-Z0-9-]+)', arn).group(1)


def _get_topic_subscriptions(conn, arn):
    """
    Paginate over each topic subscription for a specific topic.

    :param conn: boto connection object
    :param arn: AWS ARN to the topic we are interested in.
    :return: a list of all subscriptions for the given topic.
    """
    token = None
    all_subscriptions = []
    while True:
        subscriptions = get_all_subscriptions_by_topic(conn, arn, token)

        all_subscriptions.extend(
            subscriptions['ListSubscriptionsByTopicResponse']['ListSubscriptionsByTopicResult']['Subscriptions']
        )

        token = subscriptions['ListSubscriptionsByTopicResponse']['ListSubscriptionsByTopicResult']['NextToken']
        if token is None:
            break

    return all_subscriptions


def build_sns_item_from_arn(conn=None, arn=None, region=None, account=None, exception_map={}):
    """
    Builds an SNSItem from the values specified.

    :param conn: boto connection object
    :param arn: AWS ARN to the topic we are interested in
    :param region: AWS Region
    :param account: AWS Account we are working on
    :param exception_map: A singleton dict used to record all watcher exceptions
    :return: instance of SNSItem
    """
    config = {}
    attrs = get_topic_attributes(conn, arn)
    location = (SNS.index, account, region, arn)

    try:
        config['subscriptions'] = _get_topic_subscriptions(conn, arn)
        config['policy'] = _get_sns_policy(attrs, location=location, exception_map=exception_map)
        config['name'] = _get_sns_name(arn, location=location, exception_map=exception_map)
    except:
        return None

    return SNSItem(region=region, account=account, name=arn, config=config)


def get_all_topics_in_region(account, region):
    """
    Paginate over each SNS topic in a given account and region.
    :param account: AWS Account we are working on
    :param region: AWS Region we are working in
    :return: sns - boto connection object for the given account, technology, and region
    :return: topics - list containing each SNS topic
    """
    from security_monkey.common.sts_connect import connect
    sns = connect(account, 'sns', region=region)

    app.logger.debug("Checking {}/{}/{}".format(SNS.index, account, region.name))
    topics = []
    marker = None
    while True:
        topics_response = get_all_topics(sns, marker)
        current_page_topics = topics_response['ListTopicsResponse']['ListTopicsResult']['Topics']
        topics.extend(current_page_topics)
        if topics_response[u'ListTopicsResponse'][u'ListTopicsResult'][u'NextToken']:
            marker = topics_response[u'ListTopicsResponse'][u'ListTopicsResult'][u'NextToken']
        else:
            break

    return sns, topics


class SNS(Watcher):
    index = 'sns'
    i_am_singular = 'SNS Topic Policy'
    i_am_plural = 'SNS Topic Policies'

    def __init__(self, accounts=None, debug=False):
        super(SNS, self).__init__(accounts=accounts, debug=debug)

    def slurp(self):
        """
        :returns: item_list - list of SNSItem's.
        :returns: exception_map - A dict where the keys are a tuple containing the
            location of the exception and the value is the actual exception

        """
        self.prep_for_slurp()

        item_list = []
        exception_map = {}
        for account in self.accounts:
            for region in regions():
                try:
                    (sns, topics) = get_all_topics_in_region(account, region)
                except Exception as e:
                    if region.name not in TROUBLE_REGIONS:
                        exc = BotoConnectionIssue(str(e), 'sns', account, region.name)
                        record_exception((self.index, account, region.name), exc, exception_map)
                    continue

                app.logger.debug("Found {} {}".format(len(topics), SNS.i_am_plural))
                for topic in topics:
                    arn = topic['TopicArn']

                    if self.check_ignore_list(arn):
                        continue

                    item = build_sns_item_from_arn(conn=sns,
                                                   arn=arn,
                                                   region=region.name,
                                                   account=account,
                                                   exception_map=exception_map)
                    if item:
                        item_list.append(item)
        return item_list, exception_map


class SNSItem(ChangeItem):
    def __init__(self, region=None, account=None, name=None, config={}):
        super(SNSItem, self).__init__(
            index=SNS.index,
            region=region,
            account=account,
            name=name,
            new_config=config)

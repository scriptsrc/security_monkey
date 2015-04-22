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
.. module: security_monkey.watchers.iam.iam_user
    :platform: Unix

.. version:: $$VERSION$$
.. moduleauthor:: Patrick Kelley <pkelley@netflix.com> @monkeysecurity

"""

from security_monkey.watcher import Watcher
from security_monkey.watcher import ChangeItem
from security_monkey.exceptions import InvalidAWSJSON
from security_monkey.exceptions import BotoConnectionIssue
from security_monkey import app

import json
import urllib


def all_managed_policies(conn):
    managed_policies = {}

    for policy in conn.policies.all():
        for attached_user in policy.attached_users.all():
            policy = {
                "name": policy.policy_name,
                "arn": policy.arn,
                "version": policy.default_version_id
            }

            if attached_user.arn not in managed_policies:
                managed_policies[attached_user.arn] = [policy]
            else:
                managed_policies[attached_user.arn].append(policy)

    return managed_policies


class IAMUser(Watcher):
    index = 'iamuser'
    i_am_singular = 'IAM User'
    i_am_plural = 'IAM Users'

    def __init__(self, accounts=None, debug=False):
        super(IAMUser, self).__init__(accounts=accounts, debug=debug)

    def policy_names_for_user(self, conn, user):
        all_policy_names = []
        marker = None
        while True:
            response = self.wrap_aws_rate_limited_call(
                conn.get_all_user_policies,
                user.user_name,
                marker=marker
            )
            all_policy_names.extend(response.policy_names)
            if response.is_truncated == u'true':
                marker = response.marker
            else:
                break
        return all_policy_names

    def access_keys_for_user(self, conn, user):
        all_access_keys = []
        marker = None
        while True:
            response = self.wrap_aws_rate_limited_call(
                conn.get_all_access_keys,
                user_name=user.user_name,
                marker=marker
            )
            all_access_keys.extend(response.access_key_metadata)
            if response.is_truncated == u'true':
                marker = response.marker
            else:
                break
        return all_access_keys

    def mfas_for_user(self, conn, user):
        all_mfas = []
        marker = None
        while True:
            response = self.wrap_aws_rate_limited_call(
                conn.get_all_mfa_devices,
                user_name=user.user_name,
                marker=marker
            )
            all_mfas.extend(response.mfa_devices)
            if response.is_truncated == u'true':
                marker = response.marker
            else:
                break
        return all_mfas

    def certificates_for_user(self, conn, user):
        all_certificates = []
        marker = None
        while True:
            response = self.wrap_aws_rate_limited_call(
                conn.get_all_signing_certs,
                user_name=user.user_name,
                marker=marker
            )
            all_certificates.extend(response.certificates)
            if response.is_truncated == u'true':
                marker = response.marker
            else:
                break
        return all_certificates

    def slurp(self):
        """
        :returns: item_list - list of IAM Groups.
        :returns: exception_map - A dict where the keys are a tuple containing the
            location of the exception and the value is the actual exception
        """
        self.prep_for_slurp()
        item_list = []
        exception_map = {}

        from security_monkey.common.sts_connect import connect
        for account in self.accounts:
            all_users = []

            try:
                iam_b3 = connect(account, 'iam_boto3')
                managed_policies = all_managed_policies(iam_b3)

                iam = connect(account, 'iam')
                marker = None
                while True:
                    users_response = self.wrap_aws_rate_limited_call(
                        iam.get_all_users,
                        marker=marker
                    )

                    # build our iam user list
                    all_users.extend(users_response.users)

                    # ensure that we get every iam user
                    if hasattr(users_response, 'marker'):
                        marker = users_response.marker
                    else:
                        break

            except Exception as e:
                exc = BotoConnectionIssue(str(e), 'iamuser', account, None)
                self.slurp_exception((self.index, account, 'universal'), exc, exception_map)
                continue

            for user in all_users:

                if self.check_ignore_list(user.user_name):
                    continue

                item_config = {
                    'user': {},
                    'userpolicies': {},
                    'accesskeys': {},
                    'mfadevices': {},
                    'signingcerts': {}
                }
                app.logger.debug("Slurping %s (%s) from %s" % (self.i_am_singular, user.user_name, account))
                item_config['user'] = dict(user)

                if managed_policies.has_key(user.arn):
                    item_config['managed_policies'] = managed_policies.get(user.arn)

                ### USER POLICIES ###
                policy_names = self.policy_names_for_user(iam, user)

                for policy_name in policy_names:
                    policy_document = self.wrap_aws_rate_limited_call(
                        iam.get_user_policy,
                        user.user_name,
                        policy_name
                    )
                    policy_document = policy_document.policy_document
                    policy = urllib.unquote(policy_document)
                    try:
                        policydict = json.loads(policy)
                    except:
                        exc = InvalidAWSJSON(policy)
                        self.slurp_exception((self.index, account, 'universal', user.user_name), exc, exception_map)

                    item_config['userpolicies'][policy_name] = dict(policydict)

                ### ACCESS KEYS ###
                access_keys = self.access_keys_for_user(iam, user)

                for key in access_keys:
                    item_config['accesskeys'][key.access_key_id] = dict(key)

                ### Multi Factor Authentication Devices ###
                mfas = self.mfas_for_user(iam, user)

                for mfa in mfas:
                    item_config['mfadevices'][mfa.serial_number] = dict(mfa)

                ### LOGIN PROFILE ###
                login_profile = 'undefined'
                try:
                    login_profile = self.wrap_aws_rate_limited_call(
                        iam.get_login_profiles,
                        user.user_name
                    )
                    login_profile = login_profile.login_profile
                    item_config['loginprofile'] = dict(login_profile)
                except:
                    pass

                ### SIGNING CERTIFICATES ###
                certificates = self.certificates_for_user(iam, user)

                for cert in certificates:
                    _cert = dict(cert)
                    del _cert['certificate_body']
                    item_config['signingcerts'][cert.certificate_id] = dict(_cert)

                item_list.append(
                    IAMUserItem(account=account, name=user.user_name, config=item_config)
                )

        return item_list, exception_map


class IAMUserItem(ChangeItem):
    def __init__(self, account=None, name=None, config={}):
        super(IAMUserItem, self).__init__(
            index=IAMUser.index,
            region='universal',
            account=account,
            name=name,
            new_config=config)

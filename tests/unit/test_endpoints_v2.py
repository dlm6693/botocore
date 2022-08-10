# Copyright 2012-2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.

import json
import os
import unittest

import pytest

from botocore.endpoints_v2 import (
    EndpointProvider,
    EndpointRule,
    ErrorRule,
    ParameterDefinition,
    RuleCreator,
    TreeRule,
)
from botocore.exceptions import (
    EndpointInputParametersError,
    EndpointResolutionError,
)
from botocore.loaders import Loader


@pytest.fixture
def partitions():
    loader = Loader()
    return loader.load_data('partitions')


def cases():
    loader = Loader()
    exclude = [
        'license-manager-user-subscriptions',
        'sdb',
        # 's3',
        's3control',
        's3outposts',
    ]
    services = loader.list_available_services('service-2')
    for s in exclude:
        services.remove(s)
    test_data_dir = os.path.join(
        os.path.dirname(__file__), 'data', 'endpoints'
    )
    for service in services:
        ruleset = loader.load_service_model(service, 'endpoint-rule-set')
        with open(f'{test_data_dir}/{service}/endpoint-tests.json') as f:
            data = f.read()
            tests = json.loads(data)
            for test in tests['testCases']:
                input_params = test['params']
                expected_object = test['expect']
                yield (ruleset, input_params, expected_object)


# @pytest.mark.parametrize("ruleset,input_params,expected_object", cases())
# def test_endpoint_resolution(partitions, ruleset, input_params, expected_object):

#     endpoint_provider = EndpointProvider(ruleset, partitions)
#     if 'error' in expected_object:
#         with pytest.raises(EndpointResolutionError) as err:
#             endpoint_provider.resolve_endpoint(**input_params)
#             assert err.msg == expected_object['error']
#     else:
#         endpoint = endpoint_provider.resolve_endpoint(**input_params)
#         assert endpoint.url == expected_object['url']
#         assert endpoint.properties == expected_object['properties']
#         assert endpoint.headers == expected_object['headers']


@pytest.mark.parametrize(
    "rule_dict,expected_rule_type",
    [
        (
            {
                'type': 'endpoint',
                'conditions': [],
                'endpoint': {
                    'url': 'https://{Region}.myGreatService.{PartitionResult#dualStackDnsSuffix}',
                    'properties': {},
                    'headers': {},
                },
            },
            EndpointRule,
        ),
        (
            {
                'type': 'error',
                'conditions': [],
                'error': 'Dualstack is enabled but this partition does not support DualStack',
            },
            ErrorRule,
        ),
        ({'type': 'tree', 'conditions': [], 'rules': []}, TreeRule),
    ],
)
def test_rule_creation(partitions, rule_dict, expected_rule_type):
    provider = EndpointProvider({}, partitions)
    rule = RuleCreator.create(assignments={}, provider=provider, **rule_dict)
    assert isinstance(rule, expected_rule_type)


@pytest.mark.parametrize(
    "bad_input,parameter_spec",
    [
        (True, ParameterDefinition('Region', 'String')),
        ("false", ParameterDefinition('RequiresAccountId', 'Boolean')),
    ],
)
def test_input_validation(bad_input, parameter_spec):
    with pytest.raises(EndpointInputParametersError) as err:
        correct_type = getattr(
            parameter_spec.ParameterType, parameter_spec.type
        ).value
        parameter_spec.validate_input(bad_input)
        assert (
            err.msg
            == f'Invalid parameter {parameter_spec.name} is the wrong type. Must be {correct_type}'
        )


class RuleTestCase(unittest.TestCase):
    def setUp(self):
        loader = Loader()
        self.provider = EndpointProvider({}, loader.load_data('partitions'))
        self.region_template = '{Region}'
        self.dns_suffix_template = '{PartitionResult#dnsSuffix}'
        self.region_ref = {'ref': 'Region'}
        self.bucket_ref = {'ref': 'Bucket'}
        self.bucket_arn_ref = {'ref': 'bucketArn'}
        self.parse_arn_func = {
            'fn': 'parseArn',
            'argv': [self.bucket_ref],
            'assign': 'bucketArn',
        }
        self.get_attr_func = {
            'fn': 'getAttr',
            'argv': [self.bucket_arn_ref, 'region'],
        }

        self.string_equals_func = {
            'fn': 'stringEquals',
            'argv': [
                self.get_attr_func,
                '',
            ],
        }
        self.not_func = {
            'fn': 'not',
            'argv': [self.string_equals_func],
        }
        self.aws_partition_func = {
            'fn': 'aws.partition',
            'argv': [self.region_ref],
            'assign': 'PartitionResult',
        }
        self.url = (
            'https://{Region}.myGreatService.{PartitionResult#dnsSuffix}'
        )
        self.properties = {
            'authSchemes': [
                {
                    "signingName": "s3",
                    "signingScope": '{Region}',
                    "name": "s3v4",
                }
            ],
        }
        self.headers = {
            'x-amz-region-set': [
                self.region_ref,
                {
                    'fn': 'getAttr',
                    'argv': [self.bucket_arn_ref, 'region'],
                },
                'us-east-2',
            ],
        }
        self.endpoint = {
            'url': self.url,
            'properties': self.properties,
            'headers': self.headers,
        }
        self.assignments = {
            'Region': 'us-west-2',
            'Bucket': 'arn:aws:s3:us-west-2:123456789012:accesspoint:myendpoint',
        }
        self.conditions = [
            self.parse_arn_func,
            self.not_func,
            self.aws_partition_func,
        ]
        self.rule = EndpointRule(
            endpoint=self.endpoint,
            assignments=self.assignments,
            conditions=self.conditions,
            provider=self.provider,
        )

    def test_evaluate_conditions(self):
        assert self.rule.evaluate_conditions() is True

    def test_resolve_template_string(self):
        assert (
            self.rule.resolve_template_string(self.region_template)
            == 'us-west-2'
        )
        assert (
            self.rule.resolve_template_string(self.dns_suffix_template)
            == 'amazonaws.com'
        )

    def test_is_ref(self):
        assert (
            all(
                self.rule.is_ref(ref)
                for ref in [
                    self.region_ref,
                    self.bucket_ref,
                    self.bucket_arn_ref,
                ]
            )
            is True
        )

    def test_is_func(self):
        assert (
            all(
                self.rule.is_func(func)
                for func in [
                    self.parse_arn_func,
                    self.get_attr_func,
                    self.string_equals_func,
                    self.not_func,
                    self.aws_partition_func,
                ]
            )
            is True
        )

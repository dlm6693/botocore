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

import pytest

from botocore.endpoints_v2 import EndpointProvider
from botocore.exceptions import EndpointError
from botocore.loaders import Loader


@pytest.fixture
def loader():
    return Loader()


def cases():
    loader = Loader()
    exclude = [
        'license-manager-user-subscriptions',
        'sdb',
        's3',
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


@pytest.mark.parametrize("ruleset,input_params,expected_object", cases())
def test_endpoint_resolution(loader, ruleset, input_params, expected_object):

    partitions = loader.load_data('partitions')
    endpoint_provider = EndpointProvider(ruleset, partitions)
    if 'error' in expected_object:
        with pytest.raises(EndpointError) as err:
            endpoint_provider.resolve_endpoint(**input_params)
            assert err.msg == expected_object['error']
    else:
        endpoint = endpoint_provider.resolve_endpoint(**input_params)
        assert endpoint.url == expected_object['url']
        assert endpoint.properties == expected_object['properties']
        assert endpoint.headers == expected_object['headers']

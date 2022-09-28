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

from botocore.endpoint_provider import EndpointProvider
from botocore.exceptions import EndpointResolutionError
from botocore.loaders import Loader


@pytest.fixture(scope="module")
def loader():
    return Loader()


@pytest.fixture(scope="module")
def partitions(loader):
    return loader.load_data("partitions")


def ruleset_testcases():
    loader = Loader()
    error_cases = []
    endpoint_cases = []
    base_path = os.path.join(os.path.dirname(__file__), "data", "endpoints")
    for service in loader.list_available_services("endpoint-rule-set-1"):
        ruleset = loader.load_service_model(service, "endpoint-rule-set-1")
        with open(
            os.path.join(base_path, service, "endpoint-tests.json")
        ) as f:
            tests = json.load(f)
        for test in tests["testCases"]:
            input_params = test.get("params", {})
            expected_object = test["expect"]
            if "error" in expected_object:
                error_cases.append(
                    (ruleset, input_params, expected_object["error"])
                )
            elif "endpoint" in expected_object:
                endpoint_cases.append(
                    (ruleset, input_params, expected_object["endpoint"])
                )
            else:
                raise ValueError("Expected `error` or `endpoint` in test case")
    return error_cases, endpoint_cases


ERROR_TEST_CASES, ENDPOINT_TEST_CASES = ruleset_testcases()


@pytest.mark.parametrize(
    "ruleset,input_params,expected_error",
    ERROR_TEST_CASES,
)
def test_endpoint_resolution_raises(
    partitions, ruleset, input_params, expected_error
):
    endpoint_provider = EndpointProvider(ruleset, partitions)
    with pytest.raises(EndpointResolutionError) as exc_info:
        endpoint_provider.resolve_endpoint(**input_params)
    assert str(exc_info.value) == expected_error


@pytest.mark.parametrize(
    "ruleset,input_params,expected_endpoint",
    ENDPOINT_TEST_CASES,
)
def test_endpoint_resolution(
    partitions, ruleset, input_params, expected_endpoint
):
    endpoint_provider = EndpointProvider(ruleset, partitions)
    endpoint = endpoint_provider.resolve_endpoint(**input_params)
    assert endpoint.url == expected_endpoint["url"]
    assert endpoint.properties == expected_endpoint.get("properties", {})
    assert endpoint.headers == expected_endpoint.get("headers", {})

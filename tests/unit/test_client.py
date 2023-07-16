# Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
import io
from contextlib import closing

import botocore
import botocore.config
from botocore import client, exceptions, hooks
from botocore.auth import AUTH_TYPE_MAPS, BaseSigner
from botocore.client import ClientEndpointBridge
from botocore.configprovider import (
    ChainProvider,
    ConfigValueStore,
    EnvironmentProvider,
)
from botocore.credentials import Credentials
from botocore.endpoint import DEFAULT_TIMEOUT
from botocore.errorfactory import ClientExceptionsFactory
from botocore.exceptions import (
    InvalidMaxRetryAttemptsError,
    InvalidRetryConfigurationError,
    InvalidRetryModeError,
    InvalidS3AddressingStyleError,
    ParamValidationError,
    UnknownSignatureVersionError,
)
from botocore.stub import Stubber
from botocore.useragent import UserAgentString
from tests import mock, unittest


class BaseClientTest(unittest.TestCase):
    def setUp(self):
        self.service_description = {
            'metadata': {
                'serviceFullName': 'AWS MyService',
                'apiVersion': '2014-01-01',
                'endpointPrefix': 'myservice',
                'signatureVersion': 'v4',
                'protocol': 'query',
                'serviceId': 'MyService',
            },
            'operations': {
                'TestOperation': {
                    'name': 'TestOperation',
                    'http': {
                        'method': 'POST',
                        'requestUri': '/',
                    },
                    'input': {'shape': 'TestOperationRequest'},
                    'errors': [{'shape': 'TestOperationException'}],
                    'documentation': 'Documents TestOperation',
                }
            },
            'shapes': {
                'TestOperationRequest': {
                    'type': 'structure',
                    'required': ['Foo'],
                    'members': {
                        'Foo': {
                            'shape': 'StringType',
                            'documentation': 'Documents Foo',
                        },
                        'Bar': {
                            'shape': 'StringType',
                            'documentation': 'Documents Bar',
                        },
                    },
                },
                "TestOperationException": {
                    'type': 'structure',
                    'exception': True,
                    'error': {'code': 'TestOperationErrorCode'},
                },
                'StringType': {'type': 'string'},
            },
        }
        self.endpoint_ruleset = {
            "version": "1.0",
            "parameters": {},
            "rules": [
                {
                    "conditions": [],
                    "type": "endpoint",
                    "endpoint": {
                        "url": "https://foo.bar",
                        "properties": {},
                        "headers": {},
                    },
                }
            ],
        }
        self.retry_config = {
            "retry": {
                "__default__": {
                    "max_attempts": 5,
                    "delay": {
                        "type": "exponential",
                        "base": "rand",
                        "growth_factor": 2,
                    },
                    "policies": {},
                }
            }
        }

        def load_service_mock(*args, **kwargs):
            if args[1] == "service-2":
                return self.service_description

        self.loader = mock.Mock()
        self.loader.load_service_model.side_effect = load_service_mock
        self.loader.load_data.return_value = self.retry_config

        self.credentials = Credentials('access-key', 'secret-key')

        self.endpoint_creator_patch = mock.patch(
            'botocore.args.EndpointCreator'
        )
        self.endpoint_creator_cls = self.endpoint_creator_patch.start()
        self.endpoint_creator = self.endpoint_creator_cls.return_value

        self.endpoint = mock.Mock()
        self.endpoint.host = 'https://myservice.amazonaws.com'
        self.endpoint.make_request.return_value = (
            mock.Mock(status_code=200),
            {},
        )
        self.endpoint_creator.create_endpoint.return_value = self.endpoint

        self.resolver = mock.Mock()
        self.endpoint_data = {
            'partition': 'aws',
            'hostname': 'foo',
            'endpointName': 'us-west-2',
            'signatureVersions': ['v4'],
        }
        self.resolver.construct_endpoint.return_value = self.endpoint_data
        self.resolver.get_available_endpoints.return_value = ['us-west-2']
        self.config_store = ConfigValueStore()

    def tearDown(self):
        self.endpoint_creator_patch.stop()

    def create_mock_emitter(self, responses=None):
        if responses is None:
            responses = []

        emitter = mock.Mock()
        emitter.emit.return_value = responses
        return emitter

    def create_client_creator(
        self,
        endpoint_creator=None,
        event_emitter=None,
        retry_handler_factory=None,
        retry_config_translator=None,
        response_parser_factory=None,
        endpoint_prefix=None,
        exceptions_factory=None,
        config_store=None,
        user_agent_creator=None,
    ):
        if event_emitter is None:
            event_emitter = hooks.HierarchicalEmitter()
        if retry_handler_factory is None:
            retry_handler_factory = botocore.retryhandler
        if retry_config_translator is None:
            retry_config_translator = botocore.translate
        if endpoint_prefix is not None:
            self.service_description['metadata'][
                'endpointPrefix'
            ] = endpoint_prefix

        if endpoint_creator is not None:
            self.endpoint_creator_cls.return_value = endpoint_creator
        if exceptions_factory is None:
            exceptions_factory = ClientExceptionsFactory()
        if config_store is None:
            config_store = self.config_store
        if user_agent_creator is None:
            user_agent_creator = (
                UserAgentString.from_environment().set_session_config(
                    session_user_agent_name='MyUserAgent',
                    session_user_agent_version='1.2.3-rc5',
                    session_user_agent_extra=None,
                )
            )
        creator = client.ClientCreator(
            self.loader,
            self.resolver,
            'user-agent',
            event_emitter,
            retry_handler_factory,
            retry_config_translator,
            response_parser_factory,
            exceptions_factory,
            config_store,
            user_agent_creator,
        )
        return creator

    def assert_no_param_error_raised(self, client):
        try:
            self.make_api_call_with_missing_param(client)
        except ParamValidationError:
            self.fail(
                "ParamValidationError shouldn't be raised "
                "with validation disabled"
            )

    def make_api_call_with_missing_param(self, service_client):
        # Missing required 'Foo' param.
        service_client.test_operation(Bar='two')


class TestAutoGeneratedClient(BaseClientTest):
    def test_client_name(self):
        creator = self.create_client_creator()
        service_client = creator.create_client(
            'myservice', 'us-west-2', credentials=self.credentials
        )
        self.assertTrue(service_client.__class__.__name__, 'MyService')

    def test_client_name_with_amazon(self):
        self.service_description['metadata'][
            'serviceFullName'
        ] = 'Amazon MyService'
        creator = self.create_client_creator()
        service_client = creator.create_client(
            'myservice', 'us-west-2', credentials=self.credentials
        )
        self.assertTrue(service_client.__class__.__name__, 'MyService')

    def test_client_name_using_abreviation(self):
        self.service_description['metadata'][
            'serviceAbbreviation'
        ] = 'Abbreviation'
        creator = self.create_client_creator()
        service_client = creator.create_client(
            'myservice', 'us-west-2', credentials=self.credentials
        )
        self.assertTrue(service_client.__class__.__name__, 'Abbreviation')

    def test_client_name_with_non_alphabet_characters(self):
        self.service_description['metadata'][
            'serviceFullName'
        ] = 'Amazon My-Service'
        creator = self.create_client_creator()
        service_client = creator.create_client(
            'myservice', 'us-west-2', credentials=self.credentials
        )
        self.assertTrue(service_client.__class__.__name__, 'MyService')

    def test_client_name_with_no_full_name_or_abbreviation(self):
        del self.service_description['metadata']['serviceFullName']
        creator = self.create_client_creator()
        service_client = creator.create_client(
            'myservice', 'us-west-2', credentials=self.credentials
        )
        self.assertTrue(service_client.__class__.__name__, 'myservice')

    def test_client_generated_from_model(self):
        creator = self.create_client_creator()
        service_client = creator.create_client(
            'myservice', 'us-west-2', credentials=self.credentials
        )
        self.assertTrue(hasattr(service_client, 'test_operation'))

    def test_client_with_nonstandard_signature_version(self):
        self.service_description['metadata']['signatureVersion'] = 'foo'
        creator = self.create_client_creator()
        foo_signer = mock.Mock(spec=BaseSigner)

        auth_types = AUTH_TYPE_MAPS.copy()
        auth_types['foo'] = foo_signer

        with mock.patch('botocore.client.AUTH_TYPE_MAPS', auth_types):
            service_client = creator.create_client(
                'myservice', 'us-west-2', credentials=self.credentials
            )
        assert service_client.meta.config.signature_version == 'foo'

    def test_client_method_docstring(self):
        creator = self.create_client_creator()
        service_client = creator.create_client(
            'myservice', 'us-west-2', credentials=self.credentials
        )
        method_docstring = str(service_client.test_operation.__doc__)
        ref_docstring_lines = [
            'Documents TestOperation',
            '**Request Syntax**',
            '  response = client.test_operation(',
            '      Bar=\'string\'',
            '      Foo=\'string\'',
            '  )',
            ':type Bar: string',
            ':param Bar: Documents Bar',
            ':type Foo: string',
            ':param Foo: **[REQUIRED]** Documents Foo',
        ]
        for line in ref_docstring_lines:
            self.assertIn(line, method_docstring)

    def test_client_method_help(self):
        creator = self.create_client_creator()
        service_client = creator.create_client(
            'myservice', 'us-west-2', credentials=self.credentials
        )
        with mock.patch('sys.stdout', io.StringIO()) as mock_stdout:
            help(service_client.test_operation)
        method_docstring = mock_stdout.getvalue()
        ref_docstring_lines = [
            'Documents TestOperation',
            '**Request Syntax**',
            '  response = client.test_operation(',
            '      Bar=\'string\'',
            '      Foo=\'string\'',
            '  )',
            ':type Bar: string',
            ':param Bar: Documents Bar',
            ':type Foo: string',
            ':param Foo: **[REQUIRED]** Documents Foo',
        ]
        for line in ref_docstring_lines:
            self.assertIn(line, method_docstring)

    def test_client_create_unicode(self):
        creator = self.create_client_creator()
        service_client = creator.create_client(
            'myservice', 'us-west-2', credentials=self.credentials
        )
        self.assertTrue(hasattr(service_client, 'test_operation'))

    def test_client_has_region_name_on_meta(self):
        creator = self.create_client_creator()
        region_name = 'us-west-2'
        self.endpoint.region_name = region_name
        service_client = creator.create_client(
            'myservice', region_name, credentials=self.credentials
        )
        self.assertEqual(service_client.meta.region_name, region_name)

    def test_client_has_endpoint_url_on_meta(self):
        creator = self.create_client_creator()
        self.endpoint.host = 'https://foo.bar'
        service_client = creator.create_client(
            'myservice', 'us-west-2', credentials=self.credentials
        )
        self.assertEqual(service_client.meta.endpoint_url, 'https://foo.bar')

    def test_client_has_standard_partition_on_meta(self):
        creator = self.create_client_creator()
        service_client = creator.create_client(
            'myservice', 'us-west-2', credentials=self.credentials
        )
        self.assertEqual(service_client.meta.partition, 'aws')

    def test_client_has_non_standard_partition_on_meta(self):
        creator = self.create_client_creator()
        self.resolver.construct_endpoint.return_value = {
            'partition': 'aws-cn',
            'hostname': 'foo',
            'endpointName': 'cn-north-1',
            'signatureVersions': ['v4'],
        }
        service_client = creator.create_client(
            'myservice', 'cn-north-1', credentials=self.credentials
        )
        self.assertEqual(service_client.meta.partition, 'aws-cn')

    def test_client_has_exceptions_attribute(self):
        creator = self.create_client_creator()
        service_client = creator.create_client(
            'myservice', 'us-west-2', credentials=self.credentials
        )
        self.assertTrue(hasattr(service_client, 'exceptions'))

    def test_client_has_modeled_exceptions(self):
        creator = self.create_client_creator()
        service_client = creator.create_client(
            'myservice', 'us-west-2', credentials=self.credentials
        )
        self.assertTrue(
            issubclass(
                service_client.exceptions.TestOperationException,
                client.ClientError,
            )
        )

    def test_client_fips_region_transformation(self):
        creator = self.create_client_creator()
        with self.assertLogs('botocore.client', level='WARNING') as log:
            creator.create_client(
                'myservice', 'fips-us-west-2', credentials=self.credentials
            )
            self.assertIn('fips-us-west-2 to us-west-2', log.output[0])

    def test_api_version_is_passed_to_loader_if_provided(self):
        creator = self.create_client_creator()
        self.endpoint.host = 'https://foo.bar'
        specific_api_version = '2014-03-01'
        creator.create_client(
            'myservice',
            'us-west-2',
            credentials=self.credentials,
            api_version=specific_api_version,
        )
        calls = [
            mock.call(
                'myservice', 'service-2', api_version=specific_api_version
            ),
            mock.call(
                'myservice',
                'endpoint-rule-set-1',
                api_version=specific_api_version,
            ),
        ]
        self.loader.load_service_model.assert_has_calls(calls)

    def test_create_client_class_creates_class(self):
        creator = self.create_client_creator()
        client_class = creator.create_client_class('myservice')
        self.assertTrue(hasattr(client_class, 'test_operation'))

    def test_create_client_class_forwards_api_version(self):
        creator = self.create_client_creator()
        specific_api_version = '2014-03-01'
        creator.create_client_class(
            'myservice', api_version=specific_api_version
        )
        self.loader.load_service_model.assert_called_with(
            'myservice', 'service-2', api_version=specific_api_version
        )

    def test_signing_region_does_not_change_client_region(self):
        with mock.patch('botocore.args.RequestSigner') as mock_signer:
            credential_scope_region = 'us-east-1'
            self.resolver.construct_endpoint.return_value = {
                'partition': 'aws',
                'hostname': 'endpoint.url',
                'endpointName': 'us-west-2',
                'signatureVersions': ['v4'],
                'credentialScope': {'region': credential_scope_region},
            }
            creator = self.create_client_creator()
            service_client = creator.create_client(
                'myservice', 'us-west-2', credentials=self.credentials
            )
            self.assertEqual(service_client.meta.region_name, 'us-west-2')
            call_args = mock_signer.call_args
            self.assertEqual(credential_scope_region, call_args[0][1])

    def test_client_uses_signing_region_from_credential_scope(self):
        with mock.patch('botocore.args.RequestSigner') as mock_signer:
            credential_scope_region = 'us-east-1'
            self.resolver.construct_endpoint.return_value = {
                'partition': 'aws',
                'endpointName': 'us-west-2',
                'hostname': 'endpoint.url',
                'signatureVersions': ['v4'],
                'credentialScope': {'region': credential_scope_region},
            }
            creator = self.create_client_creator()
            service_client = creator.create_client(
                service_name='myservice',
                region_name='us-west-2',
                credentials=self.credentials,
            )
            # Use the resolved region as the region value.
            self.assertEqual(service_client.meta.region_name, 'us-west-2')
            # Ensure that we use the credential scope region for signing,
            # and not the resolved region name.
            call_args = mock_signer.call_args
            self.assertEqual(credential_scope_region, call_args[0][1])

    def test_client_uses_signing_name_from_credential_scope(self):
        with mock.patch('botocore.args.RequestSigner') as mock_signer:
            self.resolver.construct_endpoint.return_value = {
                'partition': 'aws',
                'endpointName': 'us-west-2',
                'hostname': 'endpoint.url',
                'signatureVersions': ['v4'],
                'credentialScope': {'service': 'override'},
            }
            creator = self.create_client_creator()
            creator.create_client(
                service_name='myservice',
                region_name='us-west-2',
                credentials=self.credentials,
            )
            call_args = mock_signer.call_args
            self.assertEqual('MyService', call_args[0][0])
            self.assertEqual('override', call_args[0][2])

    def test_client_uses_given_region_name_and_endpoint_url_when_present(self):
        with mock.patch('botocore.args.RequestSigner') as mock_signer:
            credential_scope_region = 'us-east-1'
            self.resolver.construct_endpoint.return_value = {
                'partition': 'aws',
                'endpointName': 'us-west-2',
                'hostname': 'endpoint.url',
                'signatureVersions': ['v4'],
                'credentialScope': {'region': credential_scope_region},
            }
            creator = self.create_client_creator()
            service_client = creator.create_client(
                service_name='myservice',
                region_name='us-west-2',
                credentials=self.credentials,
                endpoint_url='https://foo',
            )
            self.assertEqual(service_client.meta.region_name, 'us-west-2')
            call_args = mock_signer.call_args
            self.assertEqual('us-west-2', call_args[0][1])

    def test_client_uses_signing_name_from_model_if_present_if_resolved(self):
        self.service_description['metadata']['signingName'] = 'otherName'
        with mock.patch('botocore.args.RequestSigner') as mock_signer:
            self.resolver.construct_endpoint.return_value = {
                'partition': 'aws',
                'endpointName': 'us-west-2',
                'hostname': 'endpoint.url',
                'signatureVersions': ['v4'],
            }
            creator = self.create_client_creator()
            service_client = creator.create_client(
                service_name='myservice',
                region_name='us-west-2',
                credentials=self.credentials,
                endpoint_url='https://foo',
            )
            self.assertEqual(service_client.meta.region_name, 'us-west-2')
            call_args = mock_signer.call_args[0]
            self.assertEqual('otherName', call_args[2])

    def test_client_uses_signing_name_even_with_no_resolve(self):
        self.service_description['metadata']['signingName'] = 'otherName'
        with mock.patch('botocore.args.RequestSigner') as mock_signer:
            self.resolver.construct_endpoint.return_value = {}
            creator = self.create_client_creator()
            service_client = creator.create_client(
                service_name='myservice',
                region_name='us-west-2',
                credentials=self.credentials,
                endpoint_url='https://foo',
            )
            self.assertEqual(service_client.meta.region_name, 'us-west-2')
            call_args = mock_signer.call_args[0]
            self.assertEqual('otherName', call_args[2])

    @mock.patch('botocore.args.RequestSigner')
    def test_client_signature_no_override(self, request_signer):
        creator = self.create_client_creator()
        creator.create_client(
            'myservice',
            'us-west-2',
            credentials=self.credentials,
            scoped_config={},
        )
        request_signer.assert_called_with(
            mock.ANY,
            mock.ANY,
            mock.ANY,
            'v4',
            mock.ANY,
            mock.ANY,
            mock.ANY,
        )

    @mock.patch('botocore.args.RequestSigner')
    def test_client_signature_override_config_file(self, request_signer):
        creator = self.create_client_creator()
        config = {'myservice': {'signature_version': 'foo'}}
        creator.create_client(
            'myservice',
            'us-west-2',
            credentials=self.credentials,
            scoped_config=config,
        )
        request_signer.assert_called_with(
            mock.ANY,
            mock.ANY,
            mock.ANY,
            'foo',
            mock.ANY,
            mock.ANY,
            mock.ANY,
        )

    @mock.patch('botocore.args.RequestSigner')
    def test_client_signature_override_arg(self, request_signer):
        creator = self.create_client_creator()
        config = botocore.config.Config(signature_version='foo')
        creator.create_client(
            'myservice',
            'us-west-2',
            credentials=self.credentials,
            client_config=config,
        )
        request_signer.assert_called_with(
            mock.ANY,
            mock.ANY,
            mock.ANY,
            'foo',
            mock.ANY,
            mock.ANY,
            mock.ANY,
        )

    def test_client_method_to_api_mapping(self):
        creator = self.create_client_creator()
        service_client = creator.create_client('myservice', 'us-west-2')
        self.assertEqual(
            service_client.meta.method_to_api_mapping,
            {'test_operation': 'TestOperation'},
        )

    def test_anonymous_client_request(self):
        creator = self.create_client_creator()
        config = botocore.config.Config(signature_version=botocore.UNSIGNED)
        service_client = creator.create_client(
            'myservice', 'us-west-2', client_config=config
        )

        service_client.test_operation(Foo='one')

        # Make sure a request has been attempted
        self.assertTrue(self.endpoint.make_request.called)

        # Make sure the request parameters do NOT include auth
        # information. The service defined above for these tests
        # uses sigv4 by default (which we disable).
        params = {
            k.lower(): v
            for k, v in self.endpoint.make_request.call_args[0][1].items()
        }
        self.assertNotIn('authorization', params)
        self.assertNotIn('x-amz-signature', params)

    def test_client_user_agent_in_request(self):
        creator = self.create_client_creator()
        service_client = creator.create_client('myservice', 'us-west-2')

        service_client.test_operation(Foo='one')

        self.assertTrue(self.endpoint.make_request.called)
        params = {
            k.lower(): v
            for k, v in self.endpoint.make_request.call_args[0][1].items()
        }
        self.assertIn('MyUserAgent/1.2.3', params['headers']['User-Agent'])

    def test_client_custom_user_agent_in_request(self):
        creator = self.create_client_creator()
        config = botocore.config.Config(user_agent='baz')
        service_client = creator.create_client(
            'myservice', 'us-west-2', client_config=config
        )

        service_client.test_operation(Foo='one')

        self.assertTrue(self.endpoint.make_request.called)
        params = {
            k.lower(): v
            for k, v in self.endpoint.make_request.call_args[0][1].items()
        }
        self.assertEqual(params['headers']['User-Agent'], 'baz')

    def test_client_custom_user_agent_extra_in_request(self):
        creator = self.create_client_creator()
        config = botocore.config.Config(user_agent_extra='extrastuff')
        service_client = creator.create_client(
            'myservice', 'us-west-2', client_config=config
        )
        service_client.test_operation(Foo='one')
        headers = self.endpoint.make_request.call_args[0][1]['headers']
        self.assertTrue(headers['User-Agent'].endswith('extrastuff'))

    def test_client_registers_request_created_handler(self):
        event_emitter = self.create_mock_emitter()
        creator = self.create_client_creator(event_emitter=event_emitter)
        creator.create_client(
            'myservice', 'us-west-2', credentials=self.credentials
        )
        self.assertIn(
            mock.call('request-created.myservice', mock.ANY),
            event_emitter.register.call_args_list,
        )

    def test_client_makes_call(self):
        creator = self.create_client_creator()
        service_client = creator.create_client(
            'myservice', 'us-west-2', credentials=self.credentials
        )

        self.assertTrue(self.endpoint_creator.create_endpoint.called)

        response = service_client.test_operation(Foo='one', Bar='two')
        self.assertEqual(response, {})

    def test_client_error_message_for_positional_args(self):
        creator = self.create_client_creator()
        service_client = creator.create_client(
            'myservice', 'us-west-2', credentials=self.credentials
        )
        with self.assertRaisesRegex(
            TypeError, 'only accepts keyword arguments'
        ):
            service_client.test_operation('foo')

    @mock.patch('botocore.args.RequestSigner.sign')
    def test_client_signs_call(self, signer_mock):
        creator = self.create_client_creator()
        service_client = creator.create_client(
            'myservice', 'us-west-2', credentials=self.credentials
        )
        request = mock.Mock()

        # Emit the request created event to see if it would be signed.
        # We tested above to ensure this event is registered when
        # a client is created. This prevents testing the entire client
        # call logic.
        service_client.meta.events.emit(
            'request-created.myservice.test_operation',
            request=request,
            operation_name='test_operation',
        )

        signer_mock.assert_called_with('test_operation', request)

    def test_client_validates_params_by_default(self):
        creator = self.create_client_creator()

        service_client = creator.create_client(
            'myservice', 'us-west-2', credentials=self.credentials
        )
        with self.assertRaises(ParamValidationError):
            self.make_api_call_with_missing_param(service_client)

    def test_client_doesnt_validate_params_when_validation_disabled(self):
        creator = self.create_client_creator()

        client_config = botocore.config.Config()
        client_config.parameter_validation = False
        service_client = creator.create_client(
            'myservice',
            'us-west-2',
            credentials=self.credentials,
            client_config=client_config,
        )

        self.assert_no_param_error_raised(service_client)

    def test_can_disable_param_validation_from_scoped_config(self):
        creator = self.create_client_creator()
        service_client = creator.create_client(
            'myservice',
            'us-west-2',
            credentials=self.credentials,
            scoped_config={'parameter_validation': False},
        )
        self.assert_no_param_error_raised(service_client)

    def test_client_config_trumps_scoped_config(self):
        creator = self.create_client_creator()
        scoped_config = {'parameter_validation': True}
        client_config = botocore.config.Config(parameter_validation=False)
        # Client config should win and param validation is disabled.
        service_client = creator.create_client(
            'myservice',
            'us-west-2',
            credentials=self.credentials,
            scoped_config=scoped_config,
            client_config=client_config,
        )
        self.assert_no_param_error_raised(service_client)

    def test_client_with_custom_both_timeout(self):
        self.create_client_creator().create_client(
            'myservice',
            'us-west-2',
            client_config=botocore.config.Config(
                connect_timeout=123, read_timeout=234
            ),
        )
        call_kwargs = self.endpoint_creator.create_endpoint.call_args[1]
        self.assertEqual(call_kwargs['timeout'], (123, 234))

    def test_client_with_custom_connect_timeout(self):
        self.create_client_creator().create_client(
            'myservice',
            'us-west-2',
            client_config=botocore.config.Config(connect_timeout=123),
        )
        call_kwargs = self.endpoint_creator.create_endpoint.call_args[1]
        self.assertEqual(call_kwargs['timeout'], (123, DEFAULT_TIMEOUT))

    def test_client_with_custom_read_timeout(self):
        self.create_client_creator().create_client(
            'myservice',
            'us-west-2',
            client_config=botocore.config.Config(read_timeout=234),
        )
        call_kwargs = self.endpoint_creator.create_endpoint.call_args[1]
        self.assertEqual(call_kwargs['timeout'], (DEFAULT_TIMEOUT, 234))

    def test_client_with_custom_neither_timeout(self):
        self.create_client_creator().create_client('myservice', 'us-west-2')
        call_kwargs = self.endpoint_creator.create_endpoint.call_args[1]
        self.assertEqual(
            call_kwargs['timeout'], (DEFAULT_TIMEOUT, DEFAULT_TIMEOUT)
        )

    def test_client_with_custom_params(self):
        creator = self.create_client_creator()
        creator.create_client(
            'myservice', 'us-west-2', is_secure=False, verify=False
        )
        call_kwargs = self.endpoint_creator.create_endpoint.call_args[1]
        self.assertFalse(call_kwargs['verify'])
        self.assertNotIn('is_secure', call_kwargs)

    def test_client_with_custom_proxy_config(self):
        proxies_config = {
            'proxy_ca_bundle': 'foo_ca_bundle',
            'proxy_client_cert': 'foo_cert',
            'proxy_use_forwarding_for_https': False,
        }
        self.create_client_creator().create_client(
            'myservice',
            'us-west-2',
            client_config=botocore.config.Config(
                proxies_config=proxies_config
            ),
        )
        call_kwargs = self.endpoint_creator.create_endpoint.call_args[1]
        self.assertEqual(call_kwargs['proxies_config'], proxies_config)

    def test_client_with_endpoint_url(self):
        creator = self.create_client_creator()
        creator.create_client(
            'myservice', 'us-west-2', endpoint_url='http://custom.foo'
        )
        call_kwargs = self.endpoint_creator.create_endpoint.call_args[1]
        self.assertEqual(call_kwargs['endpoint_url'], 'http://custom.foo')

    def test_client_can_use_guessed_endpoints(self):
        # Ensure the resolver returns None (meaning a guess is made)
        self.resolver.construct_endpoint.return_value = None
        creator = self.create_client_creator()
        client = creator.create_client('myservice', region_name='invalid')
        self.assertEqual('invalid', client.meta.region_name)

    def test_client_with_response_parser_factory(self):
        factory = mock.Mock()
        creator = self.create_client_creator(response_parser_factory=factory)
        creator.create_client('myservice', 'us-west-2')
        call_kwargs = self.endpoint_creator.create_endpoint.call_args[1]
        self.assertEqual(call_kwargs['response_parser_factory'], factory)

    def test_operation_cannot_paginate(self):
        pagination_config = {
            'pagination': {
                # Note that there's no pagination config for
                # 'TestOperation', indicating that TestOperation
                # is not pageable.
                'SomeOtherOperation': {
                    "input_token": "Marker",
                    "output_token": "Marker",
                    "more_results": "IsTruncated",
                    "limit_key": "MaxItems",
                    "result_key": "Users",
                }
            }
        }
        self.loader.load_service_model.side_effect = [
            self.service_description,
            self.endpoint_ruleset,
            pagination_config,
        ]
        creator = self.create_client_creator()
        service_client = creator.create_client('myservice', 'us-west-2')
        self.assertFalse(service_client.can_paginate('test_operation'))

    def test_operation_can_paginate(self):
        pagination_config = {
            'pagination': {
                'TestOperation': {
                    "input_token": "Marker",
                    "output_token": "Marker",
                    "more_results": "IsTruncated",
                    "limit_key": "MaxItems",
                    "result_key": "Users",
                }
            }
        }
        self.loader.load_service_model.side_effect = [
            self.service_description,
            self.endpoint_ruleset,
            pagination_config,
        ]
        creator = self.create_client_creator()
        service_client = creator.create_client('myservice', 'us-west-2')
        self.assertTrue(service_client.can_paginate('test_operation'))
        # Also, the config is cached, but we want to make sure we get
        # the same answer when we ask again.
        self.assertTrue(service_client.can_paginate('test_operation'))

    def test_service_has_no_pagination_configs(self):
        # This is the case where there is an actual *.paginator.json, file,
        # but the specific operation itself is not actually pageable.
        # If the loader cannot load pagination configs, it communicates
        # this by raising a DataNotFoundError.
        self.loader.load_service_model.side_effect = [
            self.service_description,
            self.endpoint_ruleset,
            exceptions.DataNotFoundError(data_path='/foo'),
        ]
        creator = self.create_client_creator()
        service_client = creator.create_client('myservice', 'us-west-2')
        self.assertFalse(service_client.can_paginate('test_operation'))

    def test_waiter_config_uses_service_name_not_endpoint_prefix(self):
        waiter_config = {'version': 2, 'waiters': {}}
        self.loader.load_service_model.side_effect = [
            self.service_description,
            self.endpoint_ruleset,
            waiter_config,
        ]
        creator = self.create_client_creator()
        # We're going to verify that the loader loads a service called
        # 'other-service-name', and even though the endpointPrefix is
        # 'myservice', we use 'other-service-name' for waiters/paginators, etc.
        service_client = creator.create_client(
            'other-service-name', 'us-west-2'
        )
        self.assertEqual(service_client.waiter_names, [])
        # Note we're using other-service-name, not
        # 'myservice', which is the endpointPrefix.
        self.loader.load_service_model.assert_called_with(
            'other-service-name', 'waiters-2', '2014-01-01'
        )

    def test_service_has_waiter_configs(self):
        waiter_config = {
            'version': 2,
            'waiters': {
                "Waiter1": {
                    'operation': 'TestOperation',
                    'delay': 5,
                    'maxAttempts': 20,
                    'acceptors': [],
                },
                "Waiter2": {
                    'operation': 'TestOperation',
                    'delay': 5,
                    'maxAttempts': 20,
                    'acceptors': [],
                },
            },
        }
        self.loader.load_service_model.side_effect = [
            self.service_description,
            self.endpoint_ruleset,
            waiter_config,
        ]
        creator = self.create_client_creator()
        service_client = creator.create_client('myservice', 'us-west-2')
        self.assertEqual(
            sorted(service_client.waiter_names), sorted(['waiter1', 'waiter2'])
        )
        self.assertTrue(hasattr(service_client.get_waiter('waiter1'), 'wait'))

    def test_service_has_no_waiter_configs(self):
        self.loader.load_service_model.side_effect = [
            self.service_description,
            self.endpoint_ruleset,
            exceptions.DataNotFoundError(data_path='/foo'),
        ]
        creator = self.create_client_creator()
        service_client = creator.create_client('myservice', 'us-west-2')
        self.assertEqual(service_client.waiter_names, [])
        with self.assertRaises(ValueError):
            service_client.get_waiter("unknown_waiter")

    def test_service_has_retry_event(self):
        # A retry event should be registered for the service.
        event_emitter = self.create_mock_emitter()
        creator = self.create_client_creator(event_emitter=event_emitter)
        creator.create_client('myservice', 'us-west-2')

        event_emitter.register.assert_any_call(
            'needs-retry.myservice',
            mock.ANY,
            unique_id='retry-config-myservice',
        )

    def test_service_creates_retryhandler(self):
        # A retry handler with the expected configuration should be
        # created when instantiating a client.
        retry_handler_factory = mock.Mock()
        creator = self.create_client_creator(
            retry_handler_factory=retry_handler_factory
        )
        creator.create_client('myservice', 'us-west-2')

        retry_handler_factory.create_retry_handler.assert_called_with(
            {
                '__default__': {
                    'delay': {
                        'growth_factor': 2,
                        'base': 'rand',
                        'type': 'exponential',
                    },
                    'policies': {},
                    'max_attempts': 5,
                }
            },
            'myservice',
        )

    def test_service_registers_retry_handler(self):
        # The retry handler returned from ``create_retry_handler``
        # that was tested above needs to be set as the handler for
        # the event emitter.
        retry_handler_factory = mock.Mock()
        handler = mock.Mock()
        event_emitter = self.create_mock_emitter()
        retry_handler_factory.create_retry_handler.return_value = handler

        creator = self.create_client_creator(
            event_emitter=event_emitter,
            retry_handler_factory=retry_handler_factory,
        )
        creator.create_client('myservice', 'us-west-2')

        event_emitter.register.assert_any_call(
            mock.ANY, handler, unique_id=mock.ANY
        )

    def test_service_retry_missing_config(self):
        # No config means we should never see any retry events registered.
        self.loader.load_data.return_value = {}

        event_emitter = self.create_mock_emitter()
        creator = self.create_client_creator(event_emitter=event_emitter)
        creator.create_client('myservice', 'us-west-2')

        for call in event_emitter.register.call_args_list:
            self.assertNotIn('needs-retry', call[0][0])

    def test_emits_after_call_error(self):
        event_emitter = hooks.HierarchicalEmitter()

        recorded_kwargs = []

        def record(event_name, **kwargs):
            recorded_kwargs.append(kwargs)

        event_emitter.register(
            'after-call-error.myservice.TestOperation', record
        )

        raised_error = RuntimeError('Unexpected error')
        self.endpoint.make_request.side_effect = raised_error
        creator = self.create_client_creator(event_emitter=event_emitter)
        client = creator.create_client('myservice', 'us-west-2')
        with self.assertRaises(RuntimeError):
            client.test_operation(Foo='one', Bar='two')
        self.assertEqual(
            recorded_kwargs, [{'exception': raised_error, 'context': mock.ANY}]
        )

    def test_can_override_max_attempts(self):
        retry_handler_factory = mock.Mock(botocore.retryhandler)
        creator = self.create_client_creator(
            retry_handler_factory=retry_handler_factory
        )
        creator.create_client(
            'myservice',
            'us-west-2',
            client_config=botocore.config.Config(
                retries={'max_attempts': 9, 'mode': 'legacy'}
            ),
        )

        retry_handler_factory.create_retry_handler.assert_called_with(
            {
                '__default__': {
                    'delay': {
                        'growth_factor': 2,
                        'base': 'rand',
                        'type': 'exponential',
                    },
                    'policies': {},
                    'max_attempts': 10,
                }
            },
            'myservice',
        )

    def test_can_register_standard_retry_mode(self):
        with mock.patch('botocore.client.standard') as standard:
            creator = self.create_client_creator()
            creator.create_client(
                'myservice',
                'us-west-2',
                client_config=botocore.config.Config(
                    retries={'mode': 'standard'}
                ),
            )
        self.assertTrue(standard.register_retry_handler.called)

    def test_can_register_standard_retry_mode_from_config_store(self):
        fake_env = {'AWS_RETRY_MODE': 'standard'}
        config_store = ConfigValueStore(
            mapping={
                'retry_mode': ChainProvider(
                    [
                        EnvironmentProvider('AWS_RETRY_MODE', fake_env),
                    ]
                )
            }
        )
        creator = self.create_client_creator(config_store=config_store)
        with mock.patch('botocore.client.standard') as standard:
            creator.create_client('myservice', 'us-west-2')
        self.assertTrue(standard.register_retry_handler.called)

    def test_try_to_paginate_non_paginated(self):
        self.loader.load_service_model.side_effect = [
            self.service_description,
            self.endpoint_ruleset,
            exceptions.DataNotFoundError(data_path='/foo'),
        ]
        creator = self.create_client_creator()
        service_client = creator.create_client('myservice', 'us-west-2')
        with self.assertRaises(exceptions.OperationNotPageableError):
            service_client.get_paginator('test_operation')

    def test_successful_pagination_object_created(self):
        pagination_config = {
            'pagination': {
                'TestOperation': {
                    "input_token": "Marker",
                    "output_token": "Marker",
                    "more_results": "IsTruncated",
                    "limit_key": "MaxItems",
                    "result_key": "Users",
                }
            }
        }
        self.loader.load_service_model.side_effect = [
            self.service_description,
            self.endpoint_ruleset,
            pagination_config,
        ]
        creator = self.create_client_creator()
        service_client = creator.create_client('myservice', 'us-west-2')
        paginator = service_client.get_paginator('test_operation')
        # The pagination logic itself is tested elsewhere (test_paginate.py),
        # but we can at least make sure it looks like a paginator.
        self.assertTrue(hasattr(paginator, 'paginate'))

    def test_paginator_class_name_from_client(self):
        pagination_config = {
            'pagination': {
                'TestOperation': {
                    "input_token": "Marker",
                    "output_token": "Marker",
                    "more_results": "IsTruncated",
                    "limit_key": "MaxItems",
                    "result_key": "Users",
                }
            }
        }
        self.loader.load_service_model.side_effect = [
            self.service_description,
            self.endpoint_ruleset,
            pagination_config,
        ]
        creator = self.create_client_creator()
        service_client = creator.create_client('myservice', 'us-west-2')
        paginator = service_client.get_paginator('test_operation')
        self.assertEqual(
            paginator.__class__.__name__, 'MyService.Paginator.TestOperation'
        )

    def test_paginator_help_from_client(self):
        pagination_config = {
            'pagination': {
                'TestOperation': {
                    "input_token": "Marker",
                    "output_token": "Marker",
                    "more_results": "IsTruncated",
                    "limit_key": "MaxItems",
                    "result_key": "Users",
                }
            }
        }
        self.loader.load_service_model.side_effect = [
            self.service_description,
            self.endpoint_ruleset,
            pagination_config,
        ]
        creator = self.create_client_creator()
        service_client = creator.create_client('myservice', 'us-west-2')
        paginator = service_client.get_paginator('test_operation')
        with mock.patch('sys.stdout', io.StringIO()) as mock_stdout:
            help(paginator.paginate)
        contents = mock_stdout.getvalue()
        lines = [
            (
                '    Creates an iterator that will paginate through responses '
                'from :py:meth:`MyService.Client.test_operation`.'
            ),
            '    **Request Syntax**',
            '    ::',
            '      response_iterator = paginator.paginate(',
            "          Foo='string',",
            "          Bar='string',",
            '          PaginationConfig={',
            "              'MaxItems': 123,",
            "              'PageSize': 123,",
            "              'StartingToken': 'string'",
            '          }',
            '      )',
            '    :type Foo: string',
            '    :param Foo: **[REQUIRED]** Documents Foo',
            '    :type Bar: string',
            '    :param Bar: Documents Bar',
            '    :type PaginationConfig: dict',
            '    :param PaginationConfig: ',
            (
                '      A dictionary that provides parameters to control '
                'pagination.'
            ),
            '      - **MaxItems** *(integer) --*',
            (
                '        The total number of items to return. If the total '
                'number of items available is more than the value specified '
                'in max-items then a ``NextToken`` will be provided in the '
                'output that you can use to resume pagination.'
            ),
            '      - **PageSize** *(integer) --*',
            '        The size of each page.',
            '      - **StartingToken** *(string) --*',
            (
                '        A token to specify where to start paginating. This is '
                'the ``NextToken`` from a previous response.'
            ),
            '    :returns: None',
        ]
        for line in lines:
            self.assertIn(line, contents)

    def test_can_set_credentials_in_client_init(self):
        creator = self.create_client_creator()
        credentials = Credentials(
            access_key='access_key',
            secret_key='secret_key',
            token='session_token',
        )
        client = creator.create_client(
            'myservice', 'us-west-2', credentials=credentials
        )

        # Verify that we create an endpoint with a credentials object
        # matching our creds arguments.
        self.assertEqual(client._request_signer._credentials, credentials)

    def test_event_emitted_when_invoked(self):
        event_emitter = hooks.HierarchicalEmitter()
        creator = self.create_client_creator(event_emitter=event_emitter)

        calls = []
        handler = lambda **kwargs: calls.append(kwargs)
        event_emitter.register('before-call', handler)

        service_client = creator.create_client(
            'myservice', 'us-west-2', credentials=self.credentials
        )
        service_client.test_operation(Foo='one', Bar='two')
        self.assertEqual(len(calls), 1)

    def test_events_are_per_client(self):
        event_emitter = hooks.HierarchicalEmitter()
        creator = self.create_client_creator(event_emitter=event_emitter)

        first_calls = []
        first_handler = lambda **kwargs: first_calls.append(kwargs)

        second_calls = []
        second_handler = lambda **kwargs: second_calls.append(kwargs)

        first_client = creator.create_client(
            'myservice', 'us-west-2', credentials=self.credentials
        )
        second_client = creator.create_client(
            'myservice', 'us-west-2', credentials=self.credentials
        )

        first_client.meta.events.register('before-call', first_handler)
        second_client.meta.events.register('before-call', second_handler)

        # Now, if we invoke an operation from either client, only
        # the handlers registered with the specific client will be invoked.
        # So if we invoke the first client.
        first_client.test_operation(Foo='one', Bar='two')
        # Only first_calls is populated, not second_calls.
        self.assertEqual(len(first_calls), 1)
        self.assertEqual(len(second_calls), 0)

        # If we invoke an operation from the second client,
        # only second_calls will be populated, not first_calls.
        second_client.test_operation(Foo='one', Bar='two')
        # first_calls == 1 from the previous first_client.test_operation()
        # call.
        self.assertEqual(len(first_calls), 1)
        self.assertEqual(len(second_calls), 1)

    def test_clients_inherit_handlers_from_session(self):
        # Even though clients get their own event emitters, they still
        # inherit any handlers that were registered on the event emitter
        # at the time the client was created.
        event_emitter = hooks.HierarchicalEmitter()
        creator = self.create_client_creator(event_emitter=event_emitter)

        # So if an event handler is registered before any clients are created:

        base_calls = []
        base_handler = lambda **kwargs: base_calls.append(kwargs)
        event_emitter.register('before-call', base_handler)

        # Then any client created from this point forward from the
        # event_emitter passed into the ClientCreator will have this
        # handler.
        first_client = creator.create_client(
            'myservice', 'us-west-2', credentials=self.credentials
        )
        first_client.test_operation(Foo='one', Bar='two')
        self.assertEqual(len(base_calls), 1)

        # Same thing if we create another client.
        second_client = creator.create_client(
            'myservice', 'us-west-2', credentials=self.credentials
        )
        second_client.test_operation(Foo='one', Bar='two')
        self.assertEqual(len(base_calls), 2)

    def test_clients_inherit_only_at_create_time(self):
        # If event handlers are added to the copied event emitter
        # _after_ a client is created, we don't pick those up.
        event_emitter = hooks.HierarchicalEmitter()
        creator = self.create_client_creator(event_emitter=event_emitter)

        # 1. Create a client.
        first_client = creator.create_client(
            'myservice', 'us-west-2', credentials=self.credentials
        )

        # 2. Now register an event handler from the originating event emitter.
        base_calls = []
        base_handler = lambda **kwargs: base_calls.append(kwargs)
        event_emitter.register('before-call', base_handler)

        # 3. The client will _not_ see this because it already has its
        #    own copy of the event handlers.
        first_client.test_operation(Foo='one', Bar='two')
        self.assertEqual(len(base_calls), 0)

    def test_clients_have_meta_object(self):
        creator = self.create_client_creator()
        service_client = creator.create_client('myservice', 'us-west-2')
        self.assertTrue(hasattr(service_client, 'meta'))
        self.assertTrue(hasattr(service_client.meta, 'events'))
        # Sanity check the event emitter has an .emit() method.
        self.assertTrue(hasattr(service_client.meta.events, 'emit'))

    def test_client_register_seperate_unique_id_event(self):
        event_emitter = hooks.HierarchicalEmitter()
        creator = self.create_client_creator(event_emitter=event_emitter)

        client1 = creator.create_client('myservice', 'us-west-2')
        client2 = creator.create_client('myservice', 'us-west-2')

        def ping(**kwargs):
            return 'foo'

        client1.meta.events.register('some-event', ping, 'my-unique-id')
        client2.meta.events.register('some-event', ping, 'my-unique-id')

        # Ensure both clients can register a function with an unique id
        client1_responses = client1.meta.events.emit('some-event')
        self.assertEqual(len(client1_responses), 1)
        self.assertEqual(client1_responses[0][1], 'foo')

        client2_responses = client2.meta.events.emit('some-event')
        self.assertEqual(len(client2_responses), 1)
        self.assertEqual(client2_responses[0][1], 'foo')

        # Ensure when a client is unregistered the other client has
        # the unique-id event still registered.
        client1.meta.events.unregister('some-event', ping, 'my-unique-id')
        client1_responses = client1.meta.events.emit('some-event')
        self.assertEqual(len(client1_responses), 0)

        client2_responses = client2.meta.events.emit('some-event')
        self.assertEqual(len(client2_responses), 1)
        self.assertEqual(client2_responses[0][1], 'foo')

        # Ensure that the other client can unregister the event
        client2.meta.events.unregister('some-event', ping, 'my-unique-id')
        client2_responses = client2.meta.events.emit('some-event')
        self.assertEqual(len(client2_responses), 0)

    def test_client_created_emits_events(self):
        called = []

        def on_client_create(class_attributes, **kwargs):
            called.append(class_attributes)

        event_emitter = hooks.HierarchicalEmitter()
        event_emitter.register('creating-client-class', on_client_create)

        creator = self.create_client_creator(event_emitter=event_emitter)
        creator.create_client(
            'myservice', 'us-west-2', credentials=self.credentials
        )

        self.assertEqual(len(called), 1)
        self.assertIn('test_operation', called[0])

    def test_client_method_called_event(self):
        event_emitter = hooks.HierarchicalEmitter()

        def inject_params(params, **kwargs):
            new_params = params.copy()
            new_params['Foo'] = 'zero'
            return new_params

        event_emitter.register(
            'provide-client-params.myservice.TestOperation', inject_params
        )

        wrapped_emitter = mock.Mock(wraps=event_emitter)
        creator = self.create_client_creator(event_emitter=wrapped_emitter)
        service_client = creator.create_client(
            'myservice', 'us-west-2', credentials=self.credentials
        )

        params = {'Foo': 'one', 'Bar': 'two'}
        service_client.test_operation(**params)

        # Ensure that the initial params were not modified in the handler
        self.assertEqual(params, {'Foo': 'one', 'Bar': 'two'})

        # Ensure the handler passed on the correct param values.
        body = self.endpoint.make_request.call_args[0][1]['body']
        self.assertEqual(body['Foo'], 'zero')

    def test_client_default_for_s3_addressing_style(self):
        creator = self.create_client_creator()
        client = creator.create_client('myservice', 'us-west-2')
        self.assertEqual(client.meta.config.s3, None)

    def test_client_s3_addressing_style_with_config(self):
        creator = self.create_client_creator()
        my_client = creator.create_client(
            'myservice',
            'us-west-2',
            client_config=botocore.config.Config(
                s3={'addressing_style': 'auto'}
            ),
        )
        self.assertEqual(my_client.meta.config.s3['addressing_style'], 'auto')

    def test_client_s3_addressing_style_with_bad_value(self):
        creator = self.create_client_creator()
        client = creator.create_client(
            'myservice',
            'us-west-2',
            scoped_config={'s3': ''},
        )
        self.assertIsNone(client.meta.config.s3)

    def test_client_s3_addressing_style_with_config_store(self):
        self.config_store.set_config_variable(
            's3', {'addressing_style': 'virtual'}
        )
        creator = self.create_client_creator()
        client = creator.create_client('myservice', 'us-west-2')
        self.assertEqual(client.meta.config.s3['addressing_style'], 'virtual')

    def test_client_s3_addressing_style_with_incorrect_style(self):
        with self.assertRaises(InvalidS3AddressingStyleError):
            botocore.config.Config(s3={'addressing_style': 'foo'})

    def test_client_s3_addressing_style_config_overrides_config_store(self):
        self.config_store.set_config_variable(
            's3', {'addressing_style': 'virtual'}
        )
        creator = self.create_client_creator()
        my_client = creator.create_client(
            'myservice',
            'us-west-2',
            client_config=botocore.config.Config(
                s3={'addressing_style': 'auto'}
            ),
        )
        self.assertEqual(my_client.meta.config.s3['addressing_style'], 'auto')

    def test_client_payload_signing_from_config_store(self):
        self.config_store.set_config_variable(
            's3', {'payload_signing_enabled': True}
        )
        creator = self.create_client_creator()
        my_client = creator.create_client('myservice', 'us-west-2')
        self.assertEqual(
            my_client.meta.config.s3['payload_signing_enabled'], True
        )

    def test_client_payload_signing_from_client_config(self):
        creator = self.create_client_creator()
        my_client = creator.create_client(
            'myservice',
            'us-west-2',
            client_config=client.Config(s3={'payload_signing_enabled': True}),
        )
        self.assertEqual(
            my_client.meta.config.s3['payload_signing_enabled'], True
        )

    def test_client_payload_signing_client_config_overrides_scoped(self):
        creator = self.create_client_creator()
        my_client = creator.create_client(
            'myservice',
            'us-west-2',
            scoped_config={'s3': {'payload_signing_enabled': False}},
            client_config=client.Config(s3={'payload_signing_enabled': True}),
        )
        self.assertEqual(
            my_client.meta.config.s3['payload_signing_enabled'], True
        )

    def test_client_s3_accelerate_from_config_store(self):
        self.config_store.set_config_variable(
            's3', {'use_accelerate_endpoint': True}
        )
        creator = self.create_client_creator()
        my_client = creator.create_client('myservice', 'us-west-2')
        self.assertEqual(
            my_client.meta.config.s3['use_accelerate_endpoint'], True
        )

    def test_client_s3_accelerate_from_client_config(self):
        creator = self.create_client_creator()
        my_client = creator.create_client(
            'myservice',
            'us-west-2',
            client_config=client.Config(s3={'use_accelerate_endpoint': True}),
        )
        self.assertEqual(
            my_client.meta.config.s3['use_accelerate_endpoint'], True
        )

    def test_client_s3_accelerate_client_config_overrides_config_store(self):
        self.config_store.set_config_variable(
            's3', {'use_accelerate_endpoint': False}
        )
        creator = self.create_client_creator()
        my_client = creator.create_client(
            'myservice',
            'us-west-2',
            client_config=client.Config(s3={'use_accelerate_endpoint': True}),
        )
        self.assertEqual(
            my_client.meta.config.s3['use_accelerate_endpoint'], True
        )

    def test_before_call_short_circuits_request(self):
        def return_mock_tuple(**kwargs):
            http_mock = mock.Mock()
            http_mock.status_code = 200
            return http_mock, mock.Mock()

        emitter = hooks.HierarchicalEmitter()
        emitter.register_last('before-call.*.*', return_mock_tuple)
        creator = self.create_client_creator(event_emitter=emitter)
        service_client = creator.create_client('myservice', 'us-west-2')

        service_client.test_operation(Foo='one')
        self.assertFalse(self.endpoint.make_request.called)

    def test_getattr_emits_event(self):
        emitter = self.create_mock_emitter()
        emitter.emit_until_response.return_value = (None, None)

        creator = self.create_client_creator(event_emitter=emitter)
        service_client = creator.create_client('myservice', 'us-west-2')

        # Assert that the event hasn't fired yet
        emitter.emit_until_response.assert_not_called()

        with self.assertRaises(AttributeError):
            service_client.attribute_that_does_not_exist

        emitter.emit_until_response.assert_called_once_with(
            'getattr.myservice.attribute_that_does_not_exist',
            client=service_client,
        )

    def test_getattr_event_returns_response(self):
        emitter = self.create_mock_emitter()
        emitter.emit_until_response.return_value = (None, 'success')

        creator = self.create_client_creator(event_emitter=emitter)
        service_client = creator.create_client('myservice', 'us-west-2')

        value = service_client.attribute_that_does_not_exist

        self.assertEqual(value, 'success')

    def _create_hostname_binding_client(self, *args, **kwargs):
        test_operation = self.service_description['operations'][
            'TestOperation'
        ]
        test_operation['endpoint'] = {'hostPrefix': '{Foo}.'}
        test_shape = self.service_description['shapes']['TestOperationRequest']
        test_shape['members']['Foo']['hostLabel'] = True

        creator = self.create_client_creator()
        return creator.create_client('myservice', *args, **kwargs)

    def test_client_operation_hostname_binding(self):
        client = self._create_hostname_binding_client('us-west-2')
        client.test_operation(Foo='bound')

        expected_url = 'https://bound.myservice.amazonaws.com/'
        self.assertTrue(self.endpoint.make_request.called)
        request_dict = self.endpoint.make_request.call_args[0][1]
        self.assertEqual(request_dict['url'], expected_url)

    def test_client_operation_hostname_binding_validation(self):
        client = self._create_hostname_binding_client('us-west-2')
        with self.assertRaises(ParamValidationError):
            client.test_operation(Foo='')

    def test_client_operation_hostname_binding_configuration(self):
        config = botocore.config.Config(inject_host_prefix=False)
        client = self._create_hostname_binding_client(
            'us-west-2',
            client_config=config,
        )

        client.test_operation(Foo='baz')
        expected_url = 'https://myservice.amazonaws.com/'
        self.assertTrue(self.endpoint.make_request.called)
        request_dict = self.endpoint.make_request.call_args[0][1]
        self.assertEqual(request_dict['url'], expected_url)

    def test_client_close(self):
        creator = self.create_client_creator()
        service_client = creator.create_client(
            'myservice', 'us-west-2', credentials=self.credentials
        )

        service_client.close()
        self.endpoint.close.assert_called_once_with()

    def test_client_close_context_manager(self):
        creator = self.create_client_creator()
        with closing(
            creator.create_client(
                'myservice', 'us-west-2', credentials=self.credentials
            )
        ) as service_client:
            service_client.test_operation(Foo='baz')

        self.endpoint.close.assert_called_once_with()


class TestClientErrors(BaseClientTest):
    def add_error_response(self, error_response):
        self.endpoint.make_request.return_value = (
            mock.Mock(status_code=400),
            error_response,
        )

    def test_client_makes_call_with_error(self):
        creator = self.create_client_creator()
        client = creator.create_client(
            'myservice', 'us-west-2', credentials=self.credentials
        )

        with Stubber(client) as stub:
            stub.add_client_error(
                'test_operation', 'TestOperationErrorCode', 'error occurred'
            )
            with self.assertRaises(client.exceptions.TestOperationException):
                client.test_operation(Foo='one', Bar='two')

    def test_error_with_no_wire_code(self):
        creator = self.create_client_creator()
        client = creator.create_client(
            'myservice', 'us-west-2', credentials=self.credentials
        )

        with Stubber(client) as stub:
            stub.add_client_error('test_operation', '404', 'Not Found')
            try:
                client.test_operation(Foo='one', Bar='two')
            except client.exceptions.ClientError as e:
                # This is needed becasue the error could be a subclass of
                # ClientError.
                # We explicitly want it to be a generic ClientError though
                self.assertEqual(e.__class__, exceptions.ClientError)

    def test_error_with_dot_separated_code(self):
        creator = self.create_client_creator()
        client = creator.create_client(
            'myservice', 'us-west-2', credentials=self.credentials
        )

        with Stubber(client) as stub:
            stub.add_client_error(
                'test_operation', 'InvalidAddress.NotFound', 'Not Found'
            )
            try:
                client.test_operation(Foo='one', Bar='two')
            except client.exceptions.ClientError as e:
                # This is needed becasue the error could be a subclass of
                # ClientError.
                # We explicitly want it to be a generic ClientError though
                self.assertEqual(e.__class__, exceptions.ClientError)

    def test_error_with_empty_message(self):
        creator = self.create_client_creator()
        client = creator.create_client(
            'myservice', 'us-west-2', credentials=self.credentials
        )

        with Stubber(client) as stub:
            stub.add_client_error('test_operation', 'TestOperationErrorCode')
            with self.assertRaises(client.exceptions.TestOperationException):
                client.test_operation(Foo='one', Bar='two')

    def test_error_with_empty_code(self):
        creator = self.create_client_creator()
        client = creator.create_client(
            'myservice', 'us-west-2', credentials=self.credentials
        )

        with Stubber(client) as stub:
            stub.add_client_error('test_operation')
            try:
                client.test_operation(Foo='one', Bar='two')
            except client.exceptions.ClientError as e:
                # This is needed becasue the error could be a subclass of
                # ClientError.
                # We explicitly want it to be a generic ClientError though
                self.assertEqual(e.__class__, exceptions.ClientError)

    def test_error_with_missing_code(self):
        error_response = {'Error': {'Message': 'error occurred'}}
        # The stubber is not being used because it will always populate the
        # the message and code.
        self.endpoint.make_request.return_value = (
            mock.Mock(status_code=400),
            error_response,
        )

        creator = self.create_client_creator()
        client = creator.create_client(
            'myservice', 'us-west-2', credentials=self.credentials
        )

        try:
            client.test_operation(Foo='one', Bar='two')
        except client.exceptions.ClientError as e:
            # This is needed becasue the error could be a subclass of
            # ClientError.
            # We explicitly want it to be a generic ClientError though
            self.assertEqual(e.__class__, exceptions.ClientError)

    def test_error_with_empty_contents(self):
        error_response = {'Error': {}}
        # The stubber is not being used because it will always populate the
        # the message and code.
        self.endpoint.make_request.return_value = (
            mock.Mock(status_code=400),
            error_response,
        )

        creator = self.create_client_creator()
        client = creator.create_client(
            'myservice', 'us-west-2', credentials=self.credentials
        )

        try:
            client.test_operation(Foo='one', Bar='two')
        except client.exceptions.ClientError as e:
            # This is needed becasue the error could be a subclass of
            # ClientError.
            # We explicitly want it to be a generic ClientError though
            self.assertEqual(e.__class__, exceptions.ClientError)

    def test_exception_classes_across_clients_are_the_same(self):
        creator = self.create_client_creator(
            exceptions_factory=ClientExceptionsFactory()
        )
        client = creator.create_client(
            'myservice', 'us-west-2', credentials=self.credentials
        )
        client2 = creator.create_client(
            'myservice', 'us-west-2', credentials=self.credentials
        )

        with Stubber(client) as stub:
            stub.add_client_error(
                'test_operation', 'TestOperationErrorCode', 'error occurred'
            )
            try:
                client.test_operation(Foo='one', Bar='two')
            except client2.exceptions.TestOperationException as e:
                # Caught exception should as well be an instance of the
                # other client's TestOperationException
                self.assertIsInstance(
                    e, client.exceptions.TestOperationException
                )


class TestConfig(unittest.TestCase):
    def test_can_use_args_to_construct(self):
        config = botocore.config.Config(
            *botocore.config.Config.OPTION_DEFAULTS.values()
        )
        for (
            option,
            default_value,
        ) in botocore.config.Config.OPTION_DEFAULTS.items():
            self.assertTrue(hasattr(config, option))
            self.assertEqual(getattr(config, option), default_value)

    def test_can_use_kwargs_to_construct(self):
        config = botocore.config.Config(
            **botocore.config.Config.OPTION_DEFAULTS
        )
        for (
            option,
            default_value,
        ) in botocore.config.Config.OPTION_DEFAULTS.items():
            self.assertTrue(hasattr(config, option))
            self.assertEqual(getattr(config, option), default_value)

    def test_can_use_mix_of_args_and_kwargs(self):
        config = botocore.config.Config('us-east-1', read_timeout=50)
        self.assertEqual(config.region_name, 'us-east-1')
        self.assertEqual(config.read_timeout, 50)

    def test_invalid_kwargs(self):
        with self.assertRaisesRegex(TypeError, 'Got unexpected keyword'):
            botocore.config.Config(foo='foo')

    def test_pass_invalid_length_of_args(self):
        with self.assertRaisesRegex(TypeError, 'Takes at most'):
            botocore.config.Config(
                'foo', *botocore.config.Config.OPTION_DEFAULTS.values()
            )

    def test_create_with_multiple_kwargs(self):
        with self.assertRaisesRegex(TypeError, 'Got multiple values'):
            botocore.config.Config('us-east-1', region_name='us-east-1')

    def test_merge_returns_new_config_object(self):
        config = botocore.config.Config()
        other_config = botocore.config.Config()
        new_config = config.merge(other_config)
        # Check the type is correct
        self.assertIsInstance(new_config, botocore.config.Config)
        # Make sure the new config is a brand new config object
        self.assertIsNot(new_config, config)
        self.assertIsNot(new_config, other_config)

    def test_general_merge_keeps_default_values(self):
        config = botocore.config.Config()
        other_config = botocore.config.Config()
        config_properties = vars(config)
        new_config = config.merge(other_config)
        # Ensure that the values all stayed the same in the new config
        self.assertEqual(config_properties, vars(new_config))

    def test_merge_overrides_values(self):
        config = botocore.config.Config(region_name='us-east-1')
        other_config = botocore.config.Config(region_name='us-west-2')
        new_config = config.merge(other_config)
        self.assertEqual(new_config.region_name, 'us-west-2')

    def test_merge_overrides_values_even_when_using_default(self):
        config = botocore.config.Config(region_name='us-east-1')
        other_config = botocore.config.Config(region_name=None)
        new_config = config.merge(other_config)
        self.assertEqual(new_config.region_name, None)

    def test_merge_overrides_values_even_when_using_default_timeout(self):
        config = botocore.config.Config(read_timeout=30)
        other_config = botocore.config.Config(read_timeout=DEFAULT_TIMEOUT)
        new_config = config.merge(other_config)
        self.assertEqual(new_config.read_timeout, DEFAULT_TIMEOUT)

    def test_merge_overrides_only_when_user_provided_values(self):
        config = botocore.config.Config(
            region_name='us-east-1', signature_version='s3v4'
        )
        other_config = botocore.config.Config(region_name='us-west-2')
        new_config = config.merge(other_config)
        self.assertEqual(new_config.region_name, 'us-west-2')
        self.assertEqual(new_config.signature_version, 's3v4')

    def test_can_set_retry_max_attempts(self):
        config = botocore.config.Config(retries={'max_attempts': 15})
        self.assertEqual(config.retries['max_attempts'], 15)

    def test_validates_retry_config(self):
        with self.assertRaisesRegex(
            InvalidRetryConfigurationError,
            'Cannot provide retry configuration for "not-allowed"',
        ):
            botocore.config.Config(retries={'not-allowed': True})

    def test_validates_max_retry_attempts(self):
        with self.assertRaises(InvalidMaxRetryAttemptsError):
            botocore.config.Config(retries={'max_attempts': -1})

    def test_validates_total_max_attempts(self):
        with self.assertRaises(InvalidMaxRetryAttemptsError):
            botocore.config.Config(retries={'total_max_attempts': 0})

    def test_validaties_retry_mode(self):
        with self.assertRaises(InvalidRetryModeError):
            botocore.config.Config(retries={'mode': 'turbo-mode'})


class TestClientEndpointBridge(unittest.TestCase):
    def setUp(self):
        self.resolver = mock.Mock()
        self.boilerplate_response = {
            'endpointName': 'us-east-1',
            'hostname': 's3.amazonaws.com',
            'partition': 'aws',
            'protocols': ['http', 'https'],
            'dnsSuffix': 'amazonaws.com',
            'signatureVersions': ['s3', 's3v4'],
        }
        self.resolver.construct_endpoint.return_value = (
            self.boilerplate_response
        )

    def test_guesses_endpoint_as_last_resort(self):
        resolver = mock.Mock()
        resolver.construct_endpoint.return_value = None
        bridge = ClientEndpointBridge(resolver)
        resolved = bridge.resolve('myservice', region_name='guess')
        self.assertEqual('guess', resolved['region_name'])
        self.assertEqual('guess', resolved['signing_region'])
        self.assertEqual('myservice', resolved['signing_name'])
        self.assertEqual('myservice', resolved['service_name'])
        self.assertEqual('v4', resolved['signature_version'])
        self.assertEqual(
            'https://myservice.guess.amazonaws.com', resolved['endpoint_url']
        )

    def test_uses_us_east_1_by_default_for_s3(self):
        resolver = mock.Mock()
        resolver.construct_endpoint.return_value = {
            'partition': 'aws',
            'hostname': 's3.amazonaws.com',
            'endpointName': 'us-east-1',
            'signatureVersions': ['s3', 's3v4'],
            'protocols': ['https'],
        }
        bridge = ClientEndpointBridge(resolver)
        resolved = bridge.resolve('s3')
        self.assertEqual('us-east-1', resolved['region_name'])
        self.assertEqual('us-east-1', resolved['signing_region'])
        self.assertEqual('https://s3.amazonaws.com', resolved['endpoint_url'])

    def test_uses_region_from_client_config_if_available(self):
        resolver = mock.Mock()
        resolver.construct_endpoint.return_value = None
        client_config = mock.Mock()
        client_config.region_name = 'us-foo-bar'
        bridge = ClientEndpointBridge(resolver, client_config=client_config)
        resolved = bridge.resolve('test')
        self.assertEqual('us-foo-bar', resolved['region_name'])
        self.assertEqual('us-foo-bar', resolved['signing_region'])
        self.assertEqual(
            'https://test.us-foo-bar.amazonaws.com', resolved['endpoint_url']
        )

    def test_can_guess_endpoint_and_use_given_endpoint_url(self):
        resolver = mock.Mock()
        resolver.construct_endpoint.return_value = None
        bridge = ClientEndpointBridge(resolver)
        resolved = bridge.resolve(
            'test', 'guess', endpoint_url='http://test.com'
        )
        self.assertEqual('guess', resolved['region_name'])
        self.assertEqual('guess', resolved['signing_region'])
        self.assertEqual('http://test.com', resolved['endpoint_url'])

    def test_can_use_endpoint_url_with_resolved_endpoint(self):
        resolver = mock.Mock()
        resolver.construct_endpoint.return_value = {
            'partition': 'aws',
            'hostname': 'do-not-use-this',
            'endpointName': 'us-west-2',
            'signatureVersions': ['v2'],
        }
        bridge = ClientEndpointBridge(resolver)
        resolved = bridge.resolve(
            'ec2', 'us-west-2', endpoint_url='https://foo'
        )
        self.assertEqual('us-west-2', resolved['region_name'])
        self.assertEqual('us-west-2', resolved['signing_region'])
        self.assertEqual('https://foo', resolved['endpoint_url'])
        self.assertEqual('v2', resolved['signature_version'])

    def test_can_create_http_urls(self):
        resolver = mock.Mock()
        resolver.construct_endpoint.return_value = {
            'partition': 'aws',
            'hostname': 'host.com',
            'signatureVersions': ['v4'],
            'endpointName': 'us-foo-baz',
        }
        bridge = ClientEndpointBridge(resolver)
        resolved = bridge.resolve('myservice', 'us-foo-baz', is_secure=False)
        self.assertEqual('http://host.com', resolved['endpoint_url'])

    def test_credential_scope_overrides_signing_region(self):
        resolver = mock.Mock()
        resolver.construct_endpoint.return_value = {
            'partition': 'aws',
            'hostname': 'host.com',
            'endpointName': 'us-foo-baz',
            'signatureVersions': ['v4'],
            'credentialScope': {'region': 'override'},
        }
        bridge = ClientEndpointBridge(resolver)
        resolved = bridge.resolve('myservice', 'us-foo-baz')
        self.assertEqual('us-foo-baz', resolved['region_name'])
        self.assertEqual('override', resolved['signing_region'])

    def test_cred_scope_does_not_override_signing_region_if_endpoint_url(self):
        resolver = mock.Mock()
        resolver.construct_endpoint.return_value = {
            'partition': 'aws',
            'hostname': 'will-not-use.com',
            'endpointName': 'us-foo-baz',
            'signatureVersions': ['v4'],
            'credentialScope': {'region': 'override'},
        }
        bridge = ClientEndpointBridge(resolver)
        resolved = bridge.resolve(
            'myservice', 'us-foo-baz', endpoint_url='https://override.com'
        )
        self.assertEqual('us-foo-baz', resolved['region_name'])
        self.assertEqual('us-foo-baz', resolved['signing_region'])
        self.assertEqual('https://override.com', resolved['endpoint_url'])

    def test_resolved_region_overrides_region_when_no_endpoint_url(self):
        resolver = mock.Mock()
        resolver.construct_endpoint.return_value = {
            'partition': 'aws',
            'hostname': 'host.com',
            'signatureVersions': ['v4'],
            'endpointName': 'override',
            'protocols': ['https'],
        }
        bridge = ClientEndpointBridge(resolver)
        resolved = bridge.resolve('myservice', 'will-not-be-there')
        self.assertEqual('override', resolved['region_name'])
        self.assertEqual('override', resolved['signing_region'])
        self.assertEqual('https://host.com', resolved['endpoint_url'])

    def test_does_not_use_https_if_not_available(self):
        resolver = mock.Mock()
        resolver.construct_endpoint.return_value = {
            'partition': 'aws',
            'hostname': 'host.com',
            'signatureVersions': ['v4'],
            'endpointName': 'foo',
            # Note: http, not https
            'protocols': ['http'],
        }
        bridge = ClientEndpointBridge(resolver)
        resolved = bridge.resolve('myservice')
        # We should resolve to http://, not https://
        self.assertEqual('http://host.com', resolved['endpoint_url'])

    def test_uses_signature_version_from_client_config(self):
        resolver = mock.Mock()
        resolver.construct_endpoint.return_value = {
            'partition': 'aws',
            'hostname': 'test.com',
            'endpointName': 'us-west-2',
            'signatureVersions': ['v2'],
        }
        client_config = mock.Mock()
        client_config.signature_version = 's3'
        bridge = ClientEndpointBridge(resolver, client_config=client_config)
        resolved = bridge.resolve('test', 'us-west-2')
        self.assertEqual('s3', resolved['signature_version'])

    def test_uses_signature_version_from_client_config_when_guessing(self):
        resolver = mock.Mock()
        resolver.construct_endpoint.return_value = None
        client_config = mock.Mock()
        client_config.signature_version = 's3v4'
        bridge = ClientEndpointBridge(resolver, client_config=client_config)
        resolved = bridge.resolve('test', 'us-west-2')
        self.assertEqual('s3v4', resolved['signature_version'])

    def test_uses_signature_version_from_scoped_config(self):
        resolver = mock.Mock()
        resolver.construct_endpoint.return_value = {
            'partition': 'aws',
            'hostname': 'test.com',
            'endpointName': 'us-west-2',
            'signatureVersions': ['v2'],
        }
        scoped_config = mock.Mock()
        scoped_config.get.return_value = {'signature_version': 's3'}
        bridge = ClientEndpointBridge(resolver, scoped_config)
        resolved = bridge.resolve('test', 'us-west-2')
        self.assertEqual('s3', resolved['signature_version'])

    def test_uses_s3v4_over_s3_for_s3(self):
        resolver = mock.Mock()
        resolver.construct_endpoint.return_value = {
            'partition': 'aws',
            'hostname': 'test.com',
            'endpointName': 'us-west-2',
            'signatureVersions': ['s3v4', 's3'],
        }
        bridge = ClientEndpointBridge(resolver)
        resolved = bridge.resolve('s3', 'us-west-2')
        self.assertEqual('s3v4', resolved['signature_version'])

    def test_uses_s3v4_over_others_for_s3(self):
        resolver = mock.Mock()
        resolver.construct_endpoint.return_value = {
            'partition': 'aws',
            'hostname': 'test.com',
            'endpointName': 'us-west-2',
            'signatureVersions': ['s3v4', 'v4'],
        }
        bridge = ClientEndpointBridge(resolver)
        resolved = bridge.resolve('s3', 'us-west-2')
        self.assertEqual('s3v4', resolved['signature_version'])

    def test_uses_v4_over_other_signers(self):
        resolver = mock.Mock()
        resolver.construct_endpoint.return_value = {
            'partition': 'aws',
            'hostname': 'test',
            'signatureVersions': ['v2', 'v4'],
            'endpointName': 'us-west-2',
        }
        bridge = ClientEndpointBridge(resolver)
        resolved = bridge.resolve('test', 'us-west-2')
        self.assertEqual('v4', resolved['signature_version'])

    def test_uses_known_signers_from_list_of_signature_versions(self):
        resolver = mock.Mock()
        resolver.construct_endpoint.return_value = {
            'partition': 'aws',
            'hostname': 'test',
            'signatureVersions': ['foo', 'baz', 'v3https'],
            'endpointName': 'us-west-2',
        }
        bridge = ClientEndpointBridge(resolver)
        resolved = bridge.resolve('test', 'us-west-2')
        self.assertEqual('v3https', resolved['signature_version'])

    def test_raises_when_signature_version_is_unknown(self):
        resolver = mock.Mock()
        resolver.construct_endpoint.return_value = {
            'partition': 'aws',
            'hostname': 'test',
            'endpointName': 'us-west-2',
            'signatureVersions': ['foo'],
        }
        bridge = ClientEndpointBridge(resolver)
        with self.assertRaises(UnknownSignatureVersionError):
            bridge.resolve('test', 'us-west-2')

    def test_uses_first_known_signature_version(self):
        resolver = mock.Mock()
        resolver.construct_endpoint.return_value = {
            'partition': 'aws',
            'hostname': 'test',
            'endpointName': 'us-west-2',
            'signatureVersions': ['foo', 'bar', 'baz', 's3v4', 'v2'],
        }
        bridge = ClientEndpointBridge(resolver)
        resolved = bridge.resolve('test', 'us-west-2')
        self.assertEqual('s3v4', resolved['signature_version'])

    def test_raises_when_signature_version_is_not_found(self):
        resolver = mock.Mock()
        resolver.construct_endpoint.return_value = {
            'partition': 'aws',
            'hostname': 'test',
            'endpointName': 'us-west-2',
        }
        bridge = ClientEndpointBridge(resolver)
        with self.assertRaises(UnknownSignatureVersionError):
            bridge.resolve('test', 'us-west-2')

    def test_uses_service_name_as_signing_name(self):
        resolver = mock.Mock()
        resolver.construct_endpoint.return_value = {
            'partition': 'aws',
            'hostname': 'test',
            'signatureVersions': ['v4'],
            'endpointName': 'us-west-2',
        }
        bridge = ClientEndpointBridge(resolver)
        resolved = bridge.resolve('test', 'us-west-2')
        self.assertEqual('test', resolved['signing_name'])

    def test_uses_credential_scope_signing_name(self):
        resolver = mock.Mock()
        resolver.construct_endpoint.return_value = {
            'partition': 'aws',
            'hostname': 'test',
            'endpointName': 'us-west-2',
            'signatureVersions': ['v4'],
            'credentialScope': {'service': 'override'},
        }
        bridge = ClientEndpointBridge(resolver)
        resolved = bridge.resolve('test', 'us-west-2')
        self.assertEqual('override', resolved['signing_name'])

    def test_uses_service_signing_name_when_present_and_no_cred_scope(self):
        resolver = mock.Mock()
        resolver.construct_endpoint.return_value = {
            'partition': 'aws',
            'hostname': 'test',
            'signatureVersions': ['v4'],
            'endpointName': 'us-west-2',
        }
        bridge = ClientEndpointBridge(resolver, service_signing_name='foo')
        resolved = bridge.resolve('test', 'us-west-2')
        self.assertEqual('foo', resolved['signing_name'])

    def test_disable_dualstack_explicitly(self):
        scoped_config = {'s3': {'use_dualstack_endpoint': True}}
        config = botocore.config.Config(s3={'use_dualstack_endpoint': False})
        bridge = ClientEndpointBridge(
            self.resolver, scoped_config, client_config=config
        )
        resolved = bridge.resolve('s3', 'us-east-1')
        self.assertEqual(resolved['endpoint_url'], 'https://s3.amazonaws.com')

    def test_use_dualstack_endpoint(self):
        config = botocore.config.Config(use_dualstack_endpoint=True)
        bridge = ClientEndpointBridge(self.resolver, client_config=config)
        bridge.resolve('ec2', 'us-west-2')
        self.resolver.construct_endpoint.assert_called_with(
            'ec2',
            'us-west-2',
            use_dualstack_endpoint=True,
            use_fips_endpoint=False,
        )

    def test_use_fips_endpoint(self):
        config = botocore.config.Config(use_fips_endpoint=True)
        bridge = ClientEndpointBridge(self.resolver, client_config=config)
        bridge.resolve('ec2', 'us-west-2')
        self.resolver.construct_endpoint.assert_called_with(
            'ec2',
            'us-west-2',
            use_dualstack_endpoint=False,
            use_fips_endpoint=True,
        )

    def test_use_dualstack_endpoint_omits_s3(self):
        config = botocore.config.Config(
            use_dualstack_endpoint=True, s3={'use_dualstack_endpoint': False}
        )
        bridge = ClientEndpointBridge(self.resolver, client_config=config)
        bridge.resolve('s3', 'us-west-2')
        self.resolver.construct_endpoint.assert_called_with(
            's3',
            'us-west-2',
            use_dualstack_endpoint=False,
            use_fips_endpoint=False,
        )

    def test_modeled_endpoint_variants_client_config_trumps_scoped_config(
        self,
    ):
        scoped_config = {
            'use_dualstack_endpoint': True,
            'use_fips_endpoint': True,
        }
        config = botocore.config.Config(
            use_dualstack_endpoint=False, use_fips_endpoint=False
        )
        bridge = ClientEndpointBridge(
            self.resolver, scoped_config, client_config=config
        )
        bridge.resolve('ec2', 'us-west-2')
        self.resolver.construct_endpoint.assert_called_with(
            'ec2',
            'us-west-2',
            use_dualstack_endpoint=False,
            use_fips_endpoint=False,
        )

    def test_modeled_endpoint_variants_tags_using_config_store(self):
        config_store = mock.Mock()
        config_store.get_config_variable.return_value = True
        bridge = ClientEndpointBridge(self.resolver, config_store=config_store)
        bridge.resolve('ec2', 'us-west-2')
        self.resolver.construct_endpoint.assert_called_with(
            'ec2',
            'us-west-2',
            use_dualstack_endpoint=True,
            use_fips_endpoint=True,
        )

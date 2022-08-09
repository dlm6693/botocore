import re
from enum import Enum
from functools import lru_cache

from botocore import xform_name
from botocore.compat import UNSAFE_URL_CHARS, quote, urlparse
from botocore.exceptions import EndpointError
from botocore.utils import (
    ArnParser,
    InvalidArnException,
    is_valid_ipv4_endpoint_url,
    is_valid_ipv6_endpoint_url,
    normalize_url_path,
    percent_encode,
)


class RuleTemplate:
    """A base class representing a templated error/endpoint object e.g.
    {
        "url": "https://{Bucket}.ec2.{url#authority}",
        "properties": {
            "authSchemes": [
                {
                    "name": "v4",
                    "signingName": "s3-outposts",
                    "signingScope": "{Region}"
                }
            ]
        },
        "headers": {}
    }
    """

    TEMPLATE_STRING_RE = re.compile(r'(?<=\{)[a-zA-Z#]+(?=\})')

    def resolve_template_string(self, value, parameters):
        """Given a templated string and parameters, parse out the template
        nested between curly braces, and return the nested attribute.

        :type value: str
        :param value: A template string e.g. "https://{Bucket}.ec2.{url#authority}"

        :type parameters: dict
        :param parameters: A dictionary containing assigned variables e.g.
        {
            "Region": "us-east-1",
            "Bucket": "my-bucket",
            "url": {
                "authority": foo.bar:1234,
                "scheme": "https",
                ...
            }
        }
        """
        matches = self.TEMPLATE_STRING_RE.findall(value)
        for match in matches:
            template_params = match.split('#')
            template_value = parameters
            for param in template_params:
                template_value = template_value[param]
            value = value.replace("{" + match + "}", template_value)
        return value

    def resolve(self, parameters):
        raise NotImplementedError()


class Endpoint(RuleTemplate):
    """A class representing an endpoint object that a rule returns if
    input parameters meet its requirements.
    """

    def __init__(self, url, properties, headers):
        self.url = url
        self.properties = properties
        self.headers = headers
        # self.rule = rule

    def resolve_url(self, parameters):
        """Resolve a templated/referenced variable or call a function in
        a URL string.

        :type paramters: dict
        :param parameters: A dictionary containing assigned variables

        :returns: A resolved URL string i.e. https://s3.us-east-1.amazonaws.com
        """
        return self.resolve_template_string(self.url, parameters)

    def resolve_properties(self, properties, parameters):
        """Given an endpoint's `properties` attributes, traverse the arbitrarily
        nested attributes and resolve templated/referenced/function called values
        once the lowest level is reached. In other words, if `properties` is a list
        or dictionary, recurse using the data nested within it.

        :type properties: dict/list/str
        :param properties: Initially an endpoint object's properties attribute i.e.
        {
            "authSchemes": [
                {
                    "name": "v4",
                    "signingName": "s3-outposts",
                    "signingScope": "{Region}"
                }
            ]
        }
        As the function recurses, it will traverse the nested data structure until it
        finds a string

        :type parameters: dict
        :param parameters: A Dicitonary containing assigned variables

        :returns: A fully resolved properties attribute.
        """
        if isinstance(properties, list):
            return [
                self.resolve_properties(prop, parameters)
                for prop in properties
            ]
        elif isinstance(properties, dict):
            # if 'ref' in properties:
            #     return self.resolve_template_string(
            #         properties['ref'], parameters
            #     )
            # elif self.rule.is_func(properties):
            #     return self.resolve_template_string(
            #         self.rule.call_func(properties), parameters
            #     )
            return {
                key: self.resolve_properties(value, parameters)
                for key, value in properties.items()
            }
        else:
            return self.resolve_template_string(properties, parameters)

    def resolve(self, parameters):
        """Given a set of assigned values (parameters), resolve an endpoint
        in its entirety, that is call a function or use a template/reference
        object to retrieve a value.

        :type parameters: dict
        :param parameters: A dictionary containing assigned variables

        :returns: A new endpoint instance with fully resolved attributes
        """
        url = self.resolve_url(parameters)
        properties = self.resolve_properties(self.properties, parameters)
        return Endpoint(url=url, properties=properties, headers=self.headers)


class Error(RuleTemplate):
    def __init__(self, error, documentation):
        self.error = error
        self.documentation = documentation

    def resolve_error(self, parameters):
        r"""Resolve a templated/referenced variable or call a function in
        an error string.

        :type paramters: dict
        :param parameters: A dictionary containing assigned variables

        :returns: A resolved error string i.e.
        "Custom endpoint `https://foo.bar\/+thing` was not a valid URI"
        """
        return self.resolve_template_string(self.error, parameters)

    def resolve(self, parameters):
        """Given a set of assigned values (parameters), resolve an error
        in its entirety, that is call a function or use a template/reference
        object to retrieve a value.

        :type parameters: dict
        :param parameters: A dictionary containing assigned variables

        :raises: An endpoint error containing the fully resolved error string
        """
        error = self.resolve_error(parameters)
        raise EndpointError(msg=error)


class BaseRule:
    """A base class representing a rule within a rule set. All rules contain
    a conditions property, which can be empty, a set of assigned variables
    passed by a caller, and an endpoint provider instance.
    """

    def __init__(self, conditions, assignments, provider):

        self.conditions = conditions
        self.assignments = assignments
        self.provider = provider

    def is_func(self, argument):
        """Determine if a dictionary is a function object.

        :type argument: Any
        :param argument: An object that may or may not be a function object

        :returns: A bool indicating if the input is a function object
        """

        return isinstance(argument, dict) and 'fn' in argument

    def call_function(self, func_signature):
        """Provided a function object, iterate through its arguments and recurse
        if any of them are a nested function object. If an arg is a reference object,
        dereference it by looking for it in the rule's assignments attribute. Finally,
        retrieve the function and call it with the resolved arguments. If an `assign`
        parameter is present, add the returned value to the rule's assignments.

        :type func_signature: dict
        :param func_signature: A function object e.g.
        {
            "fn": "not",
            "argv": [
                {
                    "fn": "isSet",
                    "argv": [
                        {
                            "fn": "parseURL",
                            "argv": [
                                {
                                    "ref": "Endpoint"
                                }
                            ]
                        }
                    ]
                }
            ]
        }

        :returns: The result of the function call(s)
        """
        func_args = func_signature['argv']
        func_name = func_signature['fn']
        # python does not allow a function defintion titled `not`
        # because of the built-in logical operator
        if func_name == 'not':
            func_name = '_not'
        call_args = []
        for arg in func_args:
            if self.is_func(arg):
                call_args.append(self.call_function(arg))
            elif isinstance(arg, dict):
                ref = self.assignments.get(arg['ref'])
                call_args.append(ref)
            else:
                call_args.append(arg)
        func = getattr(self, xform_name(func_name))
        result = func(*call_args)
        if 'assign' in func_signature:
            self.assignments[func_signature['assign']] = result
        return result

    def evaluate_conditions(self):
        """Determine if all conditions in a rule are truthy.

        :returns: A bool whether or not all conditions in a rule are truthy
        """
        for func_signature in self.conditions:
            if not self.call_function(func_signature):
                return False
        return True

    def evaluate(self):
        raise NotImplementedError()

    def is_set(self, value):
        """Evaluates whether a value (such as an endpoint parameter)
        is set (aka not null)

        :type value: Any
        :param value: A value of any type such as an endpoint parameter

        :return: A bool if the value is not None
        """
        return value is not None

    def get_attr(self, value, path):
        """Example: Given the input object

        {"Thing1": "foo", "Thing2": ["index0", "index1"],
        "Thing3": {"Thing3": {"SubThing": 42}}}

        Thing1 returns "foo"
        Thing2[0] returns "index0"
        Thing3.SubThing returns 42
        Example: Given the input array ["foo", "bar"]
        [0] => "foo"

        :type value: dict or list
        :param value: a JSON like object that contains values, key-value pairs or
        some combination of both

        :type path: str
        :param path: A string representing a key, index or some combination of both.
        A period `.` indicates the value to the right of it is a nested key in a
        dictionary, and an integer in brackets i.e. `[1]` represents an index of a list.
        These can be used together i.e. `Thing1.foo[3]`
        """
        for part in path.split('.'):
            match = re.search(r'(\w+)\[(\d+)\]', part)
            if match is not None:
                name, index = match.groups()
                value = value.get(name)
                if value is None:
                    return None
                index = int(index)
                # index is out of range
                if index >= len(value):
                    return None
                value = value[index]
            else:
                value = value[part]
        return value

    def partition(self, value):
        """Evaluates a single string argument value as a region,
         and matches the string value to an AWS partition

         :type value: str
         :param value: A string representing an AWS region

         :return: `output` object in the matched partition e.g.
        {
             "name": "aws",
             "dnsSuffix": "amazonaws.com",
             "dualStackDnsSuffix": "api.aws",
             "supportsFIPS": true,
             "supportsDualStack": true
         }
        """
        if value is None:
            return None
        for partition in self.provider.partitions['partitions']:
            if value in partition['regions']:
                output = {"name": partition['id']}
                output.update(partition['outputs'])
                return output

        # regionRegex is a fall back if there are no exact matches
        for partition in self.provider.partitions['partitions']:
            if re.match(partition['regionRegex'], value):
                output = {"name": partition['id']}
                output.update(partition['outputs'])
                return output

    def parse_arn(self, value):
        """Evaluates a single string argument value, and returns an
        object containing details about the parsed ARN.

        :type value: str
        :param value: A string representing an ARN

        :return: a dict containing parsed components of the ARN string e.g.
        {
            "partition": "aws",
            "service": "s3",
            "region": "us-east-1",
            "accountId": "012345678901",
            "resourceId": ["user", "Development", "product_1234", "*"]
        }
        """
        if value is None:
            return None
        arn_parser = ArnParser()
        try:
            arn_dict = arn_parser.parse_arn(value)
        except InvalidArnException:
            return None
        account = arn_dict.pop('account')
        resource = arn_dict.pop('resource')
        if ':' in resource:
            resource_id = resource.split(':')
        else:
            resource_id = resource.split('/')
        arn_dict['accountId'] = account
        arn_dict['resourceId'] = resource_id
        return arn_dict

    def string_equals(self, value1, value2):
        """Evaluates two string values value1 and value2 for
        equality and returns a boolean if both values match.

        :type value1: str
        :param value1: a string to compare

        :type value2: str
        :param value2: a string to compare

        :returns: a bool indicating if value1 and value2 equal each other
        """
        if value1 is None or value2 is None:
            return None

        if not all(isinstance(val, str) for val in (value1, value2)):
            raise TypeError("Both arguments must be strings")

        return value1 == value2

    def is_valid_host_label(self, value, allow_subdomains):
        """Evaluates whether one or more string values are valid host labels
        per RFC 1123. Each host label must be between [1, 63] characters, start
        with a number or letter, and only contain numbers, letters, or hyphens.
        If allowSubDomains is true, then the provided value may be zero or more
        dotted subdomains which are each validated per RFC 1123.

        :type value: str
        :param value: A string that may or may not be a valid RFC 1123 host label

        :type allow_subdomains: bool
        :param allow_subdomains: Indicating whether the input value can contain
        zero or more dotted subdomains

        :returns: A bool indicating whether the input value is a valid RFC 1123
        host label
        """
        if value is None:
            return None

        if UNSAFE_URL_CHARS.intersection(value):
            return False

        valid_host_re = re.compile(
            r"^((?!-)[A-Z\d-]{1,63}(?<!-)\.)*((?!-)[A-Z\d-]{1,63}(?<!-))$",
            re.IGNORECASE,
        )
        url_components = urlparse(value)
        hostname = url_components.hostname

        if hostname is None:
            return valid_host_re.match(value) is not None

        if allow_subdomains is True:
            # validate complete hostname and each domain within the host name
            to_check = [hostname] + hostname.split('.')
            for component in to_check:
                if valid_host_re.match(component) is None:
                    return False
            return True

        else:
            if hostname.count('.') > 1:
                return False

            return valid_host_re.match(hostname) is not None

    def uri_encode(self, value):
        """Given a string the function will perform percent-encoding per RFC3986
        section 2.1 link of the following characters: :/?#[]@!$&'()*+,;=%.

        :type value: str
        :param value: A string representing a URI to encode

        :returns: A percent encoded URI per RFC3986 spec
        """
        if value is None:
            return None
        return percent_encode(value)

    def parse_url(self, value):
        """Given a string the function will attempt to parse the string into its
        URL components. If the string can not be parsed into a valid URL then the
        function will return a null / empty optional.

        :type value: str
        :param value: A string representing a URL

        :returns: A dict containing all of the components contained within the URL or
        None if it can't be parsed. Example:

        {
            "scheme": "https",
            "authority": "example.com:80",
            "path": "foo/bar",
            "normalizedPath": "/foo/bar/", # guaranteed to start and end with `/`
            "isIp": True # bool whether or not URL is valid ipv4 or ipv6
        }
        """
        if value is None:
            return None

        url_components = urlparse(value)
        scheme = url_components.scheme
        query = url_components.query
        if scheme not in ['https', 'http'] or len(query) > 0:
            return None

        path = url_components.path
        normalized_path = quote(normalize_url_path(path))
        if not normalized_path.startswith('/'):
            normalized_path = f'/{normalized_path}'
        if not normalized_path.endswith('/'):
            normalized_path = f'{normalized_path}/'

        return {
            'scheme': scheme,
            'authority': url_components.netloc,
            'path': path,
            'normalizedPath': normalized_path,
            'isIp': is_valid_ipv4_endpoint_url(value)
            or is_valid_ipv6_endpoint_url(value),
        }

    def boolean_equals(self, value1, value2):
        """Evaluates two boolean values value1 and value2 for equality and returns
        a boolean true if both values match.

        :type value1: bool
        :param value1: a boolean to compare

        :type value2: bool
        :param value2: a boolean to compare

        :returns: A boolean indicating if the two values are equal.
        """
        if value1 is None or value2 is None:
            return None

        if not all(isinstance(val, bool) for val in (value1, value2)):
            raise TypeError("Both arguments must be booleans")

        return value1 is value2

    def substring(self, string_input, start, stop, reverse):
        """Computes the substring of a given string, conditionally indexing
        from the end of the string. When the string is long enough to fully
        include the substring, return the substring. Otherwise, return `None`.
        The start index is inclusive and the stop index is exclusive. The
        length of the returned string will always be `stop - start`.
        """
        if string_input is None:
            return None

        if not isinstance(string_input, str):
            raise TypeError("Input must be a string")

        if start >= stop or len(string_input) < stop:
            return None

        if reverse is True:
            r_start = len(string_input) - stop
            r_stop = len(string_input) - start
            return string_input[r_start:r_stop]

        return string_input[start:stop]

    def _not(self, value):
        """A function implementation of the logical operator `not`.

        :type value: Any
        :param value: A value returned by a function or contained
        within a rule's assignments.

        :returns: A bool indicating truthiness/falsiness of the input value.
        """
        return not value


class EndpointRule(BaseRule):
    """A class representing an endpoint rule i.e.
    {
        "conditions": [
            {
                "fn": "isSet",
                "argv": [
                    {
                        "ref": "Endpoint"
                    }
                ]
            },
            {
                "fn": "parseURL",
                "argv": [
                    {
                        "ref": "Endpoint"
                    }
                ],
                "assign": "url"
            }
        ],
        "endpoint": {
            "url": "https://{Bucket}.ec2.{url#authority}",
            "properties": {
                "authSchemes": [
                    {
                        "name": "v4",
                        "signingName": "s3-outposts",
                        "signingScope": "{Region}"
                    }
                ]
            },
            "headers": {}
        },
        "type": "endpoint"
    }
    """

    def __init__(self, endpoint, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.endpoint = Endpoint(**endpoint)

    def evaluate(self):
        """If an endpoint rule's conditions are met, return the
        fully resolved endpoint object

        :returns: A fully resolved Endpoint object
        """
        if self.evaluate_conditions() is True:
            return self.endpoint.resolve(self.assignments)


class ErrorRule(BaseRule):
    """A class representing an error rule i.e.
    {
        "conditions": [
            {
                "fn": "not",
                "argv": [
                    {
                        "fn": "isSet",
                        "argv": [
                            {
                                "ref": "Endpoint"
                            }
                        ]
                    }
                ]
            }
        ],
        "error": "Expected a endpoint to be specified but no endpoint was found",
        "type": "error"
    }
    """

    def __init__(self, error, documentation=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.error = Error(error=error, documentation=documentation)
        self.documentation = documentation

    def evaluate(self):
        """If an endpoint rule's conditions are met, raise the
        an EndpointError containing the fully resolved error
        string.

        :raises: An EndpointError containg the resolved error string.
        """
        if self.evaluate_conditions() is True:
            self.error.resolve(self.assignments)


class TreeRule(BaseRule):
    """A class representing a tree rule i.e.
    {
        "conditions": [
            {
            "fn": "isValidHostLabel",
            "argv": [
                {
                "ref": "parameterName"
                }
            ],
            "type": "tree",
            "rules": [
                {
                "type": "tree",
                "conditions": [
                    // Abbreviated for clarity
                ],
                "rules": [
                    // Abbreviated for clarity
                ]
                },
                {
                "type": "endpoint",
                "conditions": [
                    // Abbreviated for clarity
                ],
                "endpoint": {
                    "url": "{parameterName}.amazonaws.com"
                }
                },
                {
                "type": "error",
                "conditions": [
                    // Abbreviated for clarity
                ],
                "error": "an error message"
                }
            ]
            }
        ]
    }
    """

    def __init__(self, rules, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.rules = [
            RuleCreator.create(
                assignments=self.assignments, provider=self.provider, **rule
            )
            for rule in rules
        ]

    def evaluate(self):
        """If a tree rule's conditions evaluate successfully, iterate over its
        subordinate rules and return a result if there is one. If any of the
        suborinate rules are trees, the function will recurse until it reaches
        an error or an endpoint rule.

        :returns: An endpoint or error object.
        """
        if self.evaluate_conditions() is True:
            for rule in self.rules:
                evaluation = rule.evaluate()
                if evaluation:
                    return evaluation


class RuleCreator(Enum):
    """A helper class that creates rule objects."""

    endpoint = EndpointRule
    error = ErrorRule
    tree = TreeRule

    @classmethod
    def create(cls, **kwargs):
        """Given a rule dictionary, locate the `type` attribute, using it to
        determine the type of rule object to create.

        :type kwargs: dict
        :params kwargs: An arbitrary dictionary containing required parameters
        for different types of rule objects i.e. conditions, rules, errors,
        endpoints etc.
        """
        rule = getattr(cls, kwargs.pop('type'))
        return rule.value(**kwargs)


class ParameterType(Enum):
    """An enum that translates a parameter defintion's `type` attribute to
    its corresponding python native type.
    """

    String = str
    Boolean = bool


class ParameterDefinition:
    def __init__(
        self,
        name,
        type,
        documentation=None,
        builtIn=None,
        default=None,
        required=None,
        deprecated=None,
    ):

        self.name = name
        self.type = type
        self.documentation = documentation
        self.built_in = builtIn
        self.default = default
        self.required = required
        self.deprecated = deprecated

        self.validate_definition()

    def validate_definition(self):
        if self.required is False and self.default is not None:
            raise Exception(
                'Cannot set a default value if it is not a required parameter'
            )

    def validate_input(self, input_param):
        if self.required is True and input_param is None:
            raise Exception(f'Required parameter {self.name} not provided.')

        correct_param_type = getattr(ParameterType, self.type).value
        if not isinstance(input_param, correct_param_type):
            raise Exception(
                f'Input parameter {self.name} is the wrong type. '
                f'Must be {correct_param_type}'
            )

        if input_param is None and self.default is not None:
            input_param = self.default

        return input_param


class Ruleset:
    def __init__(self, version, parameters, rules, input_parameters, provider):
        self.version = version
        self.parameters = {
            name: ParameterDefinition(name, **spec)
            for name, spec in parameters.items()
        }
        self.rules = [
            RuleCreator.create(
                assignments=input_parameters, provider=provider, **rule
            )
            for rule in rules
        ]
        self.input_parameters = input_parameters
        self.provider = provider

    def validate_input_parameters(self):
        for name, value in self.input_parameters.items():
            param_spec = self.parameters.get(name)
            if param_spec is None:
                breakpoint()
            self.input_parameters[name] = param_spec.validate_input(value)


class EndpointProvider:
    def __init__(self, ruleset_data, partition_data):
        self.ruleset_data = ruleset_data
        self.partitions = partition_data

    def get_parameters_definition(self):
        """Extract `parameters` object contained within the ruleset and
        transform into a list of dictionaries. If a parameter isn't provided,
        resolve to a falsey equivalent. Used by the endpoint resolver to
        determine which parameters to pass to `resolve_endpoint`.

        :returns: A list of dicts each containing specs about an accepted
        parameter of an operation e.g. input of
        {
            "parameters" : {
                "region": {"type": "string", "builtIn": "AWS::Region", "required": True}
            }
        }
        becomes
        [{
            "name": "region",
            "type": "string",
            "builtIn": "AWS::Region",
            "default": None,
            "required": True,
            "documentation": "",
            "deprecated": {}.
        }]
        """
        params = self._ruleset_data['parameters']
        formatted_params = []
        for param_name, param_spec in params.items():
            formatted_param = {
                "name": param_name,
                "type": param_spec['type'],
                "default": param_spec.get("default"),
                "required": param_spec.get("required", False),
                "documentation": param_spec.get("documentation", ""),
                "deprecated": param_spec.get("deprecated", {}),
            }
            if param_spec.get("builtIn") is not None:
                formatted_param["builtIn"] = param_spec["builtIn"]
            formatted_params.append(formatted_param)
        return formatted_params

    def evaluate_ruleset(self, ruleset):

        for rule in ruleset.rules:
            evaluation = rule.evaluate()
            if evaluation is not None:
                return evaluation

    # caching method may not be thread safe
    @lru_cache(maxsize=None)
    def resolve_endpoint(self, **endpoint_parameters):
        """The main API that the endpoint resolver will call.
        This is responsible for parsing parameters provided by
        the user, checking that all required parameters are
        provided, then matching it to a rule by running each rule's
        set of conditions.

        :type endpoint_parameters: dict
        :param endpoint_parameters: A generic dictionary containing
        parameters to apply to a service's and/or operation's endpoint.
        Examples include region, service name, bucket name etc.

        :return: A fully resolved endpoint dictionary e.g.

        "endpoint": {
            "url": "example.us-west-2.amazonaws.com",
            "properties": {
                "authSchemes": [{
                    "name": "v4",
                    "signingName": "example",
                    "signingScope": "us-west-2"
                }]
            },
            "headers": {}, # only used by s3 for now
        }
        """
        ruleset = Ruleset(
            provider=self,
            input_parameters=endpoint_parameters,
            **self.ruleset_data,
        )
        ruleset.validate_input_parameters()
        return self.evaluate_ruleset(ruleset)

import json
import os
import time

from botocore.endpoints_v2 import EndpointProvider
from botocore.loaders import Loader

test_data = os.path.join(
    os.path.dirname(__file__),
    'tests',
    'unit',
    'data',
    'endpoints',
    's3',
    'endpoint-tests.json',
)

with open(test_data) as f:
    data = f.read()
    tests = json.loads(data)

loader = Loader()
test_cases = [x for x in tests['testCases'] if 'url' in x['expect']]

partitions = loader.load_data('partitions')
ruleset = loader.load_service_model('s3', 'endpoint-rule-set')

ep = EndpointProvider(ruleset, partitions)
for i in range(10):
    start = time.perf_counter()
    for test in test_cases:
        endpoint = ep.resolve_endpoint(**test['params'])
    print(f'Time: {time.perf_counter() - start} seconds')

import requests
import base64
from const import API_TIMEOUT


header1 = {'APPKEY': '5ee218a0-25ec-463a-81f5-6c5364707cda'}
header2 = {'content-type': 'application/json',
           'APPKEY': '5ee218a0-25ec-463a-81f5-6c5364707cda',
           'Authorization': 'Basic ' + base64.b64encode('user:')}


def get(*args, **kwargs):
    header = header1
    if 'headers' not in kwargs:
        kwargs['headers'] = header
    else:
        for k, v in header.items():
            kwargs['headers'][k] = v
    if 'timeout' not in kwargs:
        kwargs['timeout'] = API_TIMEOUT
    return requests.get(*args, **kwargs)


def patch(*args, **kwargs):
    header = header2
    if 'headers' not in kwargs:
        kwargs['headers'] = header
    else:
        for k, v in header.items():
            kwargs['headers'][k] = v
    if 'verify' not in kwargs:
        kwargs['verify'] = False
    if 'timeout' not in kwargs:
        kwargs['timeout'] = API_TIMEOUT
    return requests.patch(*args, **kwargs)


def delete(*args, **kwargs):
    header = header1
    if 'headers' not in kwargs:
        kwargs['headers'] = header
    else:
        for k, v in header.items():
            kwargs['headers'][k] = v
    if 'timeout' not in kwargs:
        kwargs['timeout'] = API_TIMEOUT
    return requests.delete(*args, **kwargs)


def post(*args, **kwargs):
    header = header2
    if 'headers' not in kwargs:
        kwargs['headers'] = header
    else:
        for k, v in header.items():
            kwargs['headers'][k] = v
    if 'timeout' not in kwargs:
        kwargs['timeout'] = API_TIMEOUT
    return requests.post(*args, **kwargs)


def put(*args, **kwargs):
    header = header2
    if 'headers' not in kwargs:
        kwargs['headers'] = header
    else:
        for k, v in header.items():
            kwargs['headers'][k] = v
    if 'verify' not in kwargs:
        kwargs['verify'] = False
    if 'timeout' not in kwargs:
        kwargs['timeout'] = API_TIMEOUT
    return requests.put(*args, **kwargs)


def get_stats(*args, **kwargs):
    header = {}
    if 'headers' not in kwargs:
        kwargs['headers'] = header
    else:
        for k, v in header.items():
            kwargs['headers'][k] = v
    if 'timeout' not in kwargs:
        kwargs['timeout'] = API_TIMEOUT
    return requests.get(*args, **kwargs)

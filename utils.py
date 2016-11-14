import functools
import struct
import socket
import simplejson as json
import re
from flask import Response

import models


def ip2long(ip):
    return struct.unpack('!L', socket.inet_aton(ip))[0]


def long2ip(ip_long):
    return socket.inet_ntoa(struct.pack('!L', ip_long))


def process_request_args(args, model=None):
    filters = {}
    fields = []
    fields_transformer = {}
    if model is not None:
        assert issubclass(model, models.BaseModel)
        for k, v in model._fields.items():
            fields_transformer[v.serialized_name] = k
    for k, v in args.iterlists():
        if k == 'fields':
            fields = v
        else:
            nk = fields_transformer.get(k, k)
            if nk not in filters:
                filters[nk] = v
    return filters, fields


Response = functools.partial(Response,
                             content_type='application/json; charset=utf-8')


def ip_to_bin(ipaddr):
    """string IP to binary
    """
    (a, b, c, d) = [int(str) for str in ipaddr.split('.')]
    return (a << 24) + (b << 16) + (c << 8) + d


def bin_to_ip(binaddr):
    """binary IP to string
    """
    return '%d.%d.%d.%d' % (binaddr >> 24,
                            (binaddr & 0x00FFFFFF) >> 16,
                            (binaddr & 0x0000FFFF) >> 8,
                            binaddr & 0x000000FF)


def masklen2netmask(masklen):
    """convert masklen to netmask
    """
    return bin_to_ip(0xffffffff ^ (0xffffffff >> masklen))


def get_ip_list_from_cidr(cidr=None):
    cidr = str(cidr).split('/')
    ip_bin = ip_to_bin(cidr[0])
    netmask_bin = ip_to_bin(masklen2netmask(int(cidr[1])))
    prefix_bin = ip_bin & netmask_bin
    ip_num = 0xFFFFFFFF - netmask_bin
    if ip_num == 0:
        ip_began = prefix_bin
        ip_end = ip_began + 1
    else:
        ip_began = prefix_bin
        ip_end = prefix_bin + ip_num + 1

    return [bin_to_ip(ip) for ip in xrange(ip_began, ip_end)]


def ip_mask_to_cidr(ip=None, masklen=None):
    prefix_bin = ip_to_bin(ip) & (0xffffffff ^ (0xffffffff >> masklen))
    prefix = bin_to_ip(prefix_bin)
    return prefix + '/' + str(masklen)


def ip_list_to_alloc_pools(ips):
    assert isinstance(ips, list)
    ips = [ip_to_bin(it) for it in ips]
    ips.sort()
    all_pool = []
    pool = {}
    start = ips[0]
    end = ips[-1]
    pool['start'] = bin_to_ip(start)
    for ip in ips:
        if ip == start:
            continue
        if ip == start + 1:
            start = ip
            end = ip
            continue
        pool['end'] = bin_to_ip(end)
        all_pool.append(pool)
        pool = {}
        start = ip
        end = ip
        pool['start'] = bin_to_ip(start)
    pool['end'] = bin_to_ip(end)
    all_pool.append(pool)

    return all_pool


def alloc_pools_to_ip_list(pools=[]):
    ips = []
    for pool in pools:
        start = pool['start']
        end = pool['end']
        for ip in range(ip_to_bin(start), ip_to_bin(end) + 1):
            if ip not in ips:
                ips.append(bin_to_ip(ip))

    return ips


def err_return(message='', type='', detail='', code=200):
    result = {
        "NeutronError": {
            "message": message,
            "type": type,
            "detail": detail
        }
    }
    return Response(json.dumps(result)), code


def validate_ip(ip):
    if '\n' in ip:
        return False

    IP_REGEX = re.compile(
        r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})\.){3}'
        '(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})$')
    if re.match(IP_REGEX, ip) is None:
        return False
    else:
        return True


def validate_cidr(cidr=None):
    try:
        if not cidr:
            return False
        cidr = cidr.split('/')
        if len(cidr) != 2:
            return False
        mask_len = int(cidr[1])
        if mask_len < 0 or mask_len > 32:
            return False
        return validate_ip(cidr[0])

    except Exception:
        return False

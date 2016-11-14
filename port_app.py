from collections import defaultdict
import logging
import simplejson as json
import uuid

from flask import Blueprint
from flask import request
import MySQLdb

from conf import conf
from const import DB_INFO, NEUTRON_500, API_PREFIX
from documentation import autodoc
import lcapi
import models
from utils import ip2long, long2ip
from utils import process_request_args
from utils import Response

log = logging.getLogger(__name__)
port_app = Blueprint('port_app', __name__)


@port_app.route(API_PREFIX + '/ports')
@autodoc.doc(groups=['public', __name__])
def port_get_api(id=None):
    """
    Implementation Notes
        List ports.

    Response Class (Status 200)
        Port {
            portId (string, optional): Port uuid. ,
            portName (string, optional): Port name, a user readable name. ,
            macAddress (string, optional): The MAC address. ,
            fixedIps (Array[string], optional): IP address to use on the
                port. ,
            subnetId (string, optional): Subnet uuid. If you specify only
                a subnet UUID, OpenStack Networking allocates an available
                IP from that subnet to the port. If you specify both a subnet
                UUID and an IP address, OpenStack Networking tries to allocate
                the address to the port. ,
            networkId (string, optional): The UUID of the network. ,
            deviceType (string, optional): The device type this port serves.
                For example, nova:compute, network:router_interface,
                network:dhcp. ,
            deviceId (string, optional): The device id this port serves.
                For example, hostname of a hypervisor, or uuid of a router. ,
            localVlanId (integer, optional): Local VLAN id that should be used
                to tag packet from the VM. This VLAN id is assigned by network
                controller according to deviceType and deviceId. When port
                deviceType is nova:compute, and deviceId is set, this property
                should be set by networking server.
        }

    Parameters
        networkId
    """
    code = 200
    filters = {}
    if id is not None:
        filters['id'] = [id]
        _, fields = process_request_args(request.args, models.Port)
    else:
        filters, fields = process_request_args(request.args, models.Port)
    lcfilters = {}
    for k, v in filters.items():
        lcfilters[k.upper()] = v

    items = []
    try:
        with MySQLdb.connect(**DB_INFO) as cursor:
            if id is not None:
                sql = 'SELECT * FROM neutron_ports WHERE id=%s'
                cursor.execute(sql, id)
                desc = [it[0] for it in cursor.description]
                item = cursor.fetchone()
                if item is not None:
                    items = [dict(zip(desc, item))]
            else:
                conds = 'TRUE'
                params = []
                if 'id' in filters and filters['id']:
                    rstr = ','.join(['%s' for it in filters['id']])
                    conds += ' AND id IN (%s)' % rstr
                    params.extend(filters['id'])
                if 'device_id' in filters and filters['device_id']:
                    rstr = ','.join(['%s' for it in filters['device_id']])
                    conds += ' AND device_id IN (%s)' % rstr
                    params.extend(filters['device_id'])
                if 'network_id' in filters and filters['network_id']:
                    rstr = ','.join(['%s' for it in filters['network_id']])
                    conds += ' AND network_id IN (%s)' % rstr
                    params.extend(filters['network_id'])
                sql = 'SELECT * FROM neutron_ports WHERE ' + conds
                cursor.execute(sql, tuple(params))
                desc = [it[0] for it in cursor.description]
                for item in cursor:
                    items.append(dict(zip(desc, item)))
            if items:
                sql = 'SELECT ip_address,port_id,subnet_id FROM '
                sql += 'neutron_port_ip WHERE port_id IN ('
                sql += ','.join(['%s' for it in items]) + ')'
                cursor.execute(sql, tuple([it['id'] for it in items]))
                ips = defaultdict(list)
                for item in cursor:
                    ips[item[1]].append({
                        'subnet_id': item[2],
                        'ip_address': item[0]
                    })
    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), 500

    ri = None
    rs = []
    for item in items:
        r_item = models.Port()
        if not fields:
            fields = r_item.serialized_field_names()
        if r_item.serialized_name('id') in fields:
            r_item.id = item.get('id', None)
        if r_item.serialized_name('name') in fields:
            r_item.name = item.get('name', None)
        if r_item.serialized_name('mac_address') in fields:
            r_item.mac_address = item.get('mac_address', None)
        fixed_ips = ips.get(item.get('id', None), [])
        if r_item.serialized_name('fixed_ips') in fields:
            r_item.fixed_ips = [it['ip_address'] for it in fixed_ips]
        if r_item.serialized_name('subnet_id') in fields:
            if fixed_ips:
                r_item.subnet_id = fixed_ips[0]['subnet_id']
        if r_item.serialized_name('network_id') in fields:
            r_item.network_id = item.get('network_id', None)
        if r_item.serialized_name('device_type') in fields:
            r_item.device_type = item.get('device_type', None)
        if r_item.serialized_name('device_id') in fields:
            r_item.device_id = item.get('device_id', None)

        r_item_dict = r_item.filtered_fields(fields)
        if id is not None:
            ri = r_item_dict
            break
        rs.append(r_item_dict)
    if id is not None:
        if ri is None:
            result = {
                "NeutronError": {
                    "message": "Port %s could not be found" % id,
                    "type": "PortNotFound",
                    "detail": ""
                }
            }
            code = 404
        else:
            result = ri
    else:
        result = rs

    return Response(json.dumps(result)), code


@port_app.route(API_PREFIX + '/ports/<id>')
def port_get_one_api(id):
    """
    Implementation Notes
        Shows details for a port.

    Response Class (Status 200)
        Port {
            portId (string, optional): Port uuid. ,
            portName (string, optional): Port name, a user readable name. ,
            macAddress (string, optional): The MAC address. ,
            fixedIps (Array[string], optional): IP address to use on the
                port. ,
            subnetId (string, optional): Subnet uuid. If you specify only
                a subnet UUID, OpenStack Networking allocates an available
                IP from that subnet to the port. If you specify both a subnet
                UUID and an IP address, OpenStack Networking tries to allocate
                the address to the port. ,
            networkId (string, optional): The UUID of the network. ,
            deviceType (string, optional): The device type this port serves.
                For example, nova:compute, network:router_interface,
                network:dhcp. ,
            deviceId (string, optional): The device id this port serves.
                For example, hostname of a hypervisor, or uuid of a router. ,
            localVlanId (integer, optional): Local VLAN id that should be used
                to tag packet from the VM. This VLAN id is assigned by network
                controller according to deviceType and deviceId. When port
                deviceType is nova:compute, and deviceId is set, this property
                should be set by networking server.
        }

    Parameters
        portId
    """
    return port_get_api(id)


def allocate_next_ip(cidr, allocation_pools):
    prefix, netmask = cidr.split('/')[:2]
    netmask = int(netmask)
    netmask_int = 0xFFFFFFFF >> netmask
    max_ip_int = ip2long(prefix) | netmask_int
    min_ip_int = ip2long(prefix) & (~netmask_int)
    alpl = sorted(allocation_pools, key=lambda x: ip2long(x['start']))
    if alpl:
        for it in alpl:
            start_int = ip2long(it['start'])
            end_int = ip2long(it['end'])
            for i in range(start_int, end_int + 1):
                if i >= min_ip_int and i <= max_ip_int:
                    yield long2ip(i)
    else:
        for i in range(min_ip_int + 2, max_ip_int):
            yield long2ip(i)


@port_app.route(API_PREFIX + '/ports', methods=['POST'])
@autodoc.doc(groups=['public', __name__])
def port_post_api():
    """
    Implementation Notes
        Creates a port on a network.

    Response Class (Status 201)
        Port {
            portId (string, optional): Port uuid. ,
            portName (string, optional): Port name, a user readable name. ,
            macAddress (string, optional): The MAC address. ,
            fixedIps (Array[string], optional): IP address to use on the
                port. ,
            subnetId (string, optional): Subnet uuid. If you specify only
                a subnet UUID, OpenStack Networking allocates an available
                IP from that subnet to the port. If you specify both a subnet
                UUID and an IP address, OpenStack Networking tries to allocate
                the address to the port. ,
            networkId (string, optional): The UUID of the network. ,
            deviceType (string, optional): The device type this port serves.
                For example, nova:compute, network:router_interface,
                network:dhcp. ,
            deviceId (string, optional): The device id this port serves.
                For example, hostname of a hypervisor, or uuid of a router. ,
            localVlanId (integer, optional): Local VLAN id that should be used
                to tag packet from the VM. This VLAN id is assigned by network
                controller according to deviceType and deviceId. When port
                deviceType is nova:compute, and deviceId is set, this property
                should be set by networking server.
        }

    Parameters
        port
    """
    try:
        req = models.Port(request.json)
        req.validate()
    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), 500

    new_port = {}
    new_port['id'] = str(uuid.uuid4())
    new_port['name'] = req.name
    new_port['device_type'] = req.device_type

    if req.mac_address is None:
        result = {"NeutronError": {
            "message": "MAC is None",
            "type": "MACIsNone",
            "detail": ""
        }}
        return Response(json.dumps(result)), 400
    try:
        with MySQLdb.connect(**DB_INFO) as cursor:
            sql = 'SELECT * FROM neutron_ports WHERE mac_address=%s'
            cursor.execute(sql, req.mac_address)
            if cursor.fetchone() is not None:
                result = {"NeutronError": {
                    "message": "MAC %s conflicts" % req.mac_address,
                    "type": "MACConflict",
                    "detail": ""
                }}
                return Response(json.dumps(result)), 400
    except:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), 500
    new_port['mac_address'] = req.mac_address

    try:
        params = []
        if req.subnet_id is not None:
            conds = 'id=%s'
            params = req.subnet_id
        elif req.network_id is not None:
            conds = 'network_id=%s'
            params = req.network_id
        else:
            result = {"NeutronError": {
                "message": "No network or subnet specified",
                "type": "NoNetworkOrSubnet",
                "detail": ""
            }}
            return Response(json.dumps(result)), 400

        nets = []
        with MySQLdb.connect(**DB_INFO) as cursor:
            sql = 'SELECT * FROM neutron_subnets WHERE ' + conds
            cursor.execute(sql, params)
            desc = [it[0] for it in cursor.description]
            for item in cursor:
                nets.append(dict(zip(desc, item)))

        if not nets:
            if req.subnet_id is not None:
                result = {"NeutronError": {
                    "message": "Subnet %s could not be found" % req.subnet_id,
                    "type": "SubnetNotFound",
                    "detail": ""
                }}
                return Response(json.dumps(result)), 400
            elif req.network_id is not None:
                result = {"NeutronError": {
                    "message": ("Network %s could not be found" %
                                req.network_id),
                    "type": "NetworkNotFound",
                    "detail": ""
                }}
                return Response(json.dumps(result)), 400
            else:
                # won't reach here
                assert False

        ips = []
        net_ids = []
        sql_rstr = []
        for it in nets:
            net_ids.append(it['id'])
            sql_rstr.append('%s')
        with MySQLdb.connect(**DB_INFO) as cursor:
            sql = 'SELECT * FROM neutron_port_ip WHERE subnet_id IN ('
            sql += ','.join(sql_rstr) + ')'
            cursor.execute(sql, tuple(net_ids))
            desc = [it[0] for it in cursor.description]
            for item in cursor:
                ips.append(dict(zip(desc, item)))

    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), 500

    ip_grouped_by_net = defaultdict(list)
    for ip in ips:
        ip_grouped_by_net[ip['subnet_id']].append(ip['ip_address'])
    allocate_net = nets[0]
    metric = 0
    for net in nets:
        netmask = int(net['cidr'].split('/')[1])
        try:
            alpl = json.loads(net['allocation_pools'])
            for it in alpl:
                assert ip2long(it['start']) < ip2long(it['end'])
            # TODO: check overlap pools
        except Exception as e:
            alpl = []
        alpl_metric = 0
        for it in alpl:
            alpl_metric += ip2long(it['start']) - ip2long(it['end'])
        cidr_metric = (1 << (32 - netmask))
        if alpl_metric < cidr_metric:
            new_metric = alpl_metric
        else:
            new_metric = cidr_metric
        new_metric -= len(ip_grouped_by_net[net['id']])
        if new_metric > metric:
            allocate_net = net
    existing_ips = ip_grouped_by_net[allocate_net['id']]
    new_ip = []
    if req.fixed_ips:
        for it in req.fixed_ips:
            if it in existing_ips:
                result = {"NeutronError": {
                    "message": "IP %s conflicts" % it,
                    "type": "IPConflict",
                    "detail": ""
                }}
                return Response(json.dumps(result)), 400
            if it not in new_ip:
                new_ip.append(it)
    else:
        nip = None
        for i in allocate_next_ip(allocate_net['cidr'],
                                  json.loads(
                                      allocate_net['allocation_pools'])):
            if i in existing_ips:
                continue
            else:
                nip = i
                break
        if nip is None:
            result = {"NeutronError": {
                "message": "Failed to allocate IP",
                "type": "IPAllocationFailure",
                "detail": ""
            }}
            return Response(json.dumps(result)), 500

        new_ip = [nip]

    new_port['network_id'] = allocate_net['network_id']

    try:
        url = conf.livecloud_url + '/v1/interfaces/'
        req_data = {'MAC': new_port['mac_address']}
        log.debug('Post to %s with data %s' % (url, req_data))
        r = lcapi.post(url, data=json.dumps(req_data))
        resp = r.json()
        if (resp['OPT_STATUS'] in ['SUCCESS', 'RESOURCE_ALREADY_EXIST']
                and 'DATA' in resp):
            new_port['lcuuid'] = resp['DATA']['LCUUID']
        else:
            raise Exception(resp['OPT_STATUS'])
        log.debug('Interface lcuuid is %s' % new_port['lcuuid'])
    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), 500
    try:
        with MySQLdb.connect(**DB_INFO) as cursor:
            if req.device_id is not None:
                new_port['device_id'] = req.device_id
            s = ','.join(['%s' for i in range(len(new_port))])
            sql = 'INSERT INTO neutron_ports ('
            sql += ','.join(new_port.keys())
            sql += ') VALUES (' + s + ')'
            cursor.execute(sql, tuple(new_port.values()))
            for it in new_ip:
                sql = 'INSERT INTO neutron_port_ip '
                sql += '(port_id, subnet_id, ip_address) VALUES (%s,%s,%s)'
                cursor.execute(sql, tuple([
                    new_port['id'], allocate_net['id'], it]))
    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), 500

    resp = models.Port(req.to_primitive())
    resp.id = new_port['id']
    resp.mac_address = new_port['mac_address']
    resp.fixed_ips = new_ip
    resp.subnet_id = allocate_net['id']
    resp.network_id = allocate_net['network_id']

    result = resp.to_primitive()

    return Response(json.dumps(result)), 201


@port_app.route(API_PREFIX + '/ports/<id>', methods=['PUT'])
@autodoc.doc(groups=['public', __name__])
def port_put_api(id):
    """
    Implementation Notes
        Updates a port.

    Response Class (Status 200)
        Port {
            portId (string, optional): Port uuid. ,
            portName (string, optional): Port name, a user readable name. ,
            macAddress (string, optional): The MAC address. ,
            fixedIps (Array[string], optional): IP address to use on the
                port. ,
            subnetId (string, optional): Subnet uuid. If you specify only
                a subnet UUID, OpenStack Networking allocates an available
                IP from that subnet to the port. If you specify both a subnet
                UUID and an IP address, OpenStack Networking tries to allocate
                the address to the port. ,
            networkId (string, optional): The UUID of the network. ,
            deviceType (string, optional): The device type this port serves.
                For example, nova:compute, network:router_interface,
                network:dhcp. ,
            deviceId (string, optional): The device id this port serves.
                For example, hostname of a hypervisor, or uuid of a router. ,
            localVlanId (integer, optional): Local VLAN id that should be used
                to tag packet from the VM. This VLAN id is assigned by network
                controller according to deviceType and deviceId. When port
                deviceType is nova:compute, and deviceId is set, this property
                should be set by networking server.
        }

    Parameters
        portId
        port

    Response Messages
        HTTP Status Code    Reason          Response Model      Headers
        200                 Port updated.
    """
    try:
        req = models.Port(request.json)
        req.validate()
    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), 500

    try:
        with MySQLdb.connect(**DB_INFO) as cursor:
            sql = 'SELECT * FROM neutron_ports WHERE id=%s'
            cursor.execute(sql, id)
            item = cursor.fetchone()
            if item is None:
                result = {
                    "NeutronError": {
                        "message": "Port %s could not be found" % id,
                        "type": "PortNotFound",
                        "detail": ""
                    }
                }
                return Response(json.dumps(result)), 404
            desc = [it[0] for it in cursor.description]
            port = dict(zip(desc, item))

            fields = []
            values = []
            if req.name is not None and req.name != port['name']:
                fields.append('name=%s')
                values.append(req.name)
                port['name'] = req.name
            if (req.device_type is not None and
                    req.device_type != port['device_type']):
                fields.append('device_type=%s')
                values.append(req.device_type)
                port['device_type'] = req.device_type
            if (req.device_id is not None and
                    req.device_id != port['device_id']):

                sql = 'SELECT lcuuid FROM neutron_networks WHERE id=%s'
                cursor.execute(sql, port['network_id'])
                item = cursor.fetchone()
                if item is None:
                    result = {
                        "NeutronError": {
                            "message": ("Network %s could not be "
                                        "found" % port['network_id']),
                            "type": "NetworkNotFound",
                            "detail": ""
                        }
                    }
                    return Response(json.dumps(result)), 404
                network_lcuuid = item[0]

                sql = 'SELECT t1.ip_address,t2.net_idx FROM '
                sql += 'neutron_port_ip t1 INNER JOIN '
                sql += 'neutron_subnets t2 ON t1.subnet_id=t2.id '
                sql += 'WHERE t1.port_id=%s'
                cursor.execute(sql, port['id'])
                ips_data = []
                for item in cursor:
                    ips_data.append({'VL2_NET_INDEX': item[1],
                                     'ADDRESS': item[0]})

                url = conf.livecloud_url
                url = url + '/v1/interfaces/%s/' % port['lcuuid']
                req_data = {
                    'STATE': 1,
                    'IF_TYPE': 'LAN',
                    'LAN': {
                        'VL2_LCUUID': network_lcuuid,
                        'IP_ALLOCATION_MODE': 'STATIC',
                        'IPS': ips_data,
                        'QOS': {'MIN_BANDWIDTH': 0, 'MAX_BANDWIDTH': 0}
                    },
                    'SWITCH_IP': req.device_id
                }
                log.debug('Patch to %s with data %s' % (url, req_data))
                lcapi.put(url, data=json.dumps(req_data))

                fields.append('device_id=%s')
                values.append(req.device_id)
                port['device_id'] = req.device_id

            if values:
                sql = 'UPDATE neutron_ports SET '
                sql += ','.join(fields)
                sql += ' WHERE id=%s'
                cursor.execute(sql, tuple(values + [id]))

            sql = 'SELECT ip_address,subnet_id FROM neutron_port_ip '
            sql += 'WHERE port_id=%s'
            cursor.execute(sql, port['id'])
            ips = []
            for item in cursor:
                ips.append({'subnet_id': item[1],
                            'ip_address': item[0]})

            r_item = models.Port()
            r_item.id = port.get('id', None)
            r_item.name = port.get('name', None)
            r_item.mac_address = port.get('mac_address', None)
            r_item.fixed_ips = [it['ip_address'] for it in ips]
            if ips:
                r_item.subnet_id = ips[0]['subnet_id']
            r_item.network_id = port.get('network_id', None)
            r_item.device_type = port.get('device_type', None)
            r_item.device_id = port.get('device_id', None)

            result = r_item.to_primitive()

            return Response(json.dumps(result)), 200

    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), 500
    return Response(), 204


@port_app.route(API_PREFIX + '/ports/<id>', methods=['DELETE'])
@autodoc.doc(groups=['public', __name__])
def port_delete_api(id):
    """
    Implementation Notes
        Deletes a port.

    Parameters
        portId

    Response Messages
        HTTP Status Code    Reason          Response Model      Headers
        200                 Port deleted.
    """
    try:
        with MySQLdb.connect(**DB_INFO) as cursor:
            sql = 'SELECT * FROM neutron_ports WHERE id=%s'
            cursor.execute(sql, id)
            item = cursor.fetchone()
            if item is None:
                result = {
                    "NeutronError": {
                        "message": "Port %s could not be found" % id,
                        "type": "PortNotFound",
                        "detail": ""
                    }
                }
                return Response(json.dumps(result)), 404
            desc = [it[0] for it in cursor.description]
            port = dict(zip(desc, item))

            url = conf.livecloud_url + '/v1/interfaces/%s/' % port['lcuuid']
            url += '?skip_switch_config=false'
            log.debug('Delete to %s' % url)
            lcapi.delete(url)

            sql = 'DELETE FROM neutron_ports WHERE id=%s'
            cursor.execute(sql, id)
            sql = 'DELETE FROM neutron_port_ip WHERE port_id=%s'
            cursor.execute(sql, id)
    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), 500
    return Response(), 200

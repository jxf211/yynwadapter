import logging
import simplejson as json

from flask import Blueprint
from flask import request
import MySQLdb

from conf import conf
from const import DB_INFO, NEUTRON_500, API_PREFIX
from documentation import autodoc
import lcapi
import models
from utils import Response
import copy
LC_DB_INFO = copy.copy(DB_INFO)
LC_DB_INFO['db'] = 'livecloud'

log = logging.getLogger(__name__)
arp_app = Blueprint('arp_app', __name__)


@arp_app.route(API_PREFIX + '/arp', methods=['GET'])
@autodoc.doc(groups=['public', __name__])
def arp_get_api():
    """
    Implementation Notes
        Gets all ARP records.

    Response Class (Status 200)
        ArpRecord {
            ip (string, optional): IP addresss. ,
            mac (string, optional): MAC address. ,
            networkType (string, optional): Network type. Valid values are
                                            'VLAN' and 'VXLAN'. ,
            segmentationId (integer, optional): VLAN id or VXLAN vni
        }

    Parameters
        None
    """
    code = 200
    port_items = []
    try:
        with MySQLdb.connect(**DB_INFO) as cursor:
            sql = 'SELECT * FROM neutron_ports WHERE mac_address IS NOT NULL'
            cursor.execute(sql)
            desc = [it[0] for it in cursor.description]
            for item in cursor:
                port_items.append(dict(zip(desc, item)))

    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), 500

    result = []
    for port_item in port_items:
        r_item = models.ArpReply()
        fields = r_item.serialized_field_names()
        r_item.mac = port_item.get('mac_address', None)
        sql = 'SELECT * FROM neutron_networks WHERE id=%s'
        sql_param = port_item.get('network_id', None)
        cursor.execute(sql, sql_param if sql_param else '0')
        desc = [it[0] for it in cursor.description]
        item = cursor.fetchone()
        if item:
            network_item = dict(zip(desc, item))
            r_item.network_type = network_item.get('type', None)
            r_item.segmentation_id = network_item.get('segmentation_id', 0)
        sql = 'SELECT * FROM neutron_port_ip WHERE port_id=%s'
        sql_param = port_item.get('id', None)
        cursor.execute(sql, sql_param if sql_param else '0')
        desc = [it[0] for it in cursor.description]
        item = cursor.fetchone()
        if item:
            port_ip_item = dict(zip(desc, item))
            r_item.ip = port_ip_item.get('ip_address', None)

        r_item_dict = r_item.filtered_fields(fields)
        result.append(r_item_dict)

    return Response(json.dumps(result)), code


@arp_app.route(API_PREFIX + '/arp/bymac', methods=['GET'])
@autodoc.doc(groups=['public', __name__])
def arp_bymac_get_api():
    """
    Implementation Notes
        Returns IP address for given MAC address.

    Response Class (Status 200)
        ArpRecord {
            ip (string, optional): IP addresss. ,
            mac (string, optional): MAC address. ,
            networkType (string, optional): Network type. Valid values are
                                            'VLAN' and 'VXLAN'. ,
            segmentationId (integer, optional): VLAN id or VXLAN vni
        }

    Parameters
        {
            networkType (string): Network type. Valid values are
                                  'VLAN' and 'VXLAN'. ,
            segmentationId (string): VLAN id or VXLAN vni. ,
            macAddress (string): MAC address.
        }
    """
    try:
        req = models.ArpRequest(request.json)
        req.validate()
    except Exception as e:
        result = {
            "NeutronError": {
                "message": "Request check failed: %s" % e,
                "type": "BadRequest",
                "detail": ""
            }
        }
        log.error(result)
        return Response(json.dumps(result)), 500
    if req.mac_address is None:
        result = {
            "NeutronError": {
                "message": "Request check failed, macAddress not given",
                "type": "BadRequest",
                "detail": ""
            }
        }
        log.error(result)
        return Response(json.dumps(result)), 500

    return get_arp_bymac(req)


def get_arp_bymac(req, raw=False):
    code = 200
    network_item = None
    try:
        with MySQLdb.connect(**DB_INFO) as cursor:
            sql = 'SELECT * FROM neutron_networks WHERE ' \
                + 'type=%s AND segmentation_id=%s'
            cursor.execute(sql, (req.network_type, req.segmentation_id))
            desc = [it[0] for it in cursor.description]
            item = cursor.fetchone()
            if item:
                network_item = dict(zip(desc, item))
    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), 500
    if not network_item:
        result = {
            "NeutronError": {
                "message": "%s network %s of macAddress %s not found"
                           % (req.network_type,
                              req.segmentation_id,
                              req.mac_address),
                "type": "BadRequest",
                "detail": ""
            }
        }
        log.error(result)
        return Response(json.dumps(result)), 400

    port_item = None
    try:
        with MySQLdb.connect(**DB_INFO) as cursor:
            sql = 'SELECT * FROM neutron_ports WHERE ' \
                + 'network_id=%s AND mac_address=%s'
            sql_param = network_item.get('id', None)
            cursor.execute(sql, (sql_param if sql_param else '0',
                                 req.mac_address))
            desc = [it[0] for it in cursor.description]
            item = cursor.fetchone()
            if item:
                port_item = dict(zip(desc, item))
    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), 500
    if not port_item:
        result = {
            "NeutronError": {
                "message": "Port of network %s and macAddress %s not found"
                           % (network_item.get('id', None), req.mac_address),
                "type": "BadRequest",
                "detail": ""
            }
        }
        log.error(result)
        return Response(json.dumps(result)), 400

    port_ip_items = []
    try:
        with MySQLdb.connect(**DB_INFO) as cursor:
            sql = 'SELECT * FROM neutron_port_ip WHERE port_id=%s'
            sql_param = port_item.get('id', None)
            cursor.execute(sql, sql_param if sql_param else '0')
            desc = [it[0] for it in cursor.description]
            for item in cursor:
                port_ip_items.append(dict(zip(desc, item)))
    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), 500
    if len(port_ip_items) == 0:
        result = {
            "NeutronError": {
                "message": "ARP of network %s and macAddress %s not found"
                           % (network_item.get('id', None), req.mac_address),
                "type": "ArpNotFound",
                "detail": ""
            }
        }
        log.error(result)
        return Response(json.dumps(result)), 404

    result = []
    for port_ip_item in port_ip_items:
        r_item = models.ArpReply()
        fields = r_item.serialized_field_names()
        r_item.mac = str(req.mac_address)
        r_item.network_type = str(req.network_type)
        r_item.segmentation_id = int(req.segmentation_id)
        r_item.ip = port_ip_item.get('ip_address', None)

        r_item_dict = r_item.filtered_fields(fields)
        result.append(r_item_dict)

    if raw:
        return result, code
    return Response(json.dumps(result)), code


@arp_app.route(API_PREFIX + '/arp/byip', methods=['GET'])
@autodoc.doc(groups=['public', __name__])
def arp_byip_get_api():
    """
    Implementation Notes
        Returns MAC address for given IP address.

    Response Class (Status 200)
        ArpRecord {
            ip (string, optional): IP addresss. ,
            mac (string, optional): MAC address. ,
            networkType (string, optional): Network type. Valid values are
                                            'VLAN' and 'VXLAN'. ,
            segmentationId (integer, optional): VLAN id or VXLAN vni
        }

    Parameters
        {
            networkType (string): Network type. Valid values are
                                  'VLAN' and 'VXLAN'. ,
            segmentationId (string): VLAN id or VXLAN vni. ,
            ipAddress (string): IP address.
        }
    """
    try:
        req = models.ArpRequest(request.json)
        req.validate()
    except Exception as e:
        result = {
            "NeutronError": {
                "message": "Request check failed: %s" % e,
                "type": "BadRequest",
                "detail": ""
            }
        }
        log.error(result)
        return Response(json.dumps(result)), 500
    if req.ip_address is None:
        result = {
            "NeutronError": {
                "message": "Request check failed, ipAddress not given",
                "type": "BadRequest",
                "detail": ""
            }
        }
        log.error(result)
        return Response(json.dumps(result)), 500

    return get_arp_byip(req)


def get_arp_byip(req, raw=False):
    code = 200
    network_item = None
    try:
        with MySQLdb.connect(**DB_INFO) as cursor:
            sql = 'SELECT * FROM neutron_networks WHERE ' \
                + 'type=%s AND segmentation_id=%s'
            cursor.execute(sql, (req.network_type, req.segmentation_id))
            desc = [it[0] for it in cursor.description]
            item = cursor.fetchone()
            if item:
                network_item = dict(zip(desc, item))
    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), 500
    if not network_item:
        result = {
            "NeutronError": {
                "message": "%s network %s of ipAddress %s not found"
                           % (req.network_type,
                              req.segmentation_id,
                              req.ip_address),
                "type": "BadRequest",
                "detail": ""
            }
        }
        log.error(result)
        return Response(json.dumps(result)), 400

    port_ip_items = []
    try:
        with MySQLdb.connect(**DB_INFO) as cursor:
            sql = 'SELECT * FROM neutron_port_ip WHERE ip_address=%s'
            cursor.execute(sql, req.ip_address)
            desc = [it[0] for it in cursor.description]
            for item in cursor:
                port_ip_items.append(dict(zip(desc, item)))
    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), 500

    port_item = None
    try:
        with MySQLdb.connect(**DB_INFO) as cursor:
            for port_ip_item in port_ip_items:
                sql = 'SELECT * FROM neutron_ports WHERE ' \
                    + 'network_id=%s AND id=%s'
                sql_param_1 = network_item.get('id', None)
                sql_param_2 = port_ip_item.get('port_id', None)
                cursor.execute(sql, (sql_param_1 if sql_param_1 else '0',
                                     sql_param_2 if sql_param_2 else '0'))
                desc = [it[0] for it in cursor.description]
                item = cursor.fetchone()
                if item:
                    port_item = dict(zip(desc, item))
                    break
    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), 500
    if not port_item:
        result = {
            "NeutronError": {
                "message": "ARP of network %s and ipAddress %s not found"
                           % (network_item.get('id', None), req.ip_address),
                "type": "ArpNotFound",
                "detail": ""
            }
        }
        log.error(result)
        return Response(json.dumps(result)), 404

    r_item = models.ArpReply()
    fields = r_item.serialized_field_names()
    r_item.mac = port_item.get('mac_address', None)
    r_item.network_type = str(req.network_type)
    r_item.segmentation_id = int(req.segmentation_id)
    r_item.ip = str(req.ip_address)

    result = r_item.filtered_fields(fields)

    if raw:
        return result, code
    return Response(json.dumps(result)), code


@arp_app.route(API_PREFIX + '/arp', methods=['PUT'])
@autodoc.doc(groups=['public', __name__])
def arp_put_api():
    """
    Implementation Notes
        Adds/Update global static ARP records. Each logical L2 network
        (networkType, segmentationId pair) has an independent ARP table.

    Response Class (Status 200)
        ArpRecord {
            ip (string, optional): IP addresss. ,
            mac (string, optional): MAC address. ,
            networkType (string, optional): Network type. Valid values are
                                            'VLAN' and 'VXLAN'. ,
            segmentationId (integer, optional): VLAN id or VXLAN vni
        }

    Parameters
        [
            {
                networkType (string): Network type. Valid values are
                                      'VLAN' and 'VXLAN'. ,
                segmentationId (string): VLAN id or VXLAN vni. ,
                macAddress (string): MAC address. ,
                ipAddress (string): IP address.
            }
        ]
    """
    code = 200
    reqs = []
    if not isinstance(request.json, list):
        result = {
            "NeutronError": {
                "message": "Request check failed",
                "type": "BadRequest",
                "detail": ""
            }
        }
        log.error(result)
        return Response(json.dumps(result)), 500
    for json_data in request.json:
        try:
            req = models.ArpRequest(json_data)
            req.validate()
            reqs.append(req)
        except Exception as e:
            result = {
                "NeutronError": {
                    "message": "Request check failed: %s" % e,
                    "type": "BadRequest",
                    "detail": ""
                }
            }
            log.error(result)
            return Response(json.dumps(result)), 500
        if req.mac_address is None or req.ip_address is None:
            result = {
                "NeutronError": {
                    "message": "Request check failed, " +
                               "macAddress or ipAddress not given",
                    "type": "BadRequest",
                    "detail": ""
                }
            }
            log.error(result)
            return Response(json.dumps(result)), 500

    result = []
    for req in reqs:
        resp, code = get_arp_byip(req, True)
        if code != 200:
            return resp, code
        result.append(resp)

    return Response(json.dumps(result)), code


@arp_app.route(API_PREFIX + '/arp', methods=['DELETE'])
@autodoc.doc(groups=['public', __name__])
def arp_delete_api():
    """
    Implementation Notes
        Removes all records in ARP db.

    Response Class (Status 200)

    Parameters
        None
    """
    code = 200
    try:
        r = lcapi.delete(url=conf.livecloud_talker_url + '/v1/dvs/arps/',
                         timeout=30)
        if r.status_code != 200:
            return Response(json.dumps(NEUTRON_500)), r.status_code
    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), 500

    result = {'Reason': 'Reset completed successfully.'}

    return Response(json.dumps(result)), code


@arp_app.route(API_PREFIX + '/arp/bymac', methods=['DELETE'])
@autodoc.doc(groups=['public', __name__])
def arp_bymac_delete_api():
    """
    Implementation Notes
        Deletes ARP record for given MAC address.

    Response Class (Status 200)

    Parameters
        {
            networkType (string): Network type. Valid values are
                                  'VLAN' and 'VXLAN'. ,
            segmentationId (string): VLAN id or VXLAN vni. ,
            macAddress (string): MAC address.
        }
    """
    try:
        req = models.ArpRequest(request.json)
        req.validate()
    except Exception as e:
        result = {
            "NeutronError": {
                "message": "Request check failed: %s" % e,
                "type": "BadRequest",
                "detail": ""
            }
        }
        log.error(result)
        return Response(json.dumps(result)), 500
    if req.mac_address is None:
        result = {
            "NeutronError": {
                "message": "Request check failed, macAddress not given",
                "type": "BadRequest",
                "detail": ""
            }
        }
        log.error(result)
        return Response(json.dumps(result)), 500

    return delete_arp_bymac(req)


def delete_arp_bymac(req):
    code = 200
    try:
        r = lcapi.delete(url=conf.livecloud_talker_url +
                         '/v1/dvs/arps/%s/' % req.mac_address,
                         timeout=30)
        if r.status_code != 200:
            return Response(json.dumps(NEUTRON_500)), r.status_code

    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), 500

    result = {'Reason': 'Reset completed successfully.'}

    return Response(json.dumps(result)), code


@arp_app.route(API_PREFIX + '/arp/byip', methods=['DELETE'])
@autodoc.doc(groups=['public', __name__])
def arp_byip_delete_api():
    """
    Implementation Notes
        Deletes ARP record for given IP address.

    Response Class (Status 200)

    Parameters
        {
            networkType (string): Network type. Valid values are
                                  'VLAN' and 'VXLAN'. ,
            segmentationId (string): VLAN id or VXLAN vni. ,
            ipAddress (string): IP address.
        }
    """
    try:
        req = models.ArpRequest(request.json)
        req.validate()
    except Exception as e:
        result = {
            "NeutronError": {
                "message": "Request check failed: %s" % e,
                "type": "BadRequest",
                "detail": ""
            }
        }
        log.error(result)
        return Response(json.dumps(result)), 500
    if req.ip_address is None:
        result = {
            "NeutronError": {
                "message": "Request check failed, ipAddress not given",
                "type": "BadRequest",
                "detail": ""
            }
        }
        log.error(result)
        return Response(json.dumps(result)), 500

    resp, code = get_arp_byip(req, True)
    if code != 200:
        return resp, code
    resp['macAddress'] = resp['mac']
    del resp['mac']
    del resp['ip']
    req = models.ArpRequest(resp)

    return delete_arp_bymac(req)

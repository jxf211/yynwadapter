import logging
import simplejson as json
import string

from flask import Blueprint
from flask import request
import MySQLdb
from const import DB_INFO, NEUTRON_500, API_PREFIX
from documentation import autodoc
import models
from utils import validate_ip, err_return
from utils import Response
from dbutils import (portmap_db_get_all, portmap_db_delete,
                     port_ip_db_get_one, port_db_get_one)
from router_app import rt_conf_nat_one_to_one, rt_deconf_nat_one_to_one

log = logging.getLogger(__name__)
pat_app = Blueprint('pat_app', __name__)


def generate_pat_data(pats):
    json_data = []
    i = 1
    for pat in pats:
        json_data.append({
            'NAME': 'yy-dnat-%s-%d' % (
                string.replace(pat['public_ip'], '.', '_'),
                pat['public_port']),
            'RULE_ID': (2 << i) - 1,
            'STATE': 1,
            'ISP': 1,
            'PROTOCOL': 6,
            'MATCH': {
                "MIN_ADDRESS": pat['public_ip'],
                "MAX_ADDRESS": pat['public_ip'],
                "MIN_PORT": pat['public_port'],
                "MAX_PORT": pat['public_port']
            },
            'TARGET': {
                "MIN_ADDRESS": pat['ip'],
                "MAX_ADDRESS": pat['ip'],
                "MIN_PORT": pat['port'],
                "MAX_PORT": pat['port']
            }
        })
        json_data.append({
            'NAME': 'yy-dnat-%s-%d' % (
                string.replace(pat['public_ip'], '.', '_'),
                pat['public_port']),
            'RULE_ID': i << 1,
            'STATE': 1,
            'ISP': 1,
            'PROTOCOL': 17,
            'MATCH': {
                "MIN_ADDRESS": pat['public_ip'],
                "MAX_ADDRESS": pat['public_ip'],
                "MIN_PORT": pat['public_port'],
                "MAX_PORT": pat['public_port']
            },
            'TARGET': {
                "MIN_ADDRESS": pat['ip'],
                "MAX_ADDRESS": pat['ip'],
                "MIN_PORT": pat['port'],
                "MAX_PORT": pat['port']
            }
        })
        i += 1
    return {'DATA': json_data}


@pat_app.route(API_PREFIX + '/portmapping')
@autodoc.doc(groups=['public', __name__])
def portmapping_get_api():
    """
    Implementation Notes
        Gets all port mapping rules.

    Response Class (Status 200)
        Inline Model [
            PortMapping
        ]
        PortMapping {
            networkId (string, optional): Network to draw public IP from.
                Dedicated port mapping network could be used. ,
            subnetId (string, optional): Subnet to draw public IP from.
                Dedicated port mapping subnet could be used. ,
            publicIp (string, optional): Public IP address. ,
            publicPort (integer, optional): Public port assigned for
                this mapping. ,
            fixedIPInfo (inline_model_1, optional): Fixed IP:port info.
        }
        inline_model_1 {
            ip (string, optional): Fixed IP address. ,
            port (integer, optional): Fixed IP port.
        }
    """
    items = []
    try:
        with MySQLdb.connect(**DB_INFO) as cursor:
            cursor.execute('SELECT * FROM portmappings')
            desc = [it[0] for it in cursor.description]
            for item in cursor:
                items.append(dict(zip(desc, item)))
        ret = []
        for it in items:
            r = models.PortMapping()
            r.network_id = it.get('network_id', None)
            r.subnet_id = it.get('subnet_id', None)
            r.public_ip = it.get('public_ip', None)
            r.public_port = it.get('public_port', 0)
            r.fixed_ip_info = models.IPInfo()
            r.fixed_ip_info.ip = it.get('ip', None)
            r.fixed_ip_info.port = it.get('port', None)
            ret.append(r.to_primitive())
        return Response(json.dumps(ret)), 200
    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), 500


@pat_app.route(API_PREFIX + '/portmapping', methods=['POST'])
@autodoc.doc(groups=['public', __name__])
def portmapping_post_api():
    """
    Implementation Notes
        Creates new port mapping rule. publicIP and publicPort could be
        assigned automatically by the controller.

    Parameters
        Parameter       Description         Parameter Type  Data Type
        portmapping     A portmapping req   body            PortMapping

        PortMapping {
            networkId (string, optional): Network to draw public IP from.
                Dedicated port mapping network could be used. ,
            subnetId (string, optional): Subnet to draw public IP from.
                Dedicated port mapping subnet could be used. ,
            publicIp (string, optional): Public IP address. ,
            publicPort (integer, optional): Public port assigned for
                this mapping. ,
            fixedIPInfo (inline_model_1, optional): Fixed IP:port info.
        }
        inline_model_1 {
            ip (string, optional): Fixed IP address. ,
            port (integer, optional): Fixed IP port.
        }

    Response Messages
        HTTP Status Code    Reason  Response Model  Headers
        201                 Port mapping rule created.
    """
    try:
        req = models.PortMapping(request.json)
        req.validate()
        assert req.public_ip is not None and req.public_port is not None
    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), 500

    try:
        with MySQLdb.connect(**DB_INFO) as cursor:
            if req.public_ip is not None and req.public_port is not None:
                sql = 'SELECT * FROM portmappings '
                sql += 'WHERE public_ip=%s AND public_port=%s'
                cursor.execute(sql, (req.public_ip, req.public_port))
                if cursor.fetchone() is not None:
                    result = {"NeutronError": {
                        "message": "Address pair %s:%d conflicts" % (
                            req.public_ip, req.public_port),
                        "type": "AddressConflict",
                        "detail": ""
                    }}
                    return Response(json.dumps(result)), 400

            sql = 'SELECT * FROM neutron_subnets '
            sql += 'WHERE id=%s'
            cursor.execute(sql, req.subnet_id)
            item = cursor.fetchone()
            if item is None:
                result = {"NeutronError": {
                    "message": "Subnet %s could not be found" % req.subnet_id,
                    "type": "SubnetNotFound",
                    "detail": ""
                }}
                return Response(json.dumps(result)), 404
            desc = [it[0] for it in cursor.description]
            subnet = dict(zip(desc, item))

            sql = 'SELECT external FROM neutron_networks '
            sql += 'WHERE id=%s'
            cursor.execute(sql, subnet['network_id'])
            item = cursor.fetchone()
            if item is None:
                result = {"NeutronError": {
                    "message": ("Network %s could not be found" %
                                req.network_id),
                    "type": "NetworkNotFound",
                    "detail": ""
                }}
                return Response(json.dumps(result)), 500
            external = item[0]
            if external != 1:
                result = {"NeutronError": {
                    "message": "Network %s is not external" % req.network_id,
                    "type": "NetworkNotExternal",
                    "detail": ""
                }}
                return Response(json.dumps(result)), 400

            sql = 'SELECT t1.id FROM neutron_routers t1'
            sql += ' INNER JOIN neutron_ports t2 ON t1.id=t2.device_id'
            sql += ' INNER JOIN neutron_port_ip t3 ON t2.id=t3.port_id'
            sql += ' WHERE t3.ip_address=%s'
            cursor.execute(sql, req.public_ip)
            item = cursor.fetchone()
            if item is None:
                result = {"NeutronError": {
                    "message": "No router found for ip %s" % req.public_ip,
                    "type": "RouterNotFound",
                    "detail": ""
                }}
                return Response(json.dumps(result)), 400
            router_id = item[0]

            new_portmapping = {}
            new_portmapping['network_id'] = subnet['network_id']
            new_portmapping['subnet_id'] = subnet['id']
            new_portmapping['public_ip'] = req.public_ip
            new_portmapping['public_port'] = req.public_port
            new_portmapping['ip'] = req.fixed_ip_info.ip
            new_portmapping['port'] = req.fixed_ip_info.port

            if not rt_conf_nat_one_to_one(router_id, 6,
                                          new_portmapping['public_ip'],
                                          new_portmapping['ip'],
                                          new_portmapping['public_port'],
                                          new_portmapping['port']):
                return Response(json.dumps(NEUTRON_500)), 500

            s = ','.join(['%s' for i in range(len(new_portmapping))])
            sql = 'INSERT INTO portmappings ('
            sql += ','.join(new_portmapping.keys())
            sql += ') VALUES (' + s + ')'
            cursor.execute(sql, tuple(new_portmapping.values()))

            r = models.PortMapping()
            r.network_id = new_portmapping.get('network_id', None)
            r.subnet_id = new_portmapping.get('subnet_id', None)
            r.public_ip = new_portmapping.get('public_ip', None)
            r.public_port = new_portmapping.get('public_port', 0)
            r.fixed_ip_info = models.IPInfo()
            r.fixed_ip_info.ip = new_portmapping.get('ip', None)
            r.fixed_ip_info.port = new_portmapping.get('port', None)

        return Response(json.dumps(r.to_primitive())), 201

    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), 500


@pat_app.route(API_PREFIX + '/portmapping', methods=['DELETE'])
@autodoc.doc(groups=['public', __name__])
def portmapping_delete_api():
    """
    Implementation Notes
        Deletes a port mapping rule.
            If no parameters given, delete all rules.
            If only publicIP given, delete all rules on that IP.
            If both publicIP and publicPort given, delete that single rule.

    Parameters
        Parameter       Description         Parameter Type  Data Type
        publicIp        Public IP Address.  query           string
        publicPort      Public port.        query           integer

    Response Messages
    HTTP Status Code        Reason  Response Model  Headers
    200                     Port mapping rule(s) deleted.
    """
    public_ip = request.args.get('publicIp', type=str)
    public_port = request.args.get('publicPort', type=int)
    log.debug('publicIp=%s,publicPort=%s' % (public_ip, public_port))
    if public_ip is None and public_port is not None:
        return err_return("Port specified without IP", "IPNotSpecified",
                          "", 400)
    if public_ip and not validate_ip(public_ip):
        return err_return('IP(%s) invalid' % public_ip,
                          'ParameterInvalid', '', 400)
    if public_port is not None and public_port <= 0:
        return err_return('Port(%s) invalid' % public_port,
                          'ParameterInvalid', '', 400)

    if public_ip and public_port:
        db_portmaps = portmap_db_get_all(public_ip=public_ip,
                                         public_port=public_port)
    elif public_ip:
        db_portmaps = portmap_db_get_all(public_ip=public_ip)
    else:
        db_portmaps = portmap_db_get_all()
    if not db_portmaps:
        log.debug('db_portmaps is None')
        return Response(), 200
    for db_portmap in db_portmaps:
        portid = port_ip_db_get_one('port_id',
                                    ip_address=db_portmap['public_ip'])
        routerid = port_db_get_one('device_id', id=portid)
        if not rt_deconf_nat_one_to_one(routerid, 6,
                                        db_portmap['public_ip'],
                                        db_portmap['ip'],
                                        db_portmap['public_port'],
                                        db_portmap['port']):
            return Response(json.dumps(NEUTRON_500)), 500
        portmap_db_delete(public_ip=db_portmap['public_ip'],
                          public_port=db_portmap['public_port'])
    return Response(), 200

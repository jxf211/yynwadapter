from collections import defaultdict
import traceback
import logging
import simplejson as json
import uuid

from flask import Blueprint
from flask import request
import MySQLdb

from conf import conf
from const import DB_INFO, NEUTRON_400, NEUTRON_404, NEUTRON_500, API_PREFIX
from const import (HTTP_BAD_REQUEST, HTTP_INTERNAL_SERVER_ERROR,
                   HTTP_NOT_FOUND, HTTP_OK, HTTP_CREATED)
from const import VFW_TOR_LINK_V, VFW_TOR_LINK_T
from const import PORT_TYPE_ROUTER
from const import NAT_PROTOCOL_ANY, NAT_PORT_MIN_VALUE, NAT_PORT_MAX_VALUE
from const import (VGW_WAN_PORT_IFINDEX, VGW_LAN_PORT_IFINDEX,
                   VGW_WAN_QOS_MIN, VGW_WAN_QOS_MAX, VGW_LAN_QOS_MIN,
                   VGW_LAN_QOS_MAX)
from const import VL2_DEFAULT_NET_INDEX, ROUTER_VRF, ROUTER_VSYS
from documentation import autodoc
import lcapi
import models
from utils import process_request_args, ip2long, long2ip, err_return
from utils import Response, alloc_pools_to_ip_list
import copy
import time
from dbutils import (lc_ip_res_db_get_one, lc_ps_db_get_one,
                     network_db_get_one, subnet_db_get_one, router_db_get_one,
                     port_db_get_one, port_ip_db_delete, port_db_delete,
                     port_db_get_all, floatingip_db_delete,
                     port_ip_db_get_all, lc_vif_ip_db_get_one,
                     port_ip_db_get_one, router_db_delete, lc_vl2_db_get_one,
                     port_map_db_delete, lc_vl2_net_db_get_all,
                     floatingip_db_get_one, floatingip_db_get_all,
                     port_map_db_get_one, lc_vnet_db_get_one,
                     lc_vif_db_get_one)
from async import get_callback_result

livecloud_vgw_ps_lcuuid = None

LC_DB_INFO = copy.copy(DB_INFO)
LC_DB_INFO['db'] = 'livecloud'

log = logging.getLogger(__name__)
router_app = Blueprint('router_app', __name__)


@router_app.route(API_PREFIX + '/routers')
@router_app.route(API_PREFIX + '/routers/<id>')
@autodoc.doc(groups=['public', __name__])
def router_get_api(id=None):
    """
    Implementation Notes
        List routers.

    Response Class (Status 200)
        Router {
            routerId (string, optional): Router uuid.,
            routerName (string, optional): Router name,a user readable name.,
            externalGatewayInfo: {
                networkId (string, optional):
                    Network uuid. SNAT to this network is always enabled.,
                externalFixedIps: [
                    {
                        subnetId (string, optional): Subnet uuid.,
                        ip (string, optional): IP address.
                    },
                    .....
                ]
            }
        }

    Parameters
        routerId
    """
    code = HTTP_OK
    filters = {}
    if id is not None:
        filters['id'] = [id]
        _, fields = process_request_args(request.args)
    else:
        filters, fields = process_request_args(request.args)
    lcfilters = {}
    for k, v in filters.items():
        lcfilters[k.upper()] = v

    items = []
    try:
        with MySQLdb.connect(**DB_INFO) as cursor:
            if id is not None:
                sql = 'SELECT * FROM neutron_routers WHERE id=%s'
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
                sql = 'SELECT * FROM neutron_routers WHERE ' + conds
                cursor.execute(sql, tuple(params))
                desc = [it[0] for it in cursor.description]
                for item in cursor:
                    items.append(dict(zip(desc, item)))

            if items:
                sql = 'SELECT id, device_id, network_id FROM neutron_ports '
                sql += 'WHERE device_id IN ('
                sql += ','.join(['%s' for it in items]) + ')'
                sql += ' AND device_type=%s AND ifindex=%s'
                cursor.execute(sql, tuple([it['id'] for it in items] +
                                          [PORT_TYPE_ROUTER,
                                           VGW_WAN_PORT_IFINDEX]))
                ex_ports = defaultdict(list)
                for item in cursor:
                    ex_ports[item[1]] = ({'port_id': item[0],
                                          'network_id': item[2]})
                if ex_ports:
                    sql = ('SELECT ip_address,port_id,subnet_id '
                           'FROM neutron_port_ip ')
                    sql += 'WHERE port_id IN ('
                    sql += ','.join(['%s' for p in ex_ports.values()]) + ')'
                    cursor.execute(
                        sql, tuple([p['port_id'] for p in ex_ports.values()]))
                    ips = defaultdict(list)
                    for item in cursor:
                        ips[item[1]].append({
                            'subnet_id': item[2],
                            'ip_address': item[0]
                        })
    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), HTTP_INTERNAL_SERVER_ERROR

    items_grouped_by_router = []
    for item in items:
        if 'device_id' not in item or item['device_id'] == '':
            continue
        did = item['device_id']
        if did not in items_grouped_by_router:
            items_grouped_by_router.append(did)

    ri = None
    rs = []
    for item in items:
        r_item = models.Router()
        if not fields:
            fields = r_item.serialized_field_names()
        r_item.id = item.get('id', None)
        r_item.name = item.get('name', None)
        ex_gw = ex_ports.get(item.get('id', None), None)
        if ex_gw is not None:
            external_gateway_info = models.ExternalGatewayInfo()
            r_item.external_gateway_info = external_gateway_info
            external_gateway_info.network_id = ex_gw.get('network_id', '')
            fixed_ips = ips.get(ex_gw.get('port_id', None), [])
            for fixed_ip in fixed_ips:
                external_fixed_ip = models.ExternalFixedIps()
                external_fixed_ip.subnet_id = fixed_ip.get('subnet_id', None)
                external_fixed_ip.ip = fixed_ip.get('ip_address', None)
                external_gateway_info.external_fixed_ips.\
                    append(external_fixed_ip)

        r_item_dict = r_item.filtered_fields(fields)
        if id is not None:
            ri = r_item_dict
            break
        rs.append(r_item_dict)

    if id is not None:
        if ri is None:
            result = {
                "NeutronError": {
                    "message": "Router %s could not be found" % id,
                    "type": "RouterNotFound",
                    "detail": ""
                }
            }
            code = HTTP_NOT_FOUND
        else:
            result = ri
    else:
        result = rs

    return Response(json.dumps(result)), code


def get_router_vifs_conf(lc_vgw_id=0):
    vifs_conf = []
    r = lcapi.get(url=conf.livecloud_url + '/v1/vgateways/%s' % lc_vgw_id)
    if r.status_code != HTTP_OK:
        log.debug('get vgw failed:%s' % lc_vgw_id)
        return vifs_conf
    vgw = r.json().get('DATA')
    vifs = vgw.get('INTERFACES')
    for vif in vifs:
        vif_conf = {}
        vif_conf['STATE'] = vif['STATE']
        vif_conf['IF_INDEX'] = vif['IF_INDEX']
        if vif_conf['STATE'] != 1:
            vifs_conf.append(vif_conf)
            continue
        vif_conf['IF_TYPE'] = vif['IF_TYPE']
        if vif_conf['IF_TYPE'] == 'WAN':
            vif_conf['WAN'] = {}
            vif_conf['WAN']['QOS'] = vif['WAN']['QOS']
            ips = []
            for ip in vif['WAN']['IPS']:
                ips.append({"ip_resource_lcuuid": ip['IP_RESOURCE_LCUUID']})
            vif_conf['WAN']['IPS'] = ips
        else:
            vif_conf['LAN'] = {}
            vif_conf['LAN']['VL2_LCUUID'] = vif['LAN']['VL2_LCUUID']
            vif_conf['LAN']['IPS'] = vif['LAN']['IPS']
            vif_conf['LAN']['QOS'] = vif['LAN']['QOS']
        vifs_conf.append(vif_conf)
    return vifs_conf


def get_router_nat_conf(lc_vgw_uuid=None):
    log.debug('lc_vgw_uuid=%s' % lc_vgw_uuid)
    if not lc_vgw_uuid:
        return False, [], []
    url = '/v1/vgateways/%s/snats/' % lc_vgw_uuid
    r = lcapi.get(url=conf.livecloud_url + url)
    if r.status_code != HTTP_OK:
        log.debug('get vgw snat failed:%s' % lc_vgw_uuid)
        return False, [], []
    snats = r.json()['DATA']
    url = '/v1/vgateways/%s/dnats/' % lc_vgw_uuid
    r = lcapi.get(url=conf.livecloud_url + url)
    if r.status_code != HTTP_OK:
        log.debug('get vgw dnat failed:%s' % lc_vgw_uuid)
        return False, [], []
    dnats = r.json()['DATA']
    log.debug('snats=%s, dnats=%s' % (snats, dnats))
    return True, snats, dnats


def nat_equ(protocol1=0, protocol2=0,
            s_i_min1='', s_i_max1='', s_p_min1=0, s_p_max1=0,
            d_i_min1='', d_i_max1='', d_p_min1=0, d_p_max1=0,
            s_i_min2='', s_i_max2='', s_p_min2=0, s_p_max2=0,
            d_i_min2='', d_i_max2='', d_p_min2=0, d_p_max2=0):
    if protocol1 != protocol2:
        return False
    if s_i_min1 != s_i_min2:
        return False
    if s_i_max1 != s_i_max2:
        return False
    if s_p_min1 != s_p_min2:
        return False
    if s_p_max1 != s_p_max2:
        return False
    if d_i_min1 != d_i_min2:
        return False
    if d_i_max1 != d_i_max2:
        return False
    if d_p_min1 != d_p_min2:
        return False
    if d_p_max1 != d_p_max2:
        return False

    return True


def add_nat_to_router(do_snat=True, lc_vgw_uuid=None, protocol=0,
                      s_i_min='', s_i_max='', s_p_min=0, s_p_max=0,
                      d_i_min='', d_i_max='', d_p_min=0, d_p_max=0):
    # do_snat=True, add snat to router
    # do_snat=False, add dnat to router
    log.debug('do_snat=%s' % do_snat)
    flag, SNATS, DNATS = get_router_nat_conf(lc_vgw_uuid)
    if not flag:
        return False
    if do_snat:
        NATS = SNATS
        name = 'SNAT'
        obj = 'TARGET'
        url = conf.livecloud_url + '/v1/vgateways/%s/snats/' % lc_vgw_uuid
    else:
        NATS = DNATS
        name = 'DNAT'
        obj = 'MATCH'
        url = conf.livecloud_url + '/v1/vgateways/%s/dnats/' % lc_vgw_uuid
    for NAT in NATS:
        match = NAT['MATCH']
        target = NAT['TARGET']
        if nat_equ(protocol, NAT['PROTOCOL'],
                   s_i_min, s_i_max, s_p_min, s_p_max,
                   d_i_min, d_i_max, d_p_min, d_p_max,
                   match['MIN_ADDRESS'], match['MAX_ADDRESS'],
                   match['MIN_PORT'], match['MAX_PORT'],
                   target['MIN_ADDRESS'], target['MAX_ADDRESS'],
                   target['MIN_PORT'], target['MAX_PORT']):
            return True
    new_nat = {
        "STATE": 1,
        "ISP": 1,
        "PROTOCOL": protocol,
        "MATCH": {
            "MIN_ADDRESS": s_i_min,
            "MAX_ADDRESS": s_i_max,
            "MIN_PORT": s_p_min,
            "MAX_PORT": s_p_max
        },
        "TARGET": {
            "MIN_ADDRESS": d_i_min,
            "MAX_ADDRESS": d_i_max,
            "MIN_PORT": d_p_min,
            "MAX_PORT": d_p_max
        }
    }
    NATS.append(new_nat)

    log.debug('nats=%s' % NATS)
    i = 1
    for NAT in NATS:
        NAT['NAME'] = name + str(i)
        NAT['RULE_ID'] = i
        if do_snat:
            NAT[obj]['IF_TYPE'] = 'WAN'
            NAT[obj]['IF_INDEX'] = VGW_WAN_PORT_IFINDEX
        i = i + 1

    DATA = {"DATA": NATS}
    r = lcapi.put(url, data=json.dumps(DATA))
    if r.status_code != HTTP_OK:
        log.error('router(%s):NAT(%s)' % (lc_vgw_uuid,
                                          r.json()['DESCRIPTION']))
        return False
    return True


def remove_nat_from_router(do_snat=True, lc_vgw_uuid=None, protocol=0,
                           s_i_min='', s_i_max='', s_p_min=0, s_p_max=0,
                           d_i_min='', d_i_max='', d_p_min=0, d_p_max=0):
    # do_snat=True, remove snat from router
    # do_snat=False, remove dnat from router
    log.debug('do_snat=%s' % do_snat)
    flag, SNATS, DNATS = get_router_nat_conf(lc_vgw_uuid)
    if not flag:
        return False
    if do_snat:
        NATS = SNATS
        url = conf.livecloud_url + '/v1/vgateways/%s/snats/' % lc_vgw_uuid
    else:
        NATS = DNATS
        url = conf.livecloud_url + '/v1/vgateways/%s/dnats/' % lc_vgw_uuid

    for NAT in NATS:
        match = NAT['MATCH']
        target = NAT['TARGET']
        if nat_equ(protocol, NAT['PROTOCOL'],
                   s_i_min, s_i_max, s_p_min, s_p_max,
                   d_i_min, d_i_max, d_p_min, d_p_max,
                   match['MIN_ADDRESS'], match['MAX_ADDRESS'],
                   match['MIN_PORT'], match['MAX_PORT'],
                   target['MIN_ADDRESS'], target['MAX_ADDRESS'],
                   target['MIN_PORT'], target['MAX_PORT']):
            NATS.remove(NAT)
            break
    else:
        log.debug('nat not found')
        return True
    i = 1
    for NAT in NATS:
        NAT['RULE_ID'] = i
        i = i + 1

    DATA = {"DATA": NATS}
    r = lcapi.put(url, data=json.dumps(DATA))
    if r.status_code != HTTP_OK:
        log.error('router(%s):NAT(%s)' % (lc_vgw_uuid,
                                          r.json()['DESCRIPTION']))
        return False
    return True


def attach_router_wan_port(router_lcid=None, ips=[]):
    if not ips:
        return True
    ip_lcuuids = []
    sql = 'SELECT lcuuid FROM ip_resource_v2_2 '
    sql += 'WHERE ip IN ('
    sql += ','.join(['%s' for ip in ips]) + ')'
    try:
        with MySQLdb.connect(**LC_DB_INFO) as cursor:
            cursor.execute(
                sql, tuple([ip for ip in ips]))
            for item in cursor:
                ip_lcuuids.append({'ip_resource_lcuuid': item[0]})
    except Exception as e:
        return False

    vifs = get_router_vifs_conf(router_lcid)
    if not vifs:
        return False

    for i in range(len(vifs)-1, -1, -1):
        if vifs[i]['IF_INDEX'] == VGW_WAN_PORT_IFINDEX:
            del(vifs[i])
            wan = {
                'state': 1,
                'if_type': 'WAN',
                'if_index': VGW_WAN_PORT_IFINDEX,
                'wan': {
                    "ips": ip_lcuuids,
                    'qos': {
                        'min_bandwidth': VGW_WAN_QOS_MIN,
                        'max_bandwidth': VGW_WAN_QOS_MAX
                    }
                }
            }
            vifs.append(wan)
            break

    router_req = {"data": vifs}

    try:
        r = lcapi.patch(url=conf.livecloud_url + '/v1/vgateways/' +
                        str(router_lcid),
                        data=json.dumps(router_req))
        if r.status_code != HTTP_OK:
            log.error("Config external fix ip failed")
            return False
        flag, result = get_callback_result(r.json())
        if not flag:
            log.error(result)
            return False

    except Exception as e:
        log.error(e)
        return False

    return True


def router_add_ip_to_wan_port(router_id=None, ips=[],
                              ifindex=VGW_WAN_PORT_IFINDEX):
    log.debug('ips=%s' % ips)
    if not ips:
        return True
    port = port_db_get_one('*', device_type='neutron:router',
                           device_id=router_id, ifindex=ifindex)
    if not port:
        log.warn("No Wan Port Found")
        return False
    network_id = port['network_id']
    vl2_lcuuid = network_db_get_one('lcuuid', id=network_id)
    if not vl2_lcuuid:
        log.error('network_id=%s' % network_id)
        return False
    subnet_id = subnet_db_get_one('id', network_id=network_id)
    old_isp = lc_vl2_db_get_one('isp', lcuuid=vl2_lcuuid)

    iplcuuid_to_ip = {}
    ip_lcuuids = []
    for ip in ips:
        ipr = lc_ip_res_db_get_one('*', ip=ip)
        if not ipr:
            log.error('ip(%s) is error' % ip)
            return False
        if not old_isp:
            old_isp = ipr['isp']
        if ipr['isp'] != old_isp:
            log.error("old_isp(%s)new_isp(%s)" % (old_isp, ipr['isp']))
            return False
        if iplcuuid_to_ip.get(ipr['lcuuid'], None) is not None:
            ips.remove(ip)
            continue
        iplcuuid_to_ip[ipr['lcuuid']] = ip
        ip_lcuuids.append({'ip_resource_lcuuid': ipr['lcuuid']})

    router_lcid = router_db_get_one('exlcid', id=router_id)
    vifs = get_router_vifs_conf(router_lcid)

    for i in range(len(vifs)-1, -1, -1):
        if vifs[i]['IF_INDEX'] == VGW_WAN_PORT_IFINDEX:
            if vifs[i]['STATE'] == 1:
                old_ip_lcuuids = []
                for item in vifs[i]['WAN']['IPS']:
                    old_ip_lcuuids.append(item['ip_resource_lcuuid'])
                for ip_lcuuid in ip_lcuuids:
                    if ip_lcuuid['ip_resource_lcuuid'] in old_ip_lcuuids:
                        ip = iplcuuid_to_ip[ip_lcuuid['ip_resource_lcuuid']]
                        ip_lcuuids.remove(ip_lcuuid)
                        ips.remove(ip)
                vifs[i]['WAN']['IPS'] = vifs[i]['WAN']['IPS'] + ip_lcuuids
            else:
                del(vifs[i])
                wan = {
                    'state': 1,
                    'if_type': 'WAN',
                    'if_index': VGW_WAN_PORT_IFINDEX,
                    'wan': {
                        "ips": ip_lcuuids,
                        'qos': {
                            'min_bandwidth': VGW_WAN_QOS_MIN,
                            'max_bandwidth': VGW_WAN_QOS_MAX
                        }
                    }
                }
                vifs.append(wan)
            break

    router_req = {"data": vifs}

    try:
        r = lcapi.patch(url=conf.livecloud_url + '/v1/vgateways/' +
                        str(router_lcid),
                        data=json.dumps(router_req))
        if r.status_code != 200:
            log.error(r.json()['DESCRIPTION'])
            return False
        flag, result = get_callback_result(r.json())
        if not flag:
            log.error(result)
            return False

        log.debug('ips=%s' % ips)
        with MySQLdb.connect(**DB_INFO) as cursor:
            for ip in ips:
                sql = ("INSERT INTO neutron_port_ip(port_id, subnet_id, " +
                       "ip_address)VALUES('" + port['id'] + "','" +
                       subnet_id + "','" + ip + "')")
                cursor.execute(sql)
    except Exception as e:
        log.error(e)
        return False

    return True


def router_remove_ip_from_wan_port(router_id=None, ip=None,
                                   ifindex=VGW_WAN_PORT_IFINDEX):
    if not ip:
        return True
    port = port_db_get_one('*', device_type='neutron:router',
                           device_id=router_id, ifindex=ifindex)
    if not port:
        log.error("No Wan Port Found")
        return False
    ipr = lc_ip_res_db_get_one('*', ip=ip)
    if not ipr:
        log.error('ip(%s) is error' % ip)
        return False
    router_lcid = router_db_get_one('exlcid', id=router_id)
    vifs = get_router_vifs_conf(router_lcid)
    for i in range(len(vifs)-1, -1, -1):
        if vifs[i]['IF_INDEX'] == VGW_WAN_PORT_IFINDEX:
            if vifs[i]['STATE'] != 1:
                log.error('%s not attached in this router' % ip)
                return False
            else:
                wan_ips = copy.deepcopy(vifs[i]['WAN']['IPS'])
                del(vifs[i])
                break
    else:
        log.error('router has no wan port')
        return False
    for i in range(len(wan_ips)-1, -1, -1):
        if wan_ips[i]['ip_resource_lcuuid'] == ipr['lcuuid']:
            del(wan_ips[i])
            break
    else:
        log.warn('%s not in router(%s)' % (ip, router_id))
        return True

    if len(wan_ips) != 0:
        wan = {
            'state': 1,
            'if_type': 'WAN',
            'if_index': VGW_WAN_PORT_IFINDEX,
            'wan': {
                "ips": wan_ips,
                'qos': {
                    'min_bandwidth': VGW_WAN_QOS_MIN,
                    'max_bandwidth': VGW_WAN_QOS_MAX
                }
            }
        }
    else:
        wan = {
            'state': 2,
            'if_index': VGW_WAN_PORT_IFINDEX
        }

    vifs.append(wan)

    router_req = {"data": vifs}
    try:
        r = lcapi.patch(url=conf.livecloud_url + '/v1/vgateways/' +
                        str(router_lcid),
                        data=json.dumps(router_req))
        if r.status_code != HTTP_OK:
            log.error(r.json()['DESCRIPTION'])
            return False
        flag, result = get_callback_result(r.json())
        if not flag:
            log.error(result)
            return False

        port_ip_db_delete(port_id=port['id'], ip_address=ip)
    except Exception as e:
        log.error(e)
        return False

    return True


@router_app.route(API_PREFIX + '/routers', methods=['POST'])
@autodoc.doc(groups=['public', __name__])
def router_post_api():
    """
    Implementation Notes
        Create a new router.

    Response Class (Status 200)
        Router {
            routerId (string, optional): Router uuid.,
            routerName (string, optional): Router name,a user readable name.,
            externalGatewayInfo: {
                networkId (string, optional):
                    Network uuid. SNAT to this network is always enabled.,
                externalFixedIps: [
                    {
                        subnetId (string, optional): Subnet uuid.,
                        ip (string, optional): IP address.
                    },
                    .....
                ]
            }
        }

    Parameters
        Router
    """
    # check request
    try:
        req = models.Router(request.json)
        req.validate()
    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_400)), HTTP_BAD_REQUEST
    if req.id is None:
        req.id = str(uuid.uuid4())
    else:
        if router_db_get_one(id=req.id):
            return err_return('ID(%s) in use' % req.id, 'ParameterInvilad',
                              '', HTTP_BAD_REQUEST)
    if req.external_gateway_info is not None:
        try:
            networkid = req.external_gateway_info.network_id
            item = network_db_get_one('*', id=networkid)
            if item is None:
                err = ('Network %s not found' % networkid)
                log.error(err)
                return err_return(err, 'NetworkNotFound', '', HTTP_BAD_REQUEST)
            if not item['external']:
                err = ('%s is not external network' % networkid)
                log.error(err)
                return err_return(err, 'NetworkTypeError',
                                  '', HTTP_BAD_REQUEST)
            isp_lcuuid = item['lcuuid']
            isp = lc_vl2_db_get_one('isp', lcuuid=isp_lcuuid)
            db_subnet = subnet_db_get_one('*', network_id=networkid)
            if db_subnet is None:
                err = ('subnets not found in network(%s)' % networkid)
                log.error(err)
                return err_return(err, 'SubNetNotFound', '', HTTP_BAD_REQUEST)
            subnetid = db_subnet['id']
            alloc_pools = json.loads(db_subnet['allocation_pools'])
            alloc_ips = alloc_pools_to_ip_list(alloc_pools)
        except Exception as e:
            log.error(e)
            return Response(json.dumps(NEUTRON_500)), \
                HTTP_INTERNAL_SERVER_ERROR

        req_gw_info = req.external_gateway_info
        router_ips = []
        for fixed_ip in req_gw_info.external_fixed_ips:
            if fixed_ip.ip in router_ips:
                err = ('IP(%s) has be seen more than one time' % fixed_ip.ip)
                log.error(err)
                return err_return(err, 'IPValueError', '', HTTP_BAD_REQUEST)
            if subnetid != fixed_ip.subnet_id:
                err = ('subnetid(%s) expected but %s given' %
                       (subnetid, fixed_ip.subnet_id))
                log.error(err)
                return err_return(err, 'SubNetIdError', '', HTTP_BAD_REQUEST)
            if fixed_ip.ip not in alloc_ips:
                err = ('IP(%s) not in allocation_pools' % fixed_ip.ip)
                log.error(err)
                return err_return(err, 'IPValueError', '', HTTP_BAD_REQUEST)
            try:
                item = lc_ip_res_db_get_one('*', ip=fixed_ip.ip)
                if item is None:
                    err = 'ExternalFixedIp %s not found' % fixed_ip.ip
                    log.error(err)
                    return err_return(err, 'ExternalFixedIpNotFound',
                                      '', HTTP_BAD_REQUEST)
                if item['vifid']:
                    err = 'ExternalFixedIp %s in use' % fixed_ip.ip
                    log.error(err)
                    return err_return(err, "ExternalFixedIpInUse",
                                      '', HTTP_BAD_REQUEST)
                if item['isp'] != isp:
                    err = ('IP(%s,isp=%s) not match Network(%s,isp=%s)' %
                           fixed_ip.ip, item['isp'], networkid, isp)
                    log.error(err)
                    return err_return(err, "ISPNotMatch", '', HTTP_BAD_REQUEST)
                router_ips.append(fixed_ip.ip)
            except Exception as e:
                log.error(e)
                return Response(json.dumps(NEUTRON_500)), \
                    HTTP_INTERNAL_SERVER_ERROR
        if not req_gw_info.external_fixed_ips:
            for ip in alloc_ips:
                if lc_ip_res_db_get_one('vifid', ip=ip) == 0:
                    log.debug('isp ip=%s' % ip)
                    exfixip = models.ExternalFixedIps()
                    exfixip.subnet_id = subnetid
                    exfixip.ip = ip
                    req_gw_info.external_fixed_ips.append(exfixip)
                    router_ips.append(ip)
                    break
            else:
                log.error('No external ip found')
                return err_return('No external ip found', "ParameterInvalid",
                                  '', HTTP_BAD_REQUEST)

    # get vgw ps lcuuid
    global livecloud_vgw_ps_lcuuid
    if not livecloud_vgw_ps_lcuuid:
        ps_lcuuid = lc_ps_db_get_one(req='lcuuid', product_type=2)
        if not ps_lcuuid:
            log.error('vgw product_specification not found')
            return err_return("vgw product_specification not found",
                              "ExternalFixedPSNotFount",
                              'please use mtps add vgw product_specification',
                              HTTP_BAD_REQUEST)
        livecloud_vgw_ps_lcuuid = ps_lcuuid
    router_name = req.name + '_' + str(time.time())
    # create vgateway
    router_req = {}
    router_req['allocation_type'] = 'auto'
    router_req['userid'] = conf.livecloud_userid
    router_req['order_id'] = conf.livecloud_order_id
    router_req['name'] = router_name
    router_req['domain'] = conf.livecloud_domain
    router_req['product_specification_lcuuid'] = livecloud_vgw_ps_lcuuid
    router_req['gw_launch_server_type'] = ROUTER_VRF
    try:
        r = lcapi.post(url=conf.livecloud_url + '/v1/vgateways',
                       data=json.dumps(router_req))
        if r.status_code != 200:
            return Response(json.dumps(NEUTRON_500)), r.status_code
        resp = r.json()
        if resp['OPT_STATUS'] == 'SUCCESS' and 'DATA' in resp:
            router_lcuuid = resp['DATA'].get('LCUUID', '')
            router_lcid = resp['DATA'].get('ID', 0)
        else:
            log.error('Error (%s): %s' %
                      (resp['OPT_STATUS'], resp['DESCRIPTION']))
            return Response(json.dumps(NEUTRON_500)), \
                HTTP_INTERNAL_SERVER_ERROR

        router_req['name'] = 'ex_' + router_name
        router_req['gw_launch_server_type'] = ROUTER_VSYS
        r = lcapi.post(url=conf.livecloud_url + '/v1/vgateways',
                       data=json.dumps(router_req))
        if r.status_code != HTTP_OK:
            return Response(json.dumps(NEUTRON_500)), r.status_code
        resp = r.json()
        if resp['OPT_STATUS'] == 'SUCCESS' and 'DATA' in resp:
            exrouter_lcuuid = resp['DATA'].get('LCUUID', '')
            exrouter_lcid = resp['DATA'].get('ID', 0)
        else:
            log.error('Error (%s): %s' %
                      (resp['OPT_STATUS'], resp['DESCRIPTION']))
            r = lcapi.delete(
                conf.livecloud_url + '/v1/vgateways/' + str(router_lcid))
            return Response(json.dumps(NEUTRON_500)), \
                HTTP_INTERNAL_SERVER_ERROR

    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), HTTP_INTERNAL_SERVER_ERROR

    # config networkId
    if req.external_gateway_info is not None:
        ret = attach_router_wan_port(str(exrouter_lcid), router_ips)
        if not ret:
            try:
                r = lcapi.delete(
                    conf.livecloud_url + '/v1/vgateways/' + str(router_lcid))
                r = lcapi.delete(
                    conf.livecloud_url + '/v1/vgateways/' + str(exrouter_lcid))
            except Exception as e:
                log.error(e)
            return Response(json.dumps(NEUTRON_500)), \
                HTTP_INTERNAL_SERVER_ERROR

    # insert DB
    try:
        new_router = {}
        new_router['id'] = req.id
        new_router['name'] = req.name
        new_router['lcuuid'] = router_lcuuid
        new_router['epc_id'] = 0
        new_router['userid'] = conf.livecloud_userid
        new_router['lcid'] = router_lcid
        new_router['exlcuuid'] = exrouter_lcuuid
        new_router['exlcid'] = exrouter_lcid
        with MySQLdb.connect(**DB_INFO) as cursor:
            s = ','.join(['%s' for i in range(len(new_router))])
            sql = 'INSERT INTO neutron_routers ('
            sql += ','.join(new_router.keys())
            sql += ') VALUES (' + s + ')'
            cursor.execute(sql, tuple(new_router.values()))

        if req.external_gateway_info is not None:
            new_port = {}
            new_port['id'] = str(uuid.uuid4())
            new_port['name'] = req.name + '-1'
            new_port['device_type'] = 'neutron:router'
            new_port['device_id'] = req.id
            new_port['ifindex'] = VGW_WAN_PORT_IFINDEX
            new_port['network_id'] = req.external_gateway_info.network_id
            with MySQLdb.connect(**DB_INFO) as cursor:
                s = ','.join(['%s' for i in range(len(new_port))])
                sql = 'INSERT INTO neutron_ports ('
                sql += ','.join(new_port.keys())
                sql += ') VALUES (' + s + ')'
                cursor.execute(sql, tuple(new_port.values()))

            for fixed_ip in req.external_gateway_info.external_fixed_ips:
                new_port_ip = {}
                new_port_ip['port_id'] = new_port['id']
                new_port_ip['subnet_id'] = fixed_ip.subnet_id
                new_port_ip['ip_address'] = fixed_ip.ip
                with MySQLdb.connect(**DB_INFO) as cursor:
                    s = ','.join(['%s' for i in range(len(new_port_ip))])
                    sql = 'INSERT INTO neutron_port_ip ('
                    sql += ','.join(new_port_ip.keys())
                    sql += ') VALUES (' + s + ')'
                    cursor.execute(sql, tuple(new_port_ip.values()))
    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), HTTP_INTERNAL_SERVER_ERROR

    result = req.to_primitive()

    return Response(json.dumps(result)), HTTP_OK


def router_link_vfw_tor(routerid=None, vl2uuid=None):
    log.info('routerid=%s, vl2uuid=%s' % (routerid, vl2uuid))
    if not routerid or not vl2uuid:
        return False
    router = router_db_get_one('*', id=routerid)
    if not router:
        return False
    lcuuid = router['lcuuid']
    exlcuuid = router['exlcuuid']

    vl2id = lc_vl2_db_get_one('id', lcuuid=vl2uuid)
    nets = lc_vl2_net_db_get_all('prefix, netmask', vl2id=vl2id)
    rts = []
    i = 1
    for net in nets:
        rt = {"NAME": 'vfw_to_tor' + str(i),
              "RULE_ID": i,
              "STATE": 1,
              "ISP": 1,
              "DST_NETWORK": {"ADDRESS": net['prefix'],
                              "NETMASK": net['netmask']},
              "NEXT_HOP": VFW_TOR_LINK_T}
        i = i + 1
        rts.append(rt)
    exrouter_req = {"DATA": rts}
    url = "/v1/vgateways/%s/routes/" % exlcuuid
    try:
        log.debug('put router to exrouter')
        r = lcapi.put(url=conf.livecloud_url + url,
                      data=json.dumps(exrouter_req))
        if r.status_code != HTTP_OK:
            log.error(r.json()['DESCRIPTION'])
            return False
    except Exception as e:
        log.error(e)
        return False

    rts = []
    rt = {"NAME": 'tor_to_vfw',
          "RULE_ID": 1,
          "STATE": 1,
          "ISP": 1,
          "DST_NETWORK": {"ADDRESS": '0.0.0.0',
                          "NETMASK": '0.0.0.0'},
          "NEXT_HOP": VFW_TOR_LINK_V}
    rts.append(rt)
    router_req = {"DATA": rts}
    url = "/v1/vgateways/%s/routes/" % lcuuid
    try:
        log.debug('put router to router')
        r = lcapi.put(url=conf.livecloud_url + url,
                      data=json.dumps(router_req))
        if r.status_code != HTTP_OK:
            log.error(r.json()['DESCRIPTION'])
            return False
    except Exception as e:
        log.error(e)
        return False

    return True


def move_router_to_epc(routerid=None, epc=0):
    log.info('router=%s, epc=%s' % (routerid, epc))
    if not routerid or not epc:
        return False
    db_router = router_db_get_one(id=routerid)
    router_lcid = db_router['lcid']
    router_exlcid = db_router['exlcid']
    old_epcid = db_router['epc_id']
    if old_epcid != 0:
        if old_epcid == epc:
            return True
        else:
            log.warn('router(%s) already in epc(%s)' % (routerid, old_epcid))
            return False
    try:
        exvifs = get_router_vifs_conf(router_exlcid)
        vifs = get_router_vifs_conf(router_lcid)
        router_epc_req = {}
        router_epc_req['epc_id'] = epc
        r = lcapi.patch(url=conf.livecloud_url + '/v1/vgateways/' +
                        str(router_lcid),
                        data=json.dumps(router_epc_req))
        flag, result = get_callback_result(r.json())
        if not flag:
            log.error(result)
            return False
        r = lcapi.patch(url=conf.livecloud_url + '/v1/vgateways/' +
                        str(router_exlcid),
                        data=json.dumps(router_epc_req))
        flag, result = get_callback_result(r.json())
        if not flag:
            log.error(result)
            return False
        r = lcapi.patch(url=conf.livecloud_url + '/v1/vgateways/' +
                        str(router_exlcid),
                        data=json.dumps({"data": exvifs}))
        flag, result = get_callback_result(r.json())
        if not flag:
            log.error(result)
            return False
        r = lcapi.patch(url=conf.livecloud_url + '/v1/vgateways/' +
                        str(router_lcid),
                        data=json.dumps({"data": vifs}))
        flag, result = get_callback_result(r.json())
        if not flag:
            log.error(result)
            return False
        with MySQLdb.connect(**DB_INFO) as cursor:
            sql = ("UPDATE neutron_routers SET epc_id=%s "
                   "WHERE id='%s'" % (epc, routerid))
            log.debug('sql=%s' % sql)
            cursor.execute(sql)
        return True
    except Exception as e:
        log.error(e)
        return False


@router_app.route(API_PREFIX + '/routers/<id>/addRouterInterface',
                  methods=['PUT'])
@autodoc.doc(groups=['public', __name__])
def router_add_interface_api(id):
    """
    Implementation Notes
        Adds an internal interface to a router.

    Parameters
        routerSubnetInfo {
            subnetId (string, required): Subnet uuid.,
            portId (string, optional): Port uuid.
        }

    Response Messages
        HTTP Status Code    Reason          Response Model      Headers
        200                 Interface added.
    """
    try:
        req = models.RouterInterface(request.json)
        req.validate()
        if req.subnet_id is None:
            return err_return("subnetId is required", "BadRequest",
                              "", HTTP_BAD_REQUEST)
    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_400)), HTTP_BAD_REQUEST
    if not req.port_id:
        req.port_id = str(uuid.uuid4())
    else:
        item = port_db_get_one('id', id=req.port_id)
        if item:
            return err_return("PortId in use", "BadRequest",
                              "", HTTP_BAD_REQUEST)
    ports = port_db_get_all('*', device_type=PORT_TYPE_ROUTER,
                            device_id=id, ifindex=VGW_LAN_PORT_IFINDEX)
    if ports:
        old_networkid = ports[0]['network_id']
    else:
        old_networkid = None
    for port in ports:
        portip_sbids = port_ip_db_get_all(req='subnet_id',
                                          port_id=port['id'])
        for portip_sbid in portip_sbids:
            if req.subnet_id == portip_sbid['subnet_id']:
                return err_return('Subnet(IP) already exist',
                                  "BadRequest", "", HTTP_BAD_REQUEST)

    db_router = router_db_get_one(id=id)
    if db_router is None:
        return err_return("Router %s could not be found" % id,
                          "RouterNotFound", "", HTTP_BAD_REQUEST)
    db_subnet = subnet_db_get_one(id=req.subnet_id)
    if db_subnet is None:
        return err_return("Subnet %s not found" % req.subnet_id,
                          "SubnetNotFound", "", HTTP_NOT_FOUND)
    db_network = network_db_get_one(id=db_subnet['network_id'])
    if db_network is None:
        return err_return(("Network %s not found" %
                           db_subnet['network_id']),
                          "NetworkNotFound", "", HTTP_NOT_FOUND)
    if old_networkid and old_networkid != db_network['id']:
        return err_return(("Network %s expected but %s received" %
                           (old_networkid, db_subnet['network_id'])),
                          "SubnetIdError", "", HTTP_BAD_REQUEST)
    if db_network['external']:
        return err_return("Internal Network expected",
                          "SubnetIdError", "", HTTP_BAD_REQUEST)

    router_lcid = db_router['lcid']
    router_lcuuid = db_router['lcuuid']
    router_exlcid = db_router['exlcid']
    router_exlcuuid = db_router['exlcuuid']
    old_epcid = db_router['epc_id']

    if not old_epcid:
        epc_id = network_db_get_one('epc_id', id=db_network['id'])
        if not move_router_to_epc(id, epc_id):
            log.error('move router(%s) to epc(%s) fail' % (id, epc_id))
            return Response(json.dumps(NEUTRON_500)), \
                HTTP_INTERNAL_SERVER_ERROR

    vifs = get_router_vifs_conf(router_lcid)
    for i in range(len(vifs)-1, -1, -1):
        if vifs[i]['IF_INDEX'] == VGW_LAN_PORT_IFINDEX:
            if vifs[i]['STATE'] != 1:
                router_ips = []
            else:
                router_ips = vifs[i]['LAN']['IPS']
                for j in range(len(router_ips)-1, -1, -1):
                    if router_ips[j]['VL2_NET_INDEX'] == db_subnet['net_idx']:
                        del(router_ips[j])
                        continue
                    if router_ips[j]['VL2_NET_INDEX'] == VL2_DEFAULT_NET_INDEX:
                        del(router_ips[j])
            del(vifs[i])
            break
    else:
        log.error('can not find lan port(lcuuid=%s)' % router_lcuuid)
        return Response(json.dumps(NEUTRON_500)), HTTP_INTERNAL_SERVER_ERROR
    vl2id = lc_vl2_db_get_one('id', lcuuid=db_network['lcuuid'])
    vifid = lc_vif_ip_db_get_one('vifid', ip=db_subnet['gateway_ip'],
                                 net_index=db_subnet['net_idx'], vl2id=vl2id)
    if vifid:
        log.debug('vifid=%s' % vifid)
        deviceid = lc_vnet_db_get_one('id', lcuuid=router_lcuuid)
        if vifid != lc_vif_db_get_one('id', ifindex=VGW_LAN_PORT_IFINDEX,
                                      deviceid=deviceid, devicetype=5):
            err = ("subnet(%s)'s gateway(%s) "
                   "in use" % (db_subnet['id'], db_subnet['gateway_ip']))
            log.error(err)
            return err_return(err, 'ParameterIvalid', '', HTTP_BAD_REQUEST)

    router_ips.append({
        "vl2_net_index": db_subnet['net_idx'],
        "address": db_subnet['gateway_ip']
    })
    router_ips.append({
        "vl2_net_index": VL2_DEFAULT_NET_INDEX,
        "address": VFW_TOR_LINK_T
    })
    lan = {
        'state': 1,
        'if_type': 'LAN',
        'if_index': VGW_LAN_PORT_IFINDEX,
        'lan': {
            "vl2_lcuuid": db_network['lcuuid'],
            "ips": router_ips,
            'qos': {
                'min_bandwidth': VGW_LAN_QOS_MIN,
                'max_bandwidth': VGW_LAN_QOS_MAX
            }
        }
    }
    vifs.append(lan)
    router_req = {"data": vifs}

    exvifs = get_router_vifs_conf(router_exlcid)
    for i in range(len(exvifs)-1, -1, -1):
        if exvifs[i]['IF_INDEX'] == VGW_LAN_PORT_IFINDEX:
            ex_lan_state = exvifs[i]['STATE']
            if exvifs[i]['STATE'] != 1:
                del(exvifs[i])
            break
    else:
        log.error('can not find lan port(lcuuid=%s)' % router_exlcuuid)
        return Response(json.dumps(NEUTRON_500)), HTTP_INTERNAL_SERVER_ERROR
    if ex_lan_state != 1:
        router_ips = []
        router_ips.append({
            "vl2_net_index": VL2_DEFAULT_NET_INDEX,
            "address": VFW_TOR_LINK_V
        })
        lan = {
            'state': 1,
            'if_type': 'LAN',
            'if_index': VGW_LAN_PORT_IFINDEX,
            'lan': {
                "vl2_lcuuid": db_network['lcuuid'],
                "ips": router_ips,
                'qos': {
                    'min_bandwidth': VGW_LAN_QOS_MIN,
                    'max_bandwidth': VGW_LAN_QOS_MAX
                }
            }
        }
        exvifs.append(lan)
        exrouter_req = {"data": exvifs}
    try:
        r = lcapi.patch(url=conf.livecloud_url + '/v1/vgateways/' +
                        str(router_lcid),
                        data=json.dumps(router_req))
        if r.status_code != HTTP_OK:
            err = r.json()['DESCRIPTION']
            log.error(err)
            return err_return(err, 'Fail', '', HTTP_BAD_REQUEST)
        flag, result = get_callback_result(r.json())
        if not flag:
            log.error(result)
            return err_return(result, 'Fail', '', HTTP_BAD_REQUEST)
        if ex_lan_state != 1:
            r = lcapi.patch(url=conf.livecloud_url + '/v1/vgateways/' +
                            str(router_exlcid),
                            data=json.dumps(exrouter_req))
            if r.status_code != HTTP_OK:
                err = r.json()['DESCRIPTION']
                log.error(err)
                return err_return(err, 'Fail', '', HTTP_BAD_REQUEST)
            flag, result = get_callback_result(r.json())
            if not flag:
                log.error(result)
                return err_return(result, 'Fail', '', HTTP_BAD_REQUEST)

    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), HTTP_INTERNAL_SERVER_ERROR

    if not router_link_vfw_tor(id, db_network['lcuuid']):
        return Response(json.dumps(NEUTRON_500)), HTTP_INTERNAL_SERVER_ERROR

    try:
        with MySQLdb.connect(**DB_INFO) as cursor:
            new_port = {}
            new_port['id'] = req.port_id
            new_port['name'] = db_router['name'] + '-' + str(10)
            new_port['device_type'] = 'neutron:router'
            new_port['device_id'] = db_router['id']
            new_port['ifindex'] = VGW_LAN_PORT_IFINDEX
            new_port['network_id'] = db_subnet['network_id']
            s = ','.join(['%s' for i in range(len(new_port))])
            sql = 'INSERT INTO neutron_ports ('
            sql += ','.join(new_port.keys())
            sql += ') VALUES (' + s + ')'
            cursor.execute(sql, tuple(new_port.values()))

            new_port_ip = {}
            new_port_ip['port_id'] = new_port['id']
            new_port_ip['subnet_id'] = db_subnet['id']
            new_port_ip['ip_address'] = db_subnet['gateway_ip']
            s = ','.join(['%s' for i in range(len(new_port_ip))])
            sql = 'INSERT INTO neutron_port_ip ('
            sql += ','.join(new_port_ip.keys())
            sql += ') VALUES (' + s + ')'
            cursor.execute(sql, tuple(new_port_ip.values()))
            sql = 'UPDATE neutron_routers SET userid=%s'
            sql += ' WHERE id=%s'
            cursor.execute(sql, (db_network['userid'], db_router['id']))

    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), HTTP_INTERNAL_SERVER_ERROR

    return Response(), 200


@router_app.route(API_PREFIX + '/routers/<id>/removeRouterInterface',
                  methods=['PUT'])
@autodoc.doc(groups=['public', __name__])
def router_remove_interface_api(id):
    """
    Implementation Notes
        Removes an internal interface from a router.

    Parameters
        routerSubnetInfo {
            subnetId (string, optional): Subnet uuid.,
            portId (string, required): Port uuid.
        }

    Response Messages
        HTTP Status Code    Reason          Response Model      Headers
        200                 Interface removed.
    """
    try:
        req = models.RouterInterface(request.json)
        req.validate()
        if req.port_id is None and req.subnet_id is None:
            return err_return("PortId/SbunetId is required",
                              "BadRequest", '', HTTP_BAD_REQUEST)
    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_400)), HTTP_BAD_REQUEST
    return router_remove_interface(id, req)


def router_remove_interface(id, req):
    router_ips = []
    try:
        db_router = router_db_get_one('*', id=id)
        if not db_router:
            return err_return("Router %s could not be found" % id,
                              "RouterNotFound", "", HTTP_NOT_FOUND)
        if req.port_id:
            db_port = port_db_get_one('*', id=req.port_id,
                                      device_type=PORT_TYPE_ROUTER,
                                      device_id=id,
                                      ifindex=VGW_LAN_PORT_IFINDEX)
            if not db_port:
                return err_return("Port %s not found on router" % req.port_id,
                                  "PortNotFound", "", HTTP_NOT_FOUND)
        else:
            port_ids = port_db_get_all('id',
                                       device_type=PORT_TYPE_ROUTER,
                                       device_id=id,
                                       ifindex=VGW_LAN_PORT_IFINDEX)
            for port_id in port_ids:
                portip_sbids = port_ip_db_get_all(req='subnet_id',
                                                  port_id=port_id['id'])
                for portip_sbid in portip_sbids:
                    if req.subnet_id == portip_sbid['subnet_id']:
                        req.port_id = port_id['id']
                        break
                else:
                    continue
                break
            else:
                return err_return("no port on Subnet %s" % req.subnet_id,
                                  "SubnetIdError", "", HTTP_BAD_REQUEST)
        db_port_ip = port_ip_db_get_one('*', port_id=req.port_id)
        if not db_port_ip:
            return err_return("Port %s ip not found" % req.port_id,
                              "PortIpNotFound", "", HTTP_NOT_FOUND)
        network_id = subnet_db_get_one('network_id',
                                       id=db_port_ip['subnet_id'])
        network_lcuuid = network_db_get_one('lcuuid', id=network_id)
    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), HTTP_INTERNAL_SERVER_ERROR

    router_id = db_router['lcid']
    vifs = get_router_vifs_conf(router_id)
    for i in range(len(vifs)-1, -1, -1):
        if vifs[i]['IF_INDEX'] == VGW_LAN_PORT_IFINDEX:
            router_ips = vifs[i]['LAN']['IPS']
            del(vifs[i])
            break
    for ip in router_ips:
        if ip['ADDRESS'] == db_port_ip['ip_address']:
            router_ips.remove(ip)

    if len(router_ips) >= 1:
        lan = {
            'state': 1,
            'if_type': 'LAN',
            'if_index': VGW_LAN_PORT_IFINDEX,
            'lan': {
                "vl2_lcuuid": network_lcuuid,
                "ips": router_ips,
                'qos': {
                    'min_bandwidth': VGW_LAN_QOS_MIN,
                    'max_bandwidth': VGW_LAN_QOS_MAX
                }
            }
        }
    else:
        lan = {
            'state': 2,
            'if_index': VGW_LAN_PORT_IFINDEX
        }

    vifs.append(lan)
    router_req = {"data": vifs}
    try:
        r = lcapi.patch(url=conf.livecloud_url + '/v1/vgateways/' +
                        str(router_id), data=json.dumps(router_req))
        if r.status_code != 200:
            log.error(r.json()['DESCRIPTION'])
            return Response(json.dumps(NEUTRON_500)), \
                HTTP_INTERNAL_SERVER_ERROR
        flag, result = get_callback_result(r.json())
        if not flag:
            log.error(result)
            return Response(json.dumps(NEUTRON_500)), \
                HTTP_INTERNAL_SERVER_ERROR

    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), HTTP_INTERNAL_SERVER_ERROR

    port_db_delete(id=req.port_id)
    port_ip_db_delete(port_id=req.port_id)

    return Response(), HTTP_OK


@router_app.route(API_PREFIX + '/router/metering')
@router_app.route(API_PREFIX + '/routers/<routerId>/metering')
@autodoc.doc(groups=['public', __name__])
def router_metering_api(routerId=None):
    """
    Implementation Notes
        Returns north-south packet count and total used bandwidth. Traffic \
within network (east-west) is not counted.

    Parameters

    Response Class (Status 200)
      when `routerId' specified:
        {
            "totalPacketCount": 0,
            "totalBandwidth": 0
        }
      otherwise:
        [
            {
                "routerId": "338cb7d2-4656-4cbb-a06c-0475548a9de1",
                "totalPacketCount": 0,
                "totalBandwidth": 0
            }
        ]
    """
    try:
        if routerId:
            lcuuid = None
            with MySQLdb.connect(**DB_INFO) as cursor:
                if routerId is not None:
                    sql = 'SELECT exlcuuid FROM neutron_routers WHERE id=%s'
                    cursor.execute(sql, routerId)
                    item = cursor.fetchone()
                    if item is not None:
                        lcuuid = item[0]
            if lcuuid:
                r = lcapi.get_stats(
                    url=conf.livecloud_stats_url +
                    '/v1/stats/histories/vgateway-rx-traffic/%s/?limit=1'
                    % lcuuid)
                rx = {}
                rx_data = r.json().get('DATA')
                if rx_data:
                    rx_his = rx_data[0].get('HISTORIES')
                    if rx_his:
                        rx = rx_his[0]

                r = lcapi.get_stats(
                    url=conf.livecloud_stats_url +
                    '/v1/stats/histories/vgateway-tx-traffic/%s/?limit=1'
                    % lcuuid)
                tx = {}
                tx_data = r.json().get('DATA')
                if tx_data:
                    tx_his = tx_data[0].get('HISTORIES')
                    if tx_his:
                        tx = tx_his[0]

                result = {
                    "totalPacketCount": (
                        rx.get('RX_PPS', 0) + tx.get('TX_PPS', 0)) * 60,
                    "totalBandwidth": max(
                        rx.get('RX_BPS', 0), tx.get('TX_BPS', 0))
                }
                return Response(json.dumps(result)), HTTP_OK
            else:
                return Response(json.dumps(NEUTRON_404)), HTTP_NOT_FOUND

        else:  # Only for YY POC
            lcuuid_to_id = {}
            with MySQLdb.connect(**DB_INFO) as cursor:
                sql = 'SELECT id,exlcuuid FROM neutron_routers'
                cursor.execute(sql)
                for item in cursor:
                    lcuuid_to_id[item[1]] = item[0]

            r = lcapi.get_stats(
                url=conf.livecloud_stats_url +
                '/v1/stats/distributions/vgateway-wan-traffic/?top=10000')
            r_data = r.json().get('DATA')
            result = []
            for d in r_data:
                if d.get('LCUUID') in lcuuid_to_id:
                    result.append({
                        'routerId': lcuuid_to_id.get(d.get('LCUUID')),
                        'totalPacketCount': (
                            d.get('RX_PPS', 0) + d.get('TX_PPS', 0)) * 60,
                        'totalBandwidth': max(
                            d.get('RX_BPS', {}).get('USAGE', 0),
                            d.get('TX_BPS', {}).get('USAGE', 0)),
                    })
                    del lcuuid_to_id[d.get('LCUUID')]
            for lcuuid, routerId in lcuuid_to_id.iteritems():
                result.append({
                    'routerId': routerId,
                    'totalPacketCount': 0,
                    'totalBandwidth': 0,
                })
            return Response(json.dumps(result)), HTTP_OK
    except Exception as e:
        log.error(e)
        log.error(traceback.format_exc())
        return Response(json.dumps(NEUTRON_500)), HTTP_INTERNAL_SERVER_ERROR


@router_app.route(API_PREFIX + '/routers/subnetRouteGroup')
@autodoc.doc(groups=['public', __name__])
def router_srg_get_api():
    """
    Implementation Notes
        Gets subnet route groups defined on this router.

    Response Class (Status 200)
        Inline Model [
            SubnetRouteGroup
        ]
        SubnetRouteGroup {
            subnetRouteGroupId (string, optional): subnetRouteGroup uuid. ,
            routerId (string, optional): The router this subnet router group
                is created on. ,
            subnets (Array[string], optional): An array of subnets.
        }
    """
    try:
        ret = []
        with MySQLdb.connect(**DB_INFO) as cursor:
            sql = 'SELECT id,router_id FROM subnet_route_groups'
            cursor.execute(sql)
            desc = [it[0] for it in cursor.description]
            items = []
            for row in cursor:
                items.append(dict(zip(desc, row)))

            for it in items:
                r = models.SubnetRouteGroup()
                r.id = it['id']
                r.router_id = it['router_id']

                sql = 'SELECT subnet_id FROM srg_subnets '
                sql += 'WHERE srg_id=%s'
                cursor.execute(sql, it['id'])
                r.subnets = []
                for row in cursor:
                    r.subnets.append(row[0])

                ret.append(r.to_primitive())

        return Response(json.dumps(ret)), HTTP_OK

    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), HTTP_INTERNAL_SERVER_ERROR


@router_app.route(API_PREFIX + '/routers/subnetRouteGroup', methods=['POST'])
@autodoc.doc(groups=['public', __name__])
def router_srg_post_api():
    """
    Implementation Notes
        Creates a subnet route group. Subnets in the same group are reachable
        to each other via the router.

    Response Class (Status 201)
        {
          "subnetRouteGroupId": "string",
          "routerId": "string",
          "subnets": [
            "string"
          ]
        }

    Parameters
    Parameter   Value   Description Parameter               Type
    Data Type
    subnetRouteGroup    The subnet route group to create.   body
    SubnetRouteGroup
    """
    try:
        req = models.SubnetRouteGroup(request.json)
        req.validate()
        if req.router_id is None:
            result = {
                "NeutronError": {
                    "message": "Router id not specified",
                    "type": "RouterNotFound",
                    "detail": ""
                }
            }
            return Response(json.dumps(result)), HTTP_BAD_REQUEST
    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_400)), HTTP_BAD_REQUEST

    try:
        with MySQLdb.connect(**DB_INFO) as cursor:
            sql = 'SELECT * FROM neutron_routers WHERE id=%s'
            cursor.execute(sql, req.router_id)
            if cursor.fetchone() is None:
                result = {
                    "NeutronError": {
                        "message":
                            "Router %s could not be found" % req.router_id,
                        "type": "RouterNotFound",
                        "detail": ""
                    }
                }
                return Response(json.dumps(result)), HTTP_BAD_REQUEST

            if req.subnets:
                sql = 'SELECT * FROM neutron_subnets '
                sql += 'WHERE id IN ('
                sql += ','.join(['%s' for it in req.subnets])
                sql += ')'
                cursor.execute(sql, tuple(req.subnets))
                desc = [it[0] for it in cursor.description]
                subnets = [dict(zip(desc, row)) for row in cursor]
                subnet_ids = [it['id'] for it in subnets]
                for it in req.subnets:
                    if it not in subnet_ids:
                        result = {
                            "NeutronError": {
                                "message": "Subnet %s could not be found" % it,
                                "type": "SubnetNotFound",
                                "detail": ""
                            }
                        }
                        return Response(json.dumps(result)), HTTP_BAD_REQUEST

                sql = 'SELECT * FROM neutron_networks WHERE id=%s'
                cursor.execute(sql, subnets[0]['network_id'])
                desc = [it[0] for it in cursor.description]
                item = cursor.fetchone()
                if item is None:
                    result = {
                        "NeutronError": {
                            "message": ("Network %s could not be found" %
                                        subnets[0]['network_id']),
                            "type": "NetworkNotFound",
                            "detail": ""
                        }
                    }
                    return Response(json.dumps(result)), HTTP_BAD_REQUEST
                network = dict(zip(desc, item))
                if network['external'] == 1:
                    result = {
                        "NeutronError": {
                            "message": ("Network %s is external" %
                                        network['id']),
                            "type": "NetworkNotInternal",
                            "detail": ""
                        }
                    }
                    return Response(json.dumps(result)), HTTP_BAD_REQUEST

                sql = 'SELECT srg_id,subnet_id FROM srg_subnets '
                sql += 'WHERE srg_id IN ('
                sql += ','.join(['%s' for it in req.subnets])
                sql += ')'
                cursor.execute(sql, tuple(req.subnets))
                if cursor.rowcount > 0:
                    log.error('Subnet found in other route groups')
                    for row in cursor:
                        log.error('Subnet %s in route group %s' %
                                  (row[1], row[0]))
                    result = {
                        "NeutronError": {
                            "message": "Subnet found in other route groups",
                            "type": "SubnetConflict",
                            "detail": ""
                        }
                    }
                    return Response(json.dumps(result)), HTTP_BAD_REQUEST

                sql = 'SELECT t2.subnet_id FROM neutron_ports t1'
                sql += ' INNER JOIN neutron_port_ip t2 ON t1.id=t2.port_id'
                sql += ' WHERE t1.device_id=%s AND t2.subnet_id IN ('
                sql += ','.join(['%s' for it in req.subnets])
                sql += ') GROUP BY t2.subnet_id'
                cursor.execute(sql, tuple([req.router_id] + req.subnets))
                if cursor.rowcount != len(req.subnets):
                    log.error('Router not attached to some subnets')
                    att_subnets = [row[0] for row in cursor]
                    for it in req.subnets:
                        if it not in att_subnets:
                            log.error('Subnet %s not attached to router %s' %
                                      (it, req.router_id))
                    result = {
                        "NeutronError": {
                            "message": "Subnet not attached to some subnets",
                            "type": "SubnetNotAttached",
                            "detail": ""
                        }
                    }
                    return Response(json.dumps(result)), HTTP_BAD_REQUEST

        srg_id = str(uuid.uuid4())

        router_req = {}
        router_req['allocation_type'] = 'auto'
        router_req['userid'] = conf.livecloud_userid
        router_req['order_id'] = conf.livecloud_order_id
        router_req['name'] = 'tor-vgw-' + srg_id
        router_req['domain'] = conf.livecloud_domain
        router_req['product_specification_lcuuid'] = livecloud_vgw_ps_lcuuid
        router_req['gw_launch_server'] = '255.255.255.255'
        r = lcapi.post(url=conf.livecloud_url + '/v1/vgateways',
                       data=json.dumps(router_req))

        resp = r.json()
        if resp['OPT_STATUS'] == 'SUCCESS' and 'DATA' in resp:
            vgw_id = resp['DATA'].get('ID', 0)
        else:
            vgw_id = resp.get('DATA').get('ID', 0)
            if vgw_id == 0:
                log.error('Rollback VGW failed')
            else:
                lcapi.delete(url=conf.livecloud_url + '/v1/vgateways/%s' %
                             vgw_id)
            log.error('Error (%s): %s' %
                      (r['OPT_STATUS']. r['DESCRIPTION']))
            return Response(json.dumps(NEUTRON_500)), \
                HTTP_INTERNAL_SERVER_ERROR

        if req.subnets:
            ips = []
            for it in subnets:
                prefix, _ = it['cidr'].split('/')
                ip = long2ip(ip2long(prefix) + 2)
                ips.append({
                    'vl2_net_index': it['net_idx'],
                    'address': ip
                })
            router_req = {
                'data': [
                    {
                        'if_index': VGW_LAN_PORT_IFINDEX,
                        'state': 1,
                        'if_type': 'LAN',
                        'lan': {
                            "vl2_lcuuid": network['lcuuid'],
                            "ips": ips,
                            'qos': {
                                'min_bandwidth': VGW_LAN_QOS_MIN,
                                'max_bandwidth': VGW_LAN_QOS_MAX
                            }
                        }
                    }
                ]
            }
            r = lcapi.patch(url=conf.livecloud_url + '/v1/vgateways/' +
                            str(vgw_id),
                            data=json.dumps(router_req))
            if r.status_code != HTTP_OK:
                log.error('vgateways patch API returned with status code %d' %
                          r.status_code)
                lcapi.delete(url=conf.livecloud_url + '/v1/vgateways/%s' %
                             vgw_id)
                return Response(json.dumps(NEUTRON_500)), r.status_code

        with MySQLdb.connect(**DB_INFO) as cursor:
            new_srg = {
                'id': srg_id,
                'router_id': req.router_id,
                'vgw_id': vgw_id
            }
            s = ','.join(['%s' for i in range(len(new_srg))])
            sql = 'INSERT INTO subnet_route_groups ('
            sql += ','.join(new_srg.keys())
            sql += ') VALUES (' + s + ')'
            cursor.execute(sql, tuple(new_srg.values()))
            for it in req.subnets:
                new_srg_subnet = {
                    'srg_id': new_srg['id'],
                    'subnet_id': it
                }
                sql = 'INSERT INTO srg_subnets (srg_id,subnet_id)'
                sql += ' VALUES (%s,%s)'
                cursor.execute(sql, tuple(new_srg_subnet.values()))

        r = models.SubnetRouteGroup()
        r.id = new_srg['id']
        r.router_id = req.router_id
        r.subnets = req.subnets

        return Response(json.dumps(r.to_primitive())), HTTP_OK

    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), HTTP_INTERNAL_SERVER_ERROR


@router_app.route(API_PREFIX + '/routers/subnetRouteGroup', methods=['PUT'])
@autodoc.doc(groups=['public', __name__])
def router_srg_put_api():
    """
    Implementation Notes
        Updates a subnet route group.

    Response Class (Status 201)
        {
          "subnetRouteGroupId": "string",
          "routerId": "string",
          "subnets": [
            "string"
          ]
        }

    Parameters
    Parameter   Value   Description Parameter               Type
    Data Type
    subnetRouteGroup    The subnet route group to create.   body
    SubnetRouteGroup
    """
    try:
        req = models.SubnetRouteGroup(request.json)
        req.validate()
        if req.id is None:
            result = {
                "NeutronError": {
                    "message": "Subnet Route Group id not specified",
                    "type": "SubnetRouteGroupNotFound",
                    "detail": ""
                }
            }
            return Response(json.dumps(result)), HTTP_NOT_FOUND
    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_400)), HTTP_BAD_REQUEST

    try:
        with MySQLdb.connect(**DB_INFO) as cursor:
            sql = 'SELECT * FROM subnet_route_groups WHERE id=%s'
            cursor.execute(sql, req.id)
            row = cursor.fetchone()
            if row is None:
                result = {
                    "NeutronError": {
                        "message": "Subnet Route Group %s not found" % req.id,
                        "type": "SubnetRouteGroupNotFound",
                        "detail": ""
                    }
                }
                return Response(json.dumps(result)), HTTP_NOT_FOUND
            desc = [it[0] for it in cursor.description]
            srg = dict(zip(desc, row))

            sql = 'SELECT * FROM neutron_routers WHERE id=%s'
            cursor.execute(sql, srg['router_id'])
            if cursor.fetchone() is None:
                result = {
                    "NeutronError": {
                        "message":
                            "Router %s could not be found" % srg['router_id'],
                        "type": "RouterNotFound",
                        "detail": ""
                    }
                }
                return Response(json.dumps(result)), HTTP_BAD_REQUEST

            if req.subnets:
                sql = 'SELECT * FROM neutron_subnets '
                sql += 'WHERE id IN ('
                sql += ','.join(['%s' for it in req.subnets])
                sql += ')'
                cursor.execute(sql, tuple(req.subnets))
                desc = [it[0] for it in cursor.description]
                subnets = [dict(zip(desc, rowx)) for rowx in cursor]
                subnet_ids = [it['id'] for it in subnets]
                for it in req.subnets:
                    if it not in subnet_ids:
                        result = {
                            "NeutronError": {
                                "message": "Subnet %s could not be found" % it,
                                "type": "SubnetNotFound",
                                "detail": ""
                            }
                        }
                        return Response(json.dumps(result)), HTTP_BAD_REQUEST

                sql = 'SELECT * FROM neutron_networks WHERE id=%s'
                cursor.execute(sql, subnets[0]['network_id'])
                desc = [it[0] for it in cursor.description]
                item = cursor.fetchone()
                if item is None:
                    result = {
                        "NeutronError": {
                            "message": ("Network %s could not be found" %
                                        subnets[0]['network_id']),
                            "type": "NetworkNotFound",
                            "detail": ""
                        }
                    }
                    return Response(json.dumps(result)), HTTP_BAD_REQUEST
                network = dict(zip(desc, item))
                if network['external'] == 1:
                    result = {
                        "NeutronError": {
                            "message": ("Network %s is external" %
                                        network['id']),
                            "type": "NetworkNotInternal",
                            "detail": ""
                        }
                    }
                    return Response(json.dumps(result)), HTTP_BAD_REQUEST

                sql = 'SELECT srg_id,subnet_id FROM srg_subnets '
                sql += 'WHERE srg_id IN ('
                sql += ','.join(['%s' for it in req.subnets])
                sql += ')'
                cursor.execute(sql, tuple(req.subnets))
                if cursor.rowcount > 0:
                    log.error('Subnet found in other route groups')
                    for row in cursor:
                        log.error('Subnet %s in route group %s' %
                                  (row[1], row[0]))
                    result = {
                        "NeutronError": {
                            "message": "Subnet found in other route groups",
                            "type": "SubnetConflict",
                            "detail": ""
                        }
                    }
                    return Response(json.dumps(result)), HTTP_BAD_REQUEST

                sql = 'SELECT t2.subnet_id FROM neutron_ports t1'
                sql += ' INNER JOIN neutron_port_ip t2 ON t1.id=t2.port_id'
                sql += ' WHERE t1.device_id=%s AND t2.subnet_id IN ('
                sql += ','.join(['%s' for it in req.subnets])
                sql += ') GROUP BY t2.subnet_id'
                cursor.execute(sql, tuple([srg['router_id']] + req.subnets))
                if cursor.rowcount != len(req.subnets):
                    log.error('Router not attached to some subnets')
                    att_subnets = [row[0] for row in cursor]
                    for it in req.subnets:
                        if it not in att_subnets:
                            log.error('Subnet %s not attached to router %s' %
                                      (it, srg['router_id']))
                    result = {
                        "NeutronError": {
                            "message": "Subnet not attached to some subnets",
                            "type": "SubnetNotAttached",
                            "detail": ""
                        }
                    }
                    return Response(json.dumps(result)), HTTP_BAD_REQUEST

        if req.subnets:
            ips = []
            for it in subnets:
                prefix, _ = it['cidr'].split('/')
                ip = long2ip(ip2long(prefix) + 2)
                ips.append({
                    'vl2_net_index': it['net_idx'],
                    'address': ip
                })
            router_req = {
                'data': [
                    {
                        'if_index': VGW_LAN_PORT_IFINDEX,
                        'state': 1,
                        'if_type': 'LAN',
                        'lan': {
                            "vl2_lcuuid": network['lcuuid'],
                            "ips": ips,
                            'qos': {
                                'min_bandwidth': VGW_LAN_QOS_MIN,
                                'max_bandwidth': VGW_LAN_QOS_MAX
                            }
                        }
                    }
                ]
            }
        else:
            router_req = {
                'data': [
                    {
                        'if_index': VGW_LAN_PORT_IFINDEX,
                        'state': 2,
                    }
                ]
            }
        r = lcapi.patch(url=conf.livecloud_url + '/v1/vgateways/' +
                        str(srg['vgw_id']),
                        data=json.dumps(router_req))
        if r.status_code != HTTP_OK:
            log.error('vgateways patch API returned with status code %d' %
                      r.status_code)
            url = conf.livecloud_url + '/v1/vgateways/%d' % srg['vgw_id']
            lcapi.delete(url=url)
            return Response(json.dumps(NEUTRON_500)), r.status_code

        with MySQLdb.connect(**DB_INFO) as cursor:
            sql = 'DELETE FROM srg_subnets WHERE srg_id=%s'
            cursor.execute(sql, srg['id'])
            for it in req.subnets:
                new_srg_subnet = {
                    'srg_id': srg['id'],
                    'subnet_id': it
                }
                sql = 'INSERT INTO srg_subnets (srg_id,subnet_id)'
                sql += ' VALUES (%s,%s)'
                cursor.execute(sql, tuple(new_srg_subnet.values()))

        r = models.SubnetRouteGroup()
        r.id = srg['id']
        r.router_id = srg['router_id']
        r.subnets = req.subnets

        return Response(json.dumps(r.to_primitive())), HTTP_OK

    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), HTTP_INTERNAL_SERVER_ERROR


@router_app.route(API_PREFIX + '/routers/<routerId>', methods=['DELETE'])
@autodoc.doc(groups=['public', __name__])
def router_delete_api(routerId=None):
    item = router_db_get_one('*', id=routerId)
    if not item:
        return err_return('router(%s) not found' % routerId,
                          'RouterNotFound', '', HTTP_BAD_REQUEST)
    lcid = item['lcid']
    exlcid = item['exlcid']

    try:
        r = lcapi.delete(
            conf.livecloud_url + '/v1/vgateways/' + str(lcid))
        if r.status_code != HTTP_OK and r.status_code != HTTP_NOT_FOUND:
            log.error('delete vgw(%s) failed' % lcid)
            return err_return('Delete router(%s) failed' % routerId,
                              'DeleteRouterFailed', '', HTTP_BAD_REQUEST)
        if r.status_code == HTTP_OK:
            flag, result = get_callback_result(r.json())
            if not flag:
                log.error(result)
                return Response(json.dumps(NEUTRON_500)), \
                    HTTP_INTERNAL_SERVER_ERROR
        r = lcapi.delete(
            conf.livecloud_url + '/v1/vgateways/' + str(exlcid))
        if r.status_code != HTTP_OK and r.status_code != HTTP_NOT_FOUND:
            log.error('delete vgw(%s) failed' % exlcid)
            return err_return('Delete router(%s) failed' % routerId,
                              'DeleteRouterFailed', '', HTTP_BAD_REQUEST)
        if r.status_code == HTTP_OK:
            flag, result = get_callback_result(r.json())
            if not flag:
                log.error(result)
                return Response(json.dumps(NEUTRON_500)), \
                    HTTP_INTERNAL_SERVER_ERROR
    except Exception as e:
        log.error(e)
        return err_return('Delete router(%s) failed' % routerId,
                          'DeleteRouterFailed', '', HTTP_BAD_REQUEST)

    # get wan port
    port_id = port_db_get_one('id', device_type=PORT_TYPE_ROUTER,
                              device_id=routerId, ifindex=VGW_WAN_PORT_IFINDEX)
    if port_id:
        # get wan ips
        ips = port_ip_db_get_all('ip_address', port_id=port_id)
        for ip in ips:
            # delete portmapping
            port_map_db_delete(public_ip=ip['ip_address'])
        # delete wan ip
        port_ip_db_delete(port_id=port_id)
    # get lan port
    port_ids = port_db_get_all('id',
                               device_type=PORT_TYPE_ROUTER,
                               device_id=routerId,
                               ifindex=VGW_LAN_PORT_IFINDEX)
    for port_id in port_ids:
        # delete lan ip
        port_ip_db_delete(port_id=port_id['id'])
    # delete port
    port_db_delete(device_type=PORT_TYPE_ROUTER, device_id=routerId)
    # delete floating ip
    floatingip_db_delete(routerid=routerId)
    # delete router
    router_db_delete(id=routerId)

    return Response(), HTTP_OK


def get_port_by_ip(subnetid=None, ip=None):
    log.info('subnetid=%s, ip=%s' % (subnetid, ip))
    if not ip or not subnetid:
        return None
    portid = port_ip_db_get_one('port_id', subnet_id=subnetid, ip_address=ip)
    log.debug('portid=%s' % portid)
    return portid


def get_router_by_wan_ip(subnetid=None, ip=None):
    portid = get_port_by_ip(subnetid, ip)
    if not portid:
        return None
    routerid = port_db_get_one('device_id', id=portid,
                               device_type=PORT_TYPE_ROUTER,
                               ifindex=VGW_WAN_PORT_IFINDEX)
    log.debug('routerid=%s' % routerid)
    return routerid


def get_router_by_lan_ip(subnetid=None, ip=None):
    portid = get_port_by_ip(subnetid, ip)
    if not portid:
        return None
    routerid = port_db_get_one('device_id', id=portid,
                               device_type=PORT_TYPE_ROUTER,
                               ifindex=VGW_LAN_PORT_IFINDEX)
    log.debug('routerid=%s' % routerid)
    return routerid


@router_app.route(API_PREFIX + '/floatingips', methods=['GET'])
@router_app.route(API_PREFIX + '/floatingips/<floatingipid>', methods=['GET'])
@autodoc.doc(groups=['public', __name__])
def floatingips_get_api(floatingipid=None):
    """
    Implementation Notes
      Lists floating IPs.
    Response Class (Status 200)
      FloatingIP {
        floatingIpId (string, optional):
          Floating IP uuid.
        fixedIPAddress (string, optional):
          The fixed IP address that is associated with the floating IP address.
        floatingIpAddress (string, optional):
          The floating IP address.
        floatingNetworkId (string, optional):
          The UUID of the network associated with the floating IP.
        portId (string, optional):
          The UUID of the port.
        routerId (string, optional):
          The UUID of the router.
      }

    Parameters
      floatingipId (string, optional): The floating IP uuid to act on.
    """

    return floatingips_get(floatingipid=floatingipid)


def floatingips_get(floatingipid=None):
    try:
        if floatingipid:
            fip = floatingip_db_get_one(req='*', id=floatingipid)
            if not fip:
                return err_return('floatingipid not found', 'ResourceNotFound',
                                  '', HTTP_BAD_REQUEST)
            r_fip = models.FloatingIP()
            r_fip.floatingipid = fip['id']
            r_fip.fixedipaddress = fip['fixedipaddress']
            r_fip.floatingipaddress = fip['floatingipaddress']
            r_fip.floatingnetworkid = fip['floatingnetworkid']
            r_fip.portid = fip['portid']
            r_fip.routerid = fip['routerid']
            return Response(json.dumps(r_fip.to_primitive())), HTTP_OK

        fips = floatingip_db_get_all('*')
        resp = []
        for fip in fips:
            r_fip = models.FloatingIP()
            r_fip.floatingipid = fip['id']
            r_fip.fixedipaddress = fip['fixedipaddress']
            r_fip.floatingipaddress = fip['floatingipaddress']
            r_fip.floatingnetworkid = fip['floatingnetworkid']
            r_fip.portid = fip['portid']
            r_fip.routerid = fip['routerid']
            resp.append(r_fip.to_primitive())
        return Response(json.dumps(resp)), HTTP_OK
    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), HTTP_INTERNAL_SERVER_ERROR


@router_app.route(API_PREFIX + '/floatingips', methods=['POST'])
@autodoc.doc(groups=['public', __name__])
def floatingip_post_api():
    """
    Implementation Notes
      Creates a floating IP, and, if you specify port information,
      associates the floating IP with an internal port.
    Response Class (Status 200)
      FloatingIP {
        floatingIpId (string, optional):
          Floating IP uuid.
        fixedIPAddress (string, optional):
          The fixed IP address that is associated with the floating IP address.
        floatingIpAddress (string, optional):
          The floating IP address. ,
        floatingNetworkId (string, required):
          The UUID of the network associated with the floating IP.
        portId (string, optional): The UUID of the port. ,
        routerId (string, required): The UUID of the router.
      }

    Parameters
      FloatingIP (body, required): The floating IP information.
    """
    try:
        fipc = models.FloatingIPCreate(request.json)
        fipc.validate()
    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_400)), HTTP_BAD_REQUEST
    try:
        fip = models.FloatingIP()
        fip.floatingipid = str(uuid.uuid4())
        fip.floatingnetworkid = fipc.floatingnetworkid
        fip.floatingipaddress = fipc.floatingipaddress
        fip.portid = fipc.portid
        fip.fixedipaddress = fipc.fixedipaddress

        exnetwork = network_db_get_one(id=fip.floatingnetworkid)
        if not exnetwork:
            return err_return("networkId error", "ParameterInvilad",
                              "", HTTP_BAD_REQUEST)
        if not exnetwork['external']:
            return err_return("need external network", "ParameterInvilad",
                              "", HTTP_BAD_REQUEST)
        exsubnet = subnet_db_get_one(network_id=exnetwork['id'])
        if not exsubnet:
            return err_return("create subnet first", "ParameterInvilad",
                              "", HTTP_BAD_REQUEST)
        if fip.portid:
            if get_floatingip_by_lan_port_id(fip.portid):
                return err_return("PortId(%s) in use" % fip.portid,
                                  "ParameterInvilad", "", HTTP_BAD_REQUEST)
            port_netid = port_db_get_one('network_id', id=fip.portid)
            log.debug('port networkid=%s' % port_netid)
            if not port_netid:
                err = 'port(%s) not associate with any network' % fip.portid
                log.error(err)
                return err_return(err, "ParameterInvilad",
                                  "", HTTP_BAD_REQUEST)
            db_port_ips = port_ip_db_get_all('ip_address', port_id=fip.portid)
            if not db_port_ips:
                err = 'no ip on port(%s)' % fip.portid
                log.error(err)
                return err_return(err, "ParameterInvilad",
                                  "config vm ip first", HTTP_BAD_REQUEST)
            port_ips = []
            for db_port_ip in db_port_ips:
                port_ips.append(db_port_ip['ip_address'])
            if not fip.fixedipaddress:
                fip.fixedipaddress = port_ips[0]
            else:
                if fip.fixedipaddress not in port_ips:
                    err = "ip(%s) not on port(%s)" % (fip.fixedipaddress,
                                                      fip.portid)
                    log.error(err)
                    return err_return(err, "ParameterInvilad",
                                      "", HTTP_BAD_REQUEST)

        if fip.floatingipaddress:
            log.debug('floatingip=%s' % fip.floatingipaddress)
            item = floatingip_db_get_one(
                'id', floatingipaddress=fip.floatingipaddress)
            if item:
                err = ("%s be used in floatingip(%s)" % (fip.floatingipaddress,
                                                         item))
                log.error(err)
                return err_return(err, "ParameterInvilad",
                                  "", HTTP_BAD_REQUEST)
            if port_map_db_get_one(public_ip=fip.floatingipaddress):
                err = "%s be used in portmapping" % fip.floatingipaddress
                log.error(err)
                return err_return(err, "ParameterInvilad",
                                  "", HTTP_BAD_REQUEST)

            alloc_pools = json.loads(exsubnet['allocation_pools'])
            ips = alloc_pools_to_ip_list(alloc_pools)
            if fip.floatingipaddress not in ips:
                err = '%s not in allocation_pools' % fip.floatingipaddress
                return err_return(err, "ParameterInvilad",
                                  "", HTTP_BAD_REQUEST)

            fip.routerid = get_router_by_wan_ip(exsubnet['id'],
                                                fip.floatingipaddress)
            if not fip.routerid:
                err = 'router with ip(%s) not found' % fip.floatingipaddress
                log.error(err)
                return err_return(
                    err, "ParameterInvilad", "", HTTP_BAD_REQUEST)
            if fip.portid:
                rt_lanp_netid = port_db_get_one('network_id',
                                                device_type=PORT_TYPE_ROUTER,
                                                device_id=fip.routerid,
                                                ifindex=VGW_LAN_PORT_IFINDEX)
                log.debug('rt_lanp_netid=%s' % rt_lanp_netid)
                if rt_lanp_netid and rt_lanp_netid != port_netid:
                    err = ('router already attached on '
                           'network-%s' % rt_lanp_netid)
                    log.error(err)
                    return err_return(
                        "router and port not on the same network",
                        "ParameterInvilad", "", HTTP_BAD_REQUEST)
                if not rt_lanp_netid:
                    epcid = network_db_get_one('epc_id', id=port_netid)
                    if not move_router_to_epc(fip.routerid, epcid):
                        log.error('move router(%s) to epc fail' % fip.routerid)
                        return Response(json.dumps(NEUTRON_500)), \
                            HTTP_INTERNAL_SERVER_ERROR
        else:
            if not fip.portid:
                alloc_pools = json.loads(exsubnet['allocation_pools'])
                ips = alloc_pools_to_ip_list(alloc_pools)
                for ip in ips:
                    rtid = get_router_by_wan_ip(exsubnet['id'], ip)
                    if not rtid:
                        continue
                    if not router_db_get_one('epc_id', id=rtid):
                        fip.floatingipaddress = ip
                        fip.routerid = rtid
                        break
                else:
                    return err_return("no router to use", "ResourceNotFound",
                                      "", HTTP_BAD_REQUEST)
            else:
                pt_sn_id = port_ip_db_get_one('subnet_id', port_id=fip.portid)
                pt_sn = subnet_db_get_one(id=pt_sn_id)
                routerid = get_router_by_lan_ip(pt_sn['id'],
                                                pt_sn['gateway_ip'])
                log.debug('routerid=%s' % routerid)
                if routerid:
                    alloc_pools = json.loads(exsubnet['allocation_pools'])
                    ips = alloc_pools_to_ip_list(alloc_pools)
                    for ip in ips:
                        vifid = lc_ip_res_db_get_one('vifid', ip=ip)
                        if not vifid:
                            fip.floatingipaddress = ip
                            break
                    else:
                        return err_return(
                            "No external IP to use", "ResourceNotFound",
                            '', HTTP_BAD_REQUEST)
                    fip.routerid = routerid
                    ret = router_add_ip_to_wan_port(fip.routerid,
                                                    [fip.floatingipaddress])
                    if not ret:
                        err = "Add IP(%s) to router(%s) fail" % (
                            fip.floatingipaddress, fip.routerid)
                        log.error(err)
                        return err_return(err, "Fail", "", HTTP_BAD_REQUEST)
                else:
                    alloc_pools = json.loads(exsubnet['allocation_pools'])
                    ips = alloc_pools_to_ip_list(alloc_pools)
                    for ip in ips:
                        rtid = get_router_by_wan_ip(exsubnet['id'], ip)
                        if not rtid:
                            continue
                        if not router_db_get_one('epc_id', id=rtid):
                            fip.floatingipaddress = ip
                            fip.routerid = rtid
                            break
                    else:
                        return err_return("no router to use",
                                          "ResourceNotFound",
                                          "", HTTP_BAD_REQUEST)
                    epcid = network_db_get_one('epc_id', id=port_netid)
                    if not move_router_to_epc(fip.routerid, epcid):
                        log.error('move router(%s) to epc fail' % fip.routerid)
                        return Response(json.dumps(NEUTRON_500)), \
                            HTTP_INTERNAL_SERVER_ERROR

        if fip.portid:
            r = floating_config_vgw(fip.routerid, fip.floatingipaddress,
                                    fip.fixedipaddress)
            if not r:
                return Response(json.dumps(NEUTRON_500)), \
                    HTTP_INTERNAL_SERVER_ERROR
        else:
            fip.portid = ''
            fip.fixedipaddress = ''

        sql = ("INSERT INTO neutron_floatingips "
               "VALUES('%s','%s','%s','%s','%s','%s')" %
               (fip.floatingipid, fip.fixedipaddress,
                fip.floatingipaddress,
                fip.floatingnetworkid, fip.portid, fip.routerid))
        log.debug('add floating ip sql=%s' % sql)
        with MySQLdb.connect(**DB_INFO) as cursor:
            cursor.execute(sql)
        return Response(json.dumps(fip.to_primitive())), HTTP_CREATED

    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), HTTP_INTERNAL_SERVER_ERROR


def floating_config_vgw(routerid=None, isp_ip=None, fixip=None):
    ex_lcuuid = router_db_get_one('exlcuuid', id=routerid)
    log.debug('lcuuid=%s, isp_ip=%s, fixip=%s' % (ex_lcuuid, isp_ip, fixip))
    if not add_nat_to_router(True, ex_lcuuid, NAT_PROTOCOL_ANY, fixip,
                             fixip, NAT_PORT_MIN_VALUE, NAT_PORT_MAX_VALUE,
                             isp_ip, isp_ip, NAT_PORT_MIN_VALUE,
                             NAT_PORT_MAX_VALUE):
        return False
    return add_nat_to_router(False, ex_lcuuid, NAT_PROTOCOL_ANY, isp_ip,
                             isp_ip, NAT_PORT_MIN_VALUE, NAT_PORT_MAX_VALUE,
                             fixip, fixip, NAT_PORT_MIN_VALUE,
                             NAT_PORT_MAX_VALUE)


def floating_deconfig_vgw(routerid=None, isp_ip=None, fixip=None):
    ex_lcuuid = router_db_get_one('exlcuuid', id=routerid)
    log.debug('lcuuid=%s, isp_ip=%s, fixip=%s' % (ex_lcuuid, isp_ip, fixip))
    if not remove_nat_from_router(True, ex_lcuuid, NAT_PROTOCOL_ANY, fixip,
                                  fixip, NAT_PORT_MIN_VALUE,
                                  NAT_PORT_MAX_VALUE, isp_ip, isp_ip,
                                  NAT_PORT_MIN_VALUE, NAT_PORT_MAX_VALUE):
        return False
    return remove_nat_from_router(False, ex_lcuuid, NAT_PROTOCOL_ANY, isp_ip,
                                  isp_ip, NAT_PORT_MIN_VALUE,
                                  NAT_PORT_MAX_VALUE, fixip, fixip,
                                  NAT_PORT_MIN_VALUE, NAT_PORT_MAX_VALUE)


def rt_conf_nat_one_to_one(routerid=None, proto=0,
                           isp_ip=None, fixip=None,
                           isp_port=0, fixport=0):
    ex_lcuuid = router_db_get_one('exlcuuid', id=routerid)
    log.debug('lcuuid=%s, isp_ip=%s, fixip=%s' % (ex_lcuuid, isp_ip, fixip))
    log.debug('isp_port=%s, fixport=%s' % (isp_port, fixport))
    if not add_nat_to_router(True, ex_lcuuid, proto,
                             fixip, fixip, fixport, fixport,
                             isp_ip, isp_ip, isp_port, isp_port):
        return False
    return add_nat_to_router(False, ex_lcuuid, proto,
                             isp_ip, isp_ip, isp_port, isp_port,
                             fixip, fixip, fixport, fixport)


def rt_deconf_nat_one_to_one(routerid=None, proto=0,
                             isp_ip=None, fixip=None,
                             isp_port=0, fixport=0):
    ex_lcuuid = router_db_get_one('exlcuuid', id=routerid)
    log.debug('lcuuid=%s, isp_ip=%s, fixip=%s' % (ex_lcuuid, isp_ip, fixip))
    log.debug('isp_port=%s, fixport=%s' % (isp_port, fixport))
    if not remove_nat_from_router(True, ex_lcuuid, proto,
                                  fixip, fixip, fixport, fixport,
                                  isp_ip, isp_ip, isp_port, isp_port):
        return False
    return remove_nat_from_router(False, ex_lcuuid, proto,
                                  isp_ip, isp_ip, isp_port, isp_port,
                                  fixip, fixip, fixport, fixport)


@router_app.route(API_PREFIX + '/floatingips/<floatingipid>', methods=['PUT'])
@autodoc.doc(groups=['public', __name__])
def floatingip_put_api(floatingipid=None):
    """
    Implementation Notes
      Updates a floating IP and its association with an internal port.

    Response Class (Status 200)
      FloatingIP {
        floatingIpId (string, optional):
          Floating IP uuid.
        fixedIPAddress (string, optional):
          The fixed IP address that is associated with the floating IP address.
        floatingIpAddress (string, optional):
          The floating IP address.
        floatingNetworkId (string, optional):
          The UUID of the network associated with the floating IP.
        portId (string, optional):
          The UUID of the port.
        routerId (string, optional):
          The UUID of the router.
      }

    Parameters
      portId (string):
        Port uuid of the fixed IP address.
        If set to null, disassociate a floating IP from a port.
    """
    try:
        fipm = models.FloatingIPModify(request.json)
        fipm.validate()
    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_400)), HTTP_BAD_REQUEST
    try:
        if not floatingipid:
            return err_return('Floatingipid is required',
                              'BadRequest', '', HTTP_BAD_REQUEST)
        fip = models.FloatingIP()
        fip.floatingipid = floatingipid
        fip.portid = fipm.portid
        fip_db = floatingip_db_get_one('*', id=fip.floatingipid)
        if not fip_db:
            return err_return('Floatingipid does not exist',
                              'BadRequest', '', HTTP_BAD_REQUEST)
        if not fip.portid:
            if fip_db['portid'] == '':
                return floatingips_get(floatingipid=fip.floatingipid)
            r = floating_deconfig_vgw(fip_db['routerid'],
                                      fip_db['floatingipaddress'],
                                      fip_db['fixedipaddress'])
            if not r:
                return Response(json.dumps(NEUTRON_500)), \
                    HTTP_INTERNAL_SERVER_ERROR
            sql = ("UPDATE neutron_floatingips SET portid='', "
                   "fixedipaddress='' WHERE id='%s'" % fip.floatingipid)
            log.debug('disassociate sql=%s' % sql)
            with MySQLdb.connect(**DB_INFO) as cursor:
                cursor.execute(sql)
            return floatingips_get(floatingipid=fip.floatingipid)
        if fip_db['portid'] != '':
            return err_return(('Floatingip(%s) already associate with'
                               ' port(%s)' % (fip_db['id'], fip_db['portid'])),
                              type='ResouceInUse', code=HTTP_BAD_REQUEST)
        port = port_db_get_one(id=fip.portid)
        if not port:
            return err_return("PortId(%s) not found" % fip.portid,
                              "ParameterInvilad", "", HTTP_BAD_REQUEST)
        if get_floatingip_by_lan_port_id(fip.portid):
            return err_return("PortId(%s) in use" % fip.portid,
                              "ParameterInvilad", "", HTTP_BAD_REQUEST)
        networkid = port_db_get_one('network_id', id=fip.portid)
        if not networkid:
            err = 'Port(%s) not associate with any network' % fip.portid
            log.error(err)
            return err_return(err, "ParameterInvilad", "", HTTP_BAD_REQUEST)
        rt_lanp_netid = port_db_get_one('network_id',
                                        device_type=PORT_TYPE_ROUTER,
                                        device_id=fip_db['routerid'],
                                        ifindex=VGW_LAN_PORT_IFINDEX)
        if rt_lanp_netid and rt_lanp_netid != networkid:
            err = ('No port of router(%s) with port(%s) '
                   'on the same network' % (fip_db['routerid'], fip.portid))
            log.error(err)
            return err_return(err, "ParameterInvilad", "", HTTP_BAD_REQUEST)
        if not rt_lanp_netid:
            epcid = network_db_get_one('epc_id', id=networkid)
            if not move_router_to_epc(fip_db['routerid'], epcid):
                log.error('Move router(%s) to epc fail' % fip_db['routerid'])
                return Response(json.dumps(NEUTRON_500)), \
                    HTTP_INTERNAL_SERVER_ERROR
        fixedipaddress = port_ip_db_get_one('ip_address', port_id=fip.portid)
        if not fixedipaddress:
            return err_return(message='No IP on port(%s)' % fip.portid,
                              type='ResouceNotFound', code=HTTP_BAD_REQUEST)
        r = floating_config_vgw(fip_db['routerid'],
                                fip_db['floatingipaddress'],
                                fixedipaddress)
        if not r:
            return Response(json.dumps(NEUTRON_500)), \
                HTTP_INTERNAL_SERVER_ERROR
        sql = ("UPDATE neutron_floatingips SET portid='%s', "
               "fixedipaddress='%s' WHERE id='%s'" %
               (fip.portid, fixedipaddress, fip.floatingipid))
        log.debug('associate sql=%s' % sql)
        with MySQLdb.connect(**DB_INFO) as cursor:
            cursor.execute(sql)
        return floatingips_get(floatingipid=fip.floatingipid)
    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), HTTP_INTERNAL_SERVER_ERROR


@router_app.route(API_PREFIX + '/floatingips/<floatingipid>',
                  methods=['DELETE'])
@autodoc.doc(groups=['public', __name__])
def floatingip_delete_api(floatingipid=None):
    """
    Implementation Notes
      Deletes a floating IP and, if present, its associated port.

    Response Messages 200

    Parameters
      floatingipId (string, required): The floating IP uuid to act on.
    """
    try:
        if not floatingipid:
            return err_return('floatingipid required', 'ParameterInvilad',
                              '', HTTP_BAD_REQUEST)
        fip = floatingip_db_get_one('*', id=floatingipid)
        if not fip:
            return err_return('floatingipid dose not exist',
                              'ParameterInvilad', '', HTTP_BAD_REQUEST)
        if fip['portid'] != '':
            log.debug("portid=%s" % fip['portid'])
            r = floating_deconfig_vgw(fip['routerid'],
                                      fip['floatingipaddress'],
                                      fip['fixedipaddress'])
            if not r:
                return Response(json.dumps(NEUTRON_500)), \
                    HTTP_INTERNAL_SERVER_ERROR
        wan_port_id = port_db_get_one('id', device_type=PORT_TYPE_ROUTER,
                                      device_id=fip['routerid'],
                                      ifindex=VGW_WAN_PORT_IFINDEX)
        port_ips = port_ip_db_get_all(port_id=wan_port_id)
        if len(port_ips) > 1:
            ret = router_remove_ip_from_wan_port(fip['routerid'],
                                                 fip['floatingipaddress'])
            if not ret:
                return Response(json.dumps(NEUTRON_500)), \
                    HTTP_INTERNAL_SERVER_ERROR
        sql = ("DELETE FROM neutron_floatingips "
               "WHERE id='%s'" % floatingipid)
        log.debug('clear floating ip, sql=%s' % sql)
        with MySQLdb.connect(**DB_INFO) as cursor:
            cursor.execute(sql)
        return Response(), HTTP_OK
    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), HTTP_INTERNAL_SERVER_ERROR


def get_floatingip_by_lan_port_id(portid=None):
    if not portid:
        return None
    return floatingip_db_get_one('id', portid=portid)

import logging
import simplejson as json
from flask import Blueprint
from flask import request
from conf import conf
from const import NEUTRON_500, NEUTRON_400
from const import API_PREFIX
from const import VFW_TOR_LINK_NET_PRE, VFW_TOR_LINK_NET_MASK
from const import NAME_MAX_LEN
from utils import Response, ip_to_bin, masklen2netmask
from utils import ip_mask_to_cidr, err_return
from utils import alloc_pools_to_ip_list, validate_cidr
from const import HTTP_BAD_REQUEST, HTTP_INTERNAL_SERVER_ERROR, \
    HTTP_NOT_FOUND, HTTP_OK, HTTP_CREATED
from documentation import autodoc
import lcapi
import models
import MySQLdb
import copy
import uuid
import subprocess
from dbutils import DB_INFO, LCDB_INFO
from dbutils import (subnet_db_get_one, network_db_get_one,
                     subnetid_to_networkid, lc_ip_res_db_get_all,
                     subnet_db_delete, lc_vl2_db_get_one, subnet_db_get_all,
                     lc_vif_ip_db_get_all, port_ip_db_get_all)


log = logging.getLogger(__name__)
subnet_app = Blueprint('subnet_app', __name__)


def yynetworkid_to_lcvl2id(networkid):
    lcuuid = network_db_get_one('lcuuid', id=networkid)
    if not lcuuid:
        return None
    log.debug('vl2lcuuid=%s' % lcuuid)
    r = lcapi.get(conf.livecloud_url + '/v1/vl2s?lcuuid=' + lcuuid)
    log.debug('get vl2 ret=%s' % r.json())
    data = r.json().get('DATA')
    if not data:
        return None
    else:
        return data.get('ID', None)


def subnet_equ(prf_a=None, prf_b=None, mask_a=None, mask_b=None):
    if prf_a is None or prf_b is None or mask_a is None or mask_b is None:
        return False
    if mask_a != mask_b:
        return False

    a = ip_to_bin(prf_a) & ip_to_bin(masklen2netmask(mask_a))
    b = ip_to_bin(prf_b) & ip_to_bin(masklen2netmask(mask_b))

    if a == b:
        return True
    else:
        return False


def get_subnets_by_network(networkid):
    return subnet_db_get_all('*', network_id=networkid)


@subnet_app.route(API_PREFIX + '/subnets', methods=['POST'])
@autodoc.doc(groups=['public', __name__])
def subnet_create_api():
    """
    Implementation Notes
      Creates a subnet on a network.

    Response Class (Status 201)
      Subnet {
        subnetId (string, optional): Subnet uuid.
        subnetName (string, optional): Subnet name, a user readable name.
        networkId (string, optional): Network uuid.
        cidr (string, optional): The CIDR of subnet.
        allocation_pools (Array[inline_model], optional):
          The start and end addresses for the allocation pools.
        gatewayIp (string, required): The gateway IP address.
        dnsNameservers (Array[string], optional):
          A list of DNS name servers for the subnet.
      }
      inline_model {
        start (string, optional): Start IP address. ,
        end (string, optional): End IP address.
      }

    Parameters
      Subnet (body, required): Subnet description
    """
    try:
        req = models.Subnet(request.json)
        req.validate()
    except Exception as e:
        return err_return('Parameter Invalid', 'ParameterInvalid',
                          '', HTTP_BAD_REQUEST)
    try:
        if not req.network_id:
            return err_return('networkid is required', 'ParameterInvalid',
                              '', HTTP_BAD_REQUEST)
        if not req.subnet_id:
            req_id = str(uuid.uuid4())
        else:
            req_id = req.subnet_id
            sb_name = subnet_db_get_one('name', id=req_id)
            if sb_name:
                return err_return('id(%s) in use by %s' % (req_id, sb_name),
                                  'ParameterInvalid', '', HTTP_BAD_REQUEST)
        if req.subnet_name:
            if len(req.subnet_name) > NAME_MAX_LEN:
                return err_return('Length of name must be less than 255',
                                  'ParameterInvalid', '', HTTP_BAD_REQUEST)
        else:
            req.subnet_name = ''

        external = network_db_get_one('external', id=req.network_id)
        if external is None:
            return err_return("networkid does not exist",
                              "ParameterInvalid", "", HTTP_BAD_REQUEST)
        if not req.dns_nameservers:
            req.dns_nameservers = []
        if not req.allocation_pools:
            req.allocation_pools = []
        allocation_pools = []
        for all_pool in req.allocation_pools:
            allocation_pools.append(all_pool.to_primitive())
        req.allocation_pools = allocation_pools
        for pool in req.allocation_pools:
            if ip_to_bin(pool['start']) > ip_to_bin(pool['end']):
                return err_return("end_ip must be more than start_ip",
                                  "IPRangeError", "", HTTP_BAD_REQUEST)

        if external == 0:
            if not req.cidr:
                return err_return('cidr is required', 'ParameterInvalid',
                                  '', HTTP_BAD_REQUEST)
            if not validate_cidr(req.cidr):
                return err_return('cidr invalid', 'ParameterInvalid',
                                  '', HTTP_BAD_REQUEST)
            if not req.gateway_ip:
                return err_return('gateway ip is required', 'ParameterInvalid',
                                  '', HTTP_BAD_REQUEST)
            vl2lcid = yynetworkid_to_lcvl2id(req.network_id)
            log.debug('vl2lcid=%s' % vl2lcid)
            nets = [{"prefix": VFW_TOR_LINK_NET_PRE,
                     "netmask": VFW_TOR_LINK_NET_MASK}]
            cidr = str(req.cidr).split('/')
            new_prf = cidr[0]
            new_mask = int(cidr[1])
            subnets = get_subnets_by_network(req.network_id)
            for subnet in subnets:
                cidr = subnet['cidr'].split('/')
                old_prf = cidr[0]
                old_mask = int(cidr[1])
                if subnet_equ(new_prf, old_prf, new_mask, old_mask):
                    log.error('cidr is the same')
                    return err_return('subnet already exist',
                                      'ParameterInvalid', '', HTTP_BAD_REQUEST)
                nets.append({"prefix": old_prf, "netmask": old_mask})
            nets.append({"prefix": new_prf, "netmask": new_mask})
            log.debug('nets=%s' % nets)
            nw_name = network_db_get_one('name', id=req.network_id)
            payload = json.dumps({"name": nw_name, "nets": nets})
            r = lcapi.patch(conf.livecloud_url + '/v1/vl2s/%s' % vl2lcid,
                            data=payload)
            if r.status_code != HTTP_OK:
                return Response(json.dumps(NEUTRON_400)), HTTP_NOT_FOUND
            nets = r.json()['DATA']['NETS']
            for net in nets:
                if subnet_equ(net['PREFIX'], new_prf,
                              net['NETMASK'], new_mask):
                    sb_lcuuid = net['LCUUID']
                    sb_idx = net['NET_INDEX']
                    break
            else:
                log.error('sb_lcuuid no found')
                sb_lcuuid = 'sb_lcuuid no found'
                sb_idx = -1
        else:
            subnetid = subnet_db_get_one('id', network_id=req.network_id)
            if subnetid:
                return err_return('subnet(%s) already exists' % subnetid,
                                  'Fail', '', HTTP_BAD_REQUEST)
            # ISP
            if not req.allocation_pools:
                return err_return('allocation_pools can not be empty',
                                  'ParameterInvalid', '', HTTP_BAD_REQUEST)
            id = subnet_db_get_one('id', network_id=req.network_id)
            if id:
                return subnet_get(subnetid=id)
            lcuuid = network_db_get_one('lcuuid', id=req.network_id)
            isp = lc_vl2_db_get_one('isp', lcuuid=lcuuid)
            items = lc_ip_res_db_get_all(req='ip, netmask, gateway, userid',
                                         isp=isp)
            if not items:
                return err_return("No ISP IP found", "BadRequest",
                                  "Please add ISP IP to system first",
                                  HTTP_BAD_REQUEST)
            req.gateway_ip = items[0]['gateway']
            req.cidr = ip_mask_to_cidr(items[0]['ip'], items[0]['netmask'])
            isp_all_ips = []
            ip_to_userid = {}
            for it in items:
                isp_all_ips.append(it['ip'])
                ip_to_userid[it['ip']] = it['userid']
            req_ips = alloc_pools_to_ip_list(req.allocation_pools)
            for req_ip in req_ips:
                if req_ip not in isp_all_ips:
                    return err_return("%s does not exist" % req_ip,
                                      "IPInvalid", "", HTTP_BAD_REQUEST)
                if ip_to_userid[req_ip] != 0:
                    return err_return("%s in use" % req_ip,
                                      "IPInUse", "", HTTP_BAD_REQUEST)
            sb_lcuuid = str(uuid.uuid4())
            sb_idx = -1

        sql = ("INSERT INTO neutron_subnets "
               "VALUES('%s','%s','%s','%s','%s','%s','%s','%s',%d)" %
               (req_id, req.subnet_name, req.network_id,
                req.cidr, json.dumps(req.allocation_pools),
                req.gateway_ip, json.dumps(req.dns_nameservers),
                sb_lcuuid, sb_idx))
        log.debug('add subnet sql=%s' % sql)
        with MySQLdb.connect(**DB_INFO) as cursor:
            cursor.execute(sql)
        if external:
            sql = "UPDATE ip_resource_v2_2 SET userid=%s WHERE ip in ('-1',"
            for req_ip in req_ips:
                sql += "'%s'," % req_ip
            sql = sql[:-1]
            sql += ")"
            log.debug('sql=%s' % sql)
            with MySQLdb.connect(**LCDB_INFO) as cursor:
                cursor.execute(sql, conf.livecloud_userid)

        resp, code = subnet_get(subnetid=req_id)
        return resp, HTTP_CREATED

    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), HTTP_INTERNAL_SERVER_ERROR


@subnet_app.route(API_PREFIX + '/subnets')
@subnet_app.route(API_PREFIX + '/subnets/<subnetid>')
@autodoc.doc(groups=['public', __name__])
def subnet_get_api(subnetid=None):
    """
    Implementation Notes
        Gets subnet information for a single subnet.
    Response Class (Status 200)
      Subnet {
        subnetId (string, optional): Subnet uuid.
        subnetName (string, optional): Subnet name, a user readable name.
        networkId (string, optional): Network uuid.
        cidr (string, optional): The CIDR of subnet.
        allocation_pools (Array[inline_model], optional):
          The start and end addresses for the allocation pools.
        gatewayIp (string, optional): The gateway IP address.
        dnsNameservers (Array[string], optional):
          A list of DNS name servers for the subnet.
      }
      inline_model {
        start (string, optional): Start IP address. ,
        end (string, optional): End IP address.
      }

    Parameters
      subnetId (string, optional): The subnet uuid to act on
    """
    networkid = request.args.get('networkId', None)
    return subnet_get(subnetid=subnetid, networkid=networkid)


def subnet_get(subnetid=None, networkid=None):
    try:
        if subnetid:
            item = subnet_db_get_one('*', id=subnetid)
            if not item:
                return Response(json.dumps({"ERROR": "subnetId error"})),\
                    HTTP_NOT_FOUND

            r_item = models.Subnet()
            r_item.subnet_id = item['id']
            r_item.subnet_name = item['name']
            r_item.network_id = item['network_id']
            r_item.cidr = item['cidr']
            r_item.allocation_pools = json.loads(item['allocation_pools'])
            r_item.gateway_ip = item['gateway_ip']
            r_item.dns_nameservers = json.loads(item['dns_nameservers'])
            return Response(json.dumps(r_item.to_primitive())), HTTP_OK

        networkids = []
        log.debug('networkid=%s' % networkid)
        if networkid:
            networkids.append(networkid)
        else:
            with MySQLdb.connect(**DB_INFO) as cursor:
                sql = "SELECT id FROM neutron_networks"
                cursor.execute(sql)
                items = cursor.fetchall()
                for item in items:
                    networkids.append(item['id'])
        log.debug('networkids=%s' % networkids)
        rs = []
        for networkid in networkids:
            items = get_subnets_by_network(networkid)
            for item in items:
                r_item = models.Subnet()
                r_item.subnet_id = item['id']
                r_item.subnet_name = item['name']
                r_item.network_id = item['network_id']
                r_item.cidr = item['cidr']
                r_item.allocation_pools = json.loads(item['allocation_pools'])
                r_item.gateway_ip = item['gateway_ip']
                r_item.dns_nameservers = json.loads(item['dns_nameservers'])
                rs.append(r_item.to_primitive())
        return Response(json.dumps(rs)), HTTP_OK
    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), 500


@subnet_app.route(API_PREFIX + '/subnets/<subnetid>', methods=['PUT'])
@autodoc.doc(groups=['public', __name__])
def subnet_put_api(subnetid=None):
    """
    Implementation Notes
      Updates existing subnet.

    Response Class (Status 200)
      Subnet {
        subnetId (string, optional): Subnet uuid.
        subnetName (string, optional): Subnet name, a user readable name.
        networkId (string, optional): Network uuid.
        cidr (string, optional): The CIDR of subnet.
        allocation_pools (Array[inline_model], optional):
          The start and end addresses for the allocation pools.
        gatewayIp (string, optional): The gateway IP address.
        dnsNameservers (Array[string], optional):
          A list of DNS name servers for the subnet.
      }
      inline_model {
        start (string, optional): Start IP address. ,
        end (string, optional): End IP address.
      }

    Parameters
      subnetId (string, optional): The subnet uuid to act on
      Subnet (body, required): Subnet description
    """
    try:
        if not subnetid:
            return err_return('subnetId is required', "ParameterInvalid",
                              "", HTTP_BAD_REQUEST)
        db_subnet = subnet_db_get_one('*', id=subnetid)
        if not db_subnet:
            return err_return('subnetId does not exist', "ParameterInvalid",
                              "", HTTP_NOT_FOUND)
        cidr = db_subnet['cidr']
        try:
            req = models.Subnet(request.json)
            req.validate()
        except Exception as e:
            log.error(e)
            return err_return('Parameter Invalid', "ParameterInvalid",
                              "", HTTP_BAD_REQUEST)
        with MySQLdb.connect(**DB_INFO) as cursor:
            if req.subnet_name is not None:
                if len(req.subnet_name) > NAME_MAX_LEN:
                    return err_return('Length of name must be less than 255',
                                      'ParameterInvalid', '', HTTP_BAD_REQUEST)
                sql = "UPDATE neutron_subnets SET name=%s WHERE id=%s"
                cursor.execute(sql, (req.subnet_name, subnetid))
            if req.dns_nameservers is not None:
                sql = ("UPDATE neutron_subnets SET "
                       "dns_nameservers=%s WHERE id=%s")
                cursor.execute(sql,
                               (json.dumps(req.dns_nameservers), subnetid))
        if req.allocation_pools is not None:
            allocation_pools = []
            for all_pool in req.allocation_pools:
                allocation_pools.append(all_pool.to_primitive())
            req.allocation_pools = allocation_pools
            for pool in req.allocation_pools:
                if ip_to_bin(pool['start']) > ip_to_bin(pool['end']):
                    return err_return("end_ip must be more than start_ip",
                                      "IPRangeError", "", HTTP_BAD_REQUEST)
        networkid = subnetid_to_networkid(subnetid)
        db_network = network_db_get_one('*', id=networkid)
        external = db_network['external']
        log.debug('external=%s' % external)
        if external:
            if req.allocation_pools is not None:
                old_alloc_pools = json.loads(db_subnet['allocation_pools'])
                old_alloc_ips = alloc_pools_to_ip_list(old_alloc_pools)
                new_alloc_ips = alloc_pools_to_ip_list(req.allocation_pools)
                tmp_nips = copy.deepcopy(new_alloc_ips)
                for new_ip in tmp_nips:
                    if new_ip in old_alloc_ips:
                        new_alloc_ips.remove(new_ip)
                        old_alloc_ips.remove(new_ip)
                isp = lc_vl2_db_get_one('isp', lcuuid=db_network['lcuuid'])
                items = lc_ip_res_db_get_all(req='ip, userid, vifid',
                                             isp=isp)
                isp_all_ips = []
                ip_to_userid = {}
                ip_to_vifid = {}
                for it in items:
                    isp_all_ips.append(it['ip'])
                    ip_to_userid[it['ip']] = it['userid']
                    ip_to_vifid[it['ip']] = it['vifid']
                for new_alloc_ip in new_alloc_ips:
                    if new_alloc_ip not in isp_all_ips:
                        return err_return("%s invalid" % new_alloc_ip,
                                          "IPInvalid", "", HTTP_BAD_REQUEST)
                    if ip_to_userid[new_alloc_ip] != 0:
                        return err_return("%s in use" % new_alloc_ip,
                                          "IPInUse", "", HTTP_BAD_REQUEST)
                for old_alloc_ip in old_alloc_ips:
                    if ip_to_vifid[old_alloc_ip] != 0:
                        return err_return("%s in use" % old_alloc_ip,
                                          "IPInUse", "", HTTP_BAD_REQUEST)
                sql = ("UPDATE neutron_subnets SET allocation_pools='%s' "
                       "WHERE id='%s'" % (json.dumps(req.allocation_pools),
                                          subnetid))
                with MySQLdb.connect(**DB_INFO) as cursor:
                    cursor.execute(sql)
                sql = ("UPDATE ip_resource_v2_2 SET userid=0 "
                       "WHERE ip in ('-1',")
                for ip in old_alloc_ips:
                    sql += "'%s'," % ip
                sql = sql[:-1]
                sql += ")"
                sql2 = ("UPDATE ip_resource_v2_2 SET userid=%s "
                        "WHERE ip in ('-1',")
                for ip in new_alloc_ips:
                    sql2 += "'%s'," % ip
                sql2 = sql2[:-1]
                sql2 += ")"
                with MySQLdb.connect(**LCDB_INFO) as cursor:
                    cursor.execute(sql)
                    cursor.execute(sql2, conf.livecloud_userid)
            return subnet_get(subnetid=subnetid)

        if req.gateway_ip is not None:
            with MySQLdb.connect(**DB_INFO) as cursor:
                sql = "UPDATE neutron_subnets SET gateway_ip=%s WHERE id=%s"
                cursor.execute(sql, (req.gateway_ip, subnetid))
        log.debug('old_cidr=%s, new_cidr=%s' % (cidr, req.cidr))
        if req.cidr and cidr != req.cidr:
            vl2lcid = yynetworkid_to_lcvl2id(networkid)
            nets = [{"prefix": VFW_TOR_LINK_NET_PRE,
                     "netmask": VFW_TOR_LINK_NET_MASK}]
            subnets = get_subnets_by_network(networkid)
            for subnet in subnets:
                if str(subnet['id']) == subnetid:
                    continue
                cidr = subnet['cidr'].split('/')
                nets.append({"prefix": cidr[0], "netmask": int(cidr[1])})
            cidr = str(req.cidr).split('/')
            log.debug('netmask=%s' % cidr[1])
            nets.append({"prefix": cidr[0], "netmask": int(cidr[1])})
            nw_name = network_db_get_one('name', id=networkid)
            payload = json.dumps({"name": nw_name, "nets": nets})
            log.debug('patch vl2 data=%s' % payload)
            r = lcapi.patch(conf.livecloud_url + '/v1/vl2s/%s' % vl2lcid,
                            data=payload)
            if r.status_code != HTTP_OK:
                err = r.json()['DESCRIPTION']
                log.error(err)
                return err_return(err, 'Fail', '', HTTP_BAD_REQUEST)
            nets = r.json()['DATA']['NETS']
            for net in nets:
                if subnet_equ(net['PREFIX'], cidr[0],
                              net['NETMASK'], int(cidr[1])):
                    sb_lcuuid = net['LCUUID']
                    sb_idx = net['NET_INDEX']
                    break
            else:
                log.error('sb_lcuuid no found')
                return Response(json.dumps(NEUTRON_500)), \
                    HTTP_INTERNAL_SERVER_ERROR
            if req.allocation_pools is None:
                req.allocation_pools = []
        else:
            req.cidr = db_subnet['cidr']
            sb_lcuuid = db_subnet['lcuuid']
            sb_idx = db_subnet['net_idx']
            if req.allocation_pools is None:
                return subnet_get(subnetid=subnetid)
            new_alloc_ips = alloc_pools_to_ip_list(req.allocation_pools)
            vl2id = lc_vl2_db_get_one('id', lcuuid=sb_lcuuid)
            used_ips = lc_vif_ip_db_get_all('ip', vl2id=vl2id,
                                            net_index=sb_idx)
            for used_ip in used_ips:
                ip = used_ip['ip']
                if ip not in new_alloc_ips:
                    return err_return('used ip(%s) not in alloc pool' % ip,
                                      'ParameterInvalid', '', HTTP_BAD_REQUEST)

        sql = ("UPDATE neutron_subnets SET cidr='%s', "
               "allocation_pools='%s', lcuuid='%s', net_idx=%s "
               "WHERE id='%s'" %
               (req.cidr, json.dumps(req.allocation_pools),
                sb_lcuuid, sb_idx, subnetid))
        log.debug('sql=%s' % sql)
        with MySQLdb.connect(**DB_INFO) as cursor:
            cursor.execute(sql)
        return subnet_get(subnetid=subnetid)
    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), HTTP_INTERNAL_SERVER_ERROR


@subnet_app.route(API_PREFIX + '/subnets/<subnetid>', methods=['DELETE'])
@autodoc.doc(groups=['public', __name__])
def subnet_delete_api(subnetid=None):
    """
    Implementation Notes
      Deletes a subnet.

    Response Messages (Status 200)

    Parameters
      subnetId (string, required): The subnet uuid to act on.
    """
    try:
        if not subnetid:
            return err_return('subnetId is required', 'ParameterInvalid',
                              '', HTTP_BAD_REQUEST)
        cidr = subnet_db_get_one('cidr', id=subnetid)
        if not cidr:
            return err_return('subnetId does not exist', 'ParameterInvalid',
                              '', HTTP_NOT_FOUND)

        if port_ip_db_get_all(subnet_id=subnetid):
            return err_return('subnet in use', 'ParameterInvalid',
                              '', HTTP_BAD_REQUEST)
        networkid = subnetid_to_networkid(subnetid)
        external = network_db_get_one('external', id=networkid)
        log.debug('external=%s' % external)
        if external:
            ret, desc = delete_subnet_by_networkid(networkid)
            if not ret:
                return err_return(desc, 'SubnetDeleteFail',
                                  '', HTTP_BAD_REQUEST)
            return Response(), HTTP_OK
        vl2lcid = yynetworkid_to_lcvl2id(networkid)
        nets = [{"prefix": VFW_TOR_LINK_NET_PRE,
                 "netmask": VFW_TOR_LINK_NET_MASK}]
        subnets = get_subnets_by_network(networkid)
        for subnet in subnets:
            if str(subnet['id']) == subnetid:
                continue
            cidr = subnet['cidr'].split('/')
            nets.append({"prefix": cidr[0], "netmask": int(cidr[1])})
        nw_name = network_db_get_one('name', id=networkid)
        payload = json.dumps({"name": nw_name, "nets": nets})
        r = lcapi.patch(conf.livecloud_url + '/v1/vl2s/%s' % vl2lcid,
                        data=payload)
        if r.status_code != HTTP_OK:
            err = r.json()['DESCRIPTION']
            log.error(r.json()['DESCRIPTION'])
            return err_return(err, 'Fail', '', HTTP_BAD_REQUEST)
        subnet_db_delete(id=subnetid)
        return Response(), HTTP_OK
    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), HTTP_INTERNAL_SERVER_ERROR


def delete_subnet_by_networkid(networkid):
    try:
        network = network_db_get_one("*", id=networkid)
        if not network:
            return False, 'Network not found'
        if not network['external']:
            subnet_db_delete(network_id=networkid)
            return True, ''
        alloc_pools = subnet_db_get_one("allocation_pools",
                                        network_id=networkid)
        if not alloc_pools:
            return True, ''
        alloc_pools = json.loads(alloc_pools)
        ips = alloc_pools_to_ip_list(alloc_pools)
        sql = "SELECT ip FROM ip_resource_v2_2 WHERE vifid!=0 AND ip in ('-1',"
        for ip in ips:
            sql += "'%s'," % ip
        sql = sql[:-1]
        sql += ")"
        log.debug('sql=%s' % sql)
        with MySQLdb.connect(**LCDB_INFO) as cursor:
            cursor.execute(sql)
            items = cursor.fetchall()
        if items:
            return False, 'Some IP in use'
        sql = "UPDATE ip_resource_v2_2 SET userid=0 WHERE ip in ('-1',"
        for ip in ips:
            sql += "'%s'," % ip
        sql = sql[:-1]
        sql += ")"
        log.debug('sql=%s' % sql)
        with MySQLdb.connect(**LCDB_INFO) as cursor:
            cursor.execute(sql)
        subnet_db_delete(network_id=networkid)
        return True, ''
    except Exception as e:
        log.error(e)
        return False, 'Internal server error'


@subnet_app.route(API_PREFIX + '/health')
@autodoc.doc(groups=['public', __name__])
def health_get_api():
    """
    Implementation Notes
      Returns controller health status info,
      including component status, db status, cluster node info etc.

    Response Messages 200

    Parameters
      none
    """
    try:
        (out, err) = subprocess.Popen(['livecloud', 'status'],
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE).communicate()
        out_list = out.split('\n')
        while '' in out_list:
            out_list.remove('')
        del out_list[-1]
        out = '\n'.join(out_list)
        out += '\n'
        err_list = err.split('\n')
        while '' in err_list:
            err_list.remove('')
        del err_list[-1]
        err = '\n'.join(err_list)
        err += '\n'
        return Response(out+err), HTTP_OK
    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), HTTP_INTERNAL_SERVER_ERROR
import logging
import simplejson as json
import uuid

from flask import Blueprint
from flask import request
import MySQLdb
import gevent

from conf import conf
from const import DB_INFO, NEUTRON_500, API_PREFIX
from const import VFW_TOR_LINK_NET_PRE, VFW_TOR_LINK_NET_MASK
from documentation import autodoc
import lcapi
import models
from utils import process_request_args
from utils import Response
from subnet_app import delete_subnet_by_networkid
import copy
import async
LC_DB_INFO = copy.copy(DB_INFO)
LC_DB_INFO['db'] = 'livecloud'

log = logging.getLogger(__name__)
network_app = Blueprint('network_app', __name__)


@network_app.route(API_PREFIX + '/networks')
@network_app.route(API_PREFIX + '/networks/<id>')
@autodoc.doc(groups=['public', __name__])
def network_get_api(id=None):
    """
    Implementation Notes
        List networks.

    Response Class (Status 200)
        Network {
            networkId (string, optional): Network uuid,
            networkName (string, required): Network name,a user readable name,
            networkType (string, optional): Network type,Valid value is VXLAN,
            segmentationId (integer, optional): VXLAN vni,
            external (boolean, optional):
                Whether this network is external managed.
        }

    Parameters
        networkId
    """
    code = 200
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
                sql = 'SELECT * FROM neutron_networks WHERE id=%s'
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
                sql = 'SELECT * FROM neutron_networks WHERE ' + conds
                cursor.execute(sql, tuple(params))
                desc = [it[0] for it in cursor.description]
                for item in cursor:
                    items.append(dict(zip(desc, item)))

    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), 500

    ri = None
    rs = []
    for item in items:
        r_item = models.Network()
        if not fields:
            fields = r_item.serialized_field_names()
        if 'networkId' in fields:
            r_item.id = item.get('id', None)
        if 'networkName' in fields:
            r_item.name = item.get('name', None)
        if 'networkType' in fields:
            r_item.type = item.get('type', None)
        if 'segmentationId' in fields:
            r_item.segmentation_id = item.get('segmentation_id', 0)
        if 'external' in fields:
            external = item.get('external', 0)
            if external:
                r_item.external = True
            else:
                r_item.external = False

        r_item_dict = r_item.filtered_fields(fields)
        if id is not None:
            ri = r_item_dict
            break
        rs.append(r_item_dict)
    if id is not None:
        if ri is None:
            result = {
                "NeutronError": {
                    "message": "Network %s could not be found" % id,
                    "type": "NetworkNotFound",
                    "detail": ""
                }
            }
            code = 404
        else:
            result = ri
    else:
        result = rs

    return Response(json.dumps(result)), code


@network_app.route(API_PREFIX + '/networks', methods=['POST'])
@autodoc.doc(groups=['public', __name__])
def network_post_api():
    """
    Implementation Notes
        Create a new network.

    Response Class (Status 201)
        Network {
            networkId (string, optional): Network uuid,
            networkName (string, required): Network name,a user readable name,
            networkType (string, optional): Network type,Valid value is VXLAN,
            segmentationId (integer, optional): VXLAN vni,
            external (boolean, optional):
                Whether this network is external managed.
        }

    Parameters
        Network
    """
    try:
        req = models.Network(request.json)
        req.validate()
    except Exception as e:
        result = {
            "NeutronError": {
                "message": "Request check failed",
                "type": "BadRequest",
                "detail": ""
            }
        }
        log.error(result)
        return Response(json.dumps(result)), 400

    try:
        with MySQLdb.connect(**DB_INFO) as cursor:
            sql = 'SELECT * FROM neutron_networks WHERE name=%s'
            cursor.execute(sql, req.name)
            item = cursor.fetchone()
            if item is not None:
                result = {
                    "NeutronError": {
                        "message": "Network %s already exists" % req.name,
                        "type": "BadRequest",
                        "detail": ""
                    }
                }
                log.error(result)
                return Response(json.dumps(result)), 400
    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), 500

    if req.id is None:
        req.id = str(uuid.uuid4())

    network_epc_id = 0
    if not req.external:
        try:
            epc_req = {}
            epc_req['name'] = str(req.name) + '-' + str(req.id)
            epc_req['userid'] = conf.livecloud_userid
            epc_req['domain'] = conf.livecloud_domain

            r = lcapi.post(url=conf.livecloud_url + '/v1/epcs',
                           data=json.dumps(epc_req))
            if r.status_code != 200:
                return Response(json.dumps(NEUTRON_500)), r.status_code
            resp = r.json()
            if resp['OPT_STATUS'] == 'SUCCESS' and 'DATA' in resp:
                network_epc_id = resp['DATA'].get('ID', '')
            else:
                log.error('Error (%s): %s' %
                          (r['OPT_STATUS']. r['DESCRIPTION']))
                return Response(json.dumps(NEUTRON_500)), 500
        except Exception as e:
            log.error(e)
            return Response(json.dumps(NEUTRON_500)), 500

        network_req = {}
        network_req['name'] = req.name
        network_req['vlantag'] = 0
        network_req['userid'] = conf.livecloud_userid
        network_req['epc_id'] = network_epc_id
        network_req['domain'] = conf.livecloud_domain
        # default net to link vfw-router and tor-router of router
        network_req['nets'] = [{"prefix": VFW_TOR_LINK_NET_PRE,
                                "netmask": VFW_TOR_LINK_NET_MASK}]
        try:
            r = lcapi.post(url=conf.livecloud_url + '/v1/vl2s',
                           data=json.dumps(network_req))
            if r.status_code != 200:
                return Response(json.dumps(NEUTRON_500)), r.status_code
            resp = r.json()
            if resp['OPT_STATUS'] != 'SUCCESS' or 'DATA' not in resp:
                log.error('Error (%s): %s' %
                          (r['OPT_STATUS']. r['DESCRIPTION']))
                return Response(json.dumps(NEUTRON_500)), 500
            assert 'TASK' in resp
            cb_resp = async.Results.get(resp['TASK'], timeout=30)
            req.segmentation_id = cb_resp['DATA'].get('SEGMENTATION_ID', 0)
            network_lcuuid = cb_resp['DATA'].get('LCUUID', '')

        except gevent.timeout.Timeout as e:
            log.error('Callback timed out after %s' % e)
            return Response(json.dumps(NEUTRON_500)), 500

        except Exception as e:
            log.error(e)
            return Response(json.dumps(NEUTRON_500)), 500
    else:
        try:
            with MySQLdb.connect(**LC_DB_INFO) as cursor:
                if req.segmentation_id:
                    sql = ('SELECT isp FROM ip_resource_v2_2 WHERE vlantag = '
                           + str(req.segmentation_id))
                    cursor.execute(sql)
                    item = cursor.fetchone()
                    if item is None:
                        result = {
                            "NeutronError": {
                                "message": "Not support the segmentationId",
                                "type": "BadRequest",
                                "detail": ""
                            }
                        }
                        return Response(json.dumps(result)), 400

                    sql = ('SELECT lcuuid FROM vl2_v2_2 WHERE isp = '
                           + str(item[0]))
                    cursor.execute(sql)
                    item = cursor.fetchone()
                    if item is None:
                        result = {
                            "NeutronError": {
                                "message": "Please check public network "
                                           "configuration",
                                "type": "InternalServerError",
                                "detail": ""
                            }
                        }
                        return Response(json.dumps(result)), 500

                    network_lcuuid = item[0]
                else:
                    sql = ('SELECT * FROM vl2_v2_2 WHERE userid = 0 AND '
                           'isp > 0 AND isp < 7')
                    cursor.execute(sql)
                    item = cursor.fetchone()
                    if item is None:
                        result = {
                            "NeutronError": {
                                "message": "Please check public network "
                                           "configuration",
                                "type": "InternalServerError",
                                "detail": ""
                            }
                        }
                        return Response(json.dumps(result)), 500
                    desc = [it[0] for it in cursor.description]
                    isp_info = dict(zip(desc, item))

                    sql = ('SELECT vlantag FROM ip_resource_v2_2 WHERE isp = '
                           + str(isp_info['isp']))
                    cursor.execute(sql)
                    item = cursor.fetchone()
                    if item is None:
                        result = {
                            "NeutronError": {
                                "message": "Please config public network ip",
                                "type": "BadRequest",
                                "detail": ""
                            }
                        }
                        return Response(json.dumps(result)), 400

                    req.segmentation_id = item[0]
                    network_lcuuid = isp_info['lcuuid']
        except Exception as e:
            log.error(e)
            return Response(json.dumps(NEUTRON_500)), 500

    new_network = {}
    new_network['id'] = req.id
    new_network['name'] = req.name
    new_network['type'] = req.type
    new_network['segmentation_id'] = req.segmentation_id
    new_network['external'] = req.external
    new_network['lcuuid'] = network_lcuuid
    new_network['userid'] = conf.livecloud_userid
    new_network['epc_id'] = network_epc_id

    try:
        with MySQLdb.connect(**DB_INFO) as cursor:
            s = ','.join(['%s' for i in range(len(new_network))])
            sql = 'INSERT INTO neutron_networks ('
            sql += ','.join(new_network.keys())
            sql += ') VALUES (' + s + ')'
            cursor.execute(sql, tuple(new_network.values()))
    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), 500

    result = req.to_primitive()

    return Response(json.dumps(result)), 200


@network_app.route(API_PREFIX + '/networks/<id>', methods=['DELETE'])
@autodoc.doc(groups=['public', __name__])
def network_delete_api(id):
    """
    Implementation Notes
        Deletes a network.

    Parameters
        networkId

    Response Messages
        HTTP Status Code    Reason          Response Model      Headers
        200                 Network deleted.
    """
    try:
        with MySQLdb.connect(**DB_INFO) as cursor:
            sql = 'SELECT * FROM neutron_networks WHERE id=%s'
            cursor.execute(sql, id)
            desc = [it[0] for it in cursor.description]
            item = cursor.fetchone()
            if item is None:
                result = {
                    "NeutronError": {
                        "message": "Network %s could not be found" % id,
                        "type": "NetworkNotFound",
                        "detail": ""
                    }
                }
                return Response(json.dumps(result)), 404
            else:
                db_network = dict(zip(desc, item))
    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), 500

    if not db_network['external']:
        data = []
        try:
            data = lcapi.get(
                conf.livecloud_url +
                '/v1/vl2s?lcuuid=' + db_network['lcuuid']).json()['DATA']
            if len(data) == 0:
                result = {
                    "NeutronError": {
                        "message": "Network %s could not be found" % id,
                        "type": "NetworkNotFound",
                        "detail": ""
                    }
                }
                return Response(json.dumps(result)), 404

            r = lcapi.delete(
                conf.livecloud_url + '/v1/vl2s/' + str(data.get('ID', 0)))
            if r.status_code != 200:
                return Response(json.dumps(NEUTRON_500)), r.status_code

        except Exception as e:
            log.error(e)
            return Response(json.dumps(NEUTRON_500)), 500

    try:
        ret, des = delete_subnet_by_networkid(id)
        if not ret:
            result = {
                "NeutronError": {
                    "message": des,
                    "type": "SubnetDeleteFail",
                    "detail": ""
                }
            }
            log.error(result)
            return Response(json.dumps(result)), 400
        with MySQLdb.connect(**DB_INFO) as cursor:
            sql = 'DELETE FROM neutron_networks WHERE id=%s'
            cursor.execute(sql, id)
    except Exception as e:
        log.error(e)
        return Response(json.dumps(NEUTRON_500)), 500

    return Response(), 200

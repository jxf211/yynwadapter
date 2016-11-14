import MySQLdb
import MySQLdb.cursors as mysqlcur

DB_INFO = {
    'host': 'localhost',
    'user': 'root',
    'passwd': 'security421',
    'db': 'livecloud_openstack',
    'connect_timeout': 1,
    'compress': 1,
    'cursorclass': mysqlcur.DictCursor,
    'charset': 'utf8'
}


LCDB_INFO = {
    'host': 'localhost',
    'user': 'root',
    'passwd': 'security421',
    'db': 'livecloud',
    'connect_timeout': 1,
    'compress': 1,
    'cursorclass': mysqlcur.DictCursor,
    'charset': 'utf8'
}


def db_delete(table=None, **kv):
    sql = 'DELETE FROM %s WHERE TRUE ' % table
    v = []
    for key in kv.keys():
        sql += "and %s=%%s " % key
        v.append(kv[key])

    with MySQLdb.connect(**DB_INFO) as cursor:
        cursor.execute(sql, tuple(v))


def port_db_delete(**kv):
    db_delete('neutron_ports', **kv)


def port_ip_db_delete(**kv):
    db_delete('neutron_port_ip', **kv)


def floatingip_db_delete(**kv):
    db_delete('neutron_floatingips', **kv)


def router_db_delete(**kv):
    db_delete('neutron_routers', **kv)


def subnet_db_delete(**kv):
    db_delete('neutron_subnets', **kv)


def port_map_db_delete(**kv):
    db_delete('portmappings', **kv)


def db_get_one(req='*', table=None, **kv):
    sql = 'SELECT %s FROM %s WHERE TRUE ' % (req, table)
    v = []
    for key in kv.keys():
        sql += "and %s=%%s " % key
        v.append(kv[key])

    with MySQLdb.connect(**DB_INFO) as cursor:
        cursor.execute(sql, tuple(v))
        item = cursor.fetchone()
    if not item:
        return None
    else:
        if req.find('*') >= 0 or req.find(',') >= 0:
            return item
        return item[req]


def db_get_all(req='*', table=None, **kv):
    sql = 'SELECT %s FROM %s WHERE TRUE ' % (req, table)
    v = []
    for key in kv.keys():
        sql += "and %s=%%s " % key
        v.append(kv[key])

    with MySQLdb.connect(**DB_INFO) as cursor:
        cursor.execute(sql, tuple(v))
        items = cursor.fetchall()
    return items


def lc_db_get_one(req='*', table=None, **kv):
    sql = 'SELECT %s FROM %s WHERE TRUE ' % (req, table)
    w = []
    for key in kv.keys():
        sql += "and %s=%%s " % key
        w.append(kv[key])

    with MySQLdb.connect(**LCDB_INFO) as cursor:
        cursor.execute(sql, tuple(w))
        item = cursor.fetchone()
    if not item:
        return None
    else:
        if req.find('*') >= 0 or req.find(',') >= 0:
            return item
        return item[req]


def lc_db_get_all(req='*', table=None, **kv):
    sql = 'SELECT %s FROM %s WHERE TRUE ' % (req, table)
    v = []
    for key in kv.keys():
        sql += "and %s=%%s " % key
        v.append(kv[key])

    with MySQLdb.connect(**LCDB_INFO) as cursor:
        cursor.execute(sql, tuple(v))
        items = cursor.fetchall()
    return items


def network_db_get_one(req='*', **kv):
    return db_get_one(req, 'neutron_networks', **kv)


def network_db_get_all(req='*', **kv):
    return db_get_all(req, 'neutron_networks', **kv)


def subnet_db_get_one(req='*', **kv):
    return db_get_one(req, 'neutron_subnets', **kv)


def subnet_db_get_all(req='*', **kv):
    return db_get_all(req, 'neutron_subnets', **kv)


def router_db_get_one(req='*', **kv):
    return db_get_one(req, 'neutron_routers', **kv)


def router_db_get_all(req='*', **kv):
    return db_get_all(req, 'neutron_routers', **kv)


def port_db_get_one(req='*', **kv):
    return db_get_one(req, 'neutron_ports', **kv)


def port_db_get_all(req='*', **kv):
    return db_get_all(req, 'neutron_ports', **kv)


def port_ip_db_get_one(req='*', **kv):
    return db_get_one(req, 'neutron_port_ip', **kv)


def port_ip_db_get_all(req='*', **kv):
    return db_get_all(req, 'neutron_port_ip', **kv)


def port_map_db_get_one(req='*', **kv):
    return db_get_one(req, 'portmappings', **kv)


def port_map_db_get_all(req='*', **kv):
    return db_get_all(req, 'portmappings', **kv)


def lcvl2uuid_to_yynetworkid(vl2uuid):
    return network_db_get_one('id', lcuuid=vl2uuid)


def subnetid_to_networkid(subnetid):
    return subnet_db_get_one('network_id', id=subnetid)


def floatingip_db_get_one(req='*', **kv):
    return db_get_one(req, 'neutron_floatingips', **kv)


def floatingip_db_get_all(req='*', **kv):
    return db_get_all(req, 'neutron_floatingips', **kv)


def portmap_db_get_one(req='*', **kv):
    return db_get_one(req, 'portmappings', **kv)


def portmap_db_get_all(req='*', **kv):
    return db_get_all(req, 'portmappings', **kv)


def portmap_db_delete(**kv):
    return db_delete('portmappings', **kv)


def lc_ip_res_db_get_one(req='*', **kv):
    return lc_db_get_one(req, 'ip_resource_v2_2', **kv)


def lc_ip_res_db_get_all(req='*', **kv):
    return lc_db_get_all(req, 'ip_resource_v2_2', **kv)


def lc_ps_db_get_one(req='*', **kv):
    return lc_db_get_one(req, 'product_specification_v2_2', **kv)


def lc_router_db_fdb_get_one(req='*', **kv):
    return lc_db_get_one(req, 'fdb_vgateway_v2_2', **kv)


def lc_vl2_db_get_one(req='*', **kv):
    return lc_db_get_one(req, 'vl2_v2_2', **kv)


def lc_vl2_net_db_get_all(req='*', **kv):
    return lc_db_get_all(req, 'vl2_net_v2_2', **kv)


def lc_vif_ip_db_get_one(req='*', **kv):
    return lc_db_get_one(req, 'vinterface_ip_v2_2', **kv)


def lc_vif_ip_db_get_all(req='*', **kv):
    return lc_db_get_all(req, 'vinterface_ip_v2_2', **kv)


def lc_vnet_db_get_one(req='*', **kv):
    return lc_db_get_one(req, 'vnet_v2_2', **kv)


def lc_vif_db_get_one(req='*', **kv):
    return lc_db_get_one(req, 'vinterface_v2_2', **kv)

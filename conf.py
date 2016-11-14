import ConfigParser
import traceback
import MySQLdb
from const import LC_CONF_FILE, DB_INFO
import copy
LC_DB_INFO = copy.copy(DB_INFO)
LC_DB_INFO['db'] = 'livecloud'

import logging

log = logging.getLogger(__name__)


class NeutronAdapaterConf(object):
    def __init__(self):
        self.local_ctrl_ip = ''
        self.livecloud_url = ''
        self.livecloud_stats_url = ''
        self.livecloud_talker_url = ''
        self.livecloud_domain = ''
        self.livecloud_order_id = ''
        self.livecloud_userid = ''

    def parse(self):
        try:
            config = ConfigParser.ConfigParser()
            with open(LC_CONF_FILE, 'r') as cfg_file:
                config.readfp(cfg_file)
                self.local_ctrl_ip = config.get('global', 'local_ctrl_ip')
                self.livecloud_url = config.get(
                    'neutronadapter', 'livecloud_url')
                self.livecloud_stats_url = config.get(
                    'neutronadapter', 'livecloud_stats_url')
                self.livecloud_talker_url = config.get(
                    'neutronadapter', 'livecloud_talker_url')
                self.livecloud_domain = config.get(
                    'neutronadapter', 'livecloud_domain')
                self.livecloud_order_id = config.get(
                    'neutronadapter', 'livecloud_order_id')

            with MySQLdb.connect(**LC_DB_INFO) as cursor:
                sql = 'SELECT id FROM fdb_user_v2_2 WHERE user_type <> 1'
                cursor.execute(sql)
                item = cursor.fetchone()
                if item is None:
                    raise Exception('Please check if exists registered users')
                self.livecloud_userid = item[0]
        except Exception as e:
            log.error('Exception: %s' % e)
            log.error('%s' % traceback.format_exc())

    def is_valid(self):
        if (not self.local_ctrl_ip or
                not self.livecloud_url or
                not self.livecloud_userid):
            self.parse()
        return self.local_ctrl_ip and \
            self.livecloud_url and \
            self.livecloud_userid

conf = NeutronAdapaterConf()

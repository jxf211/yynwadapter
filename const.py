LISTEN_PORT = 20106
MAIN_THREAD_NAME = 'MainThread'
CALLBACK_SOCKET = ('localhost', 20106)

LC_CONF_FILE = "/usr/local/livecloud/conf/livecloud.conf"
KEY_CTRL_IP = "local_ctrl_ip"
LOCALHOST = "127.0.0.1"
DB_INFO = {
    'host': 'localhost',
    'user': 'root',
    'passwd': 'security421',
    'db': 'livecloud_openstack',
    'connect_timeout': 1
}


API_TIMEOUT = 40
API_PREFIX = '/v1'

NEUTRON_500 = {
    "NeutronError": "Request Failed: internal server error "
                    "while processing your request."}
NEUTRON_400 = {
    "NeutronError": "Request Failed: bad request"}
NEUTRON_404 = {
    "NeutronError": "Request Failed: resource not found"}
NOVA_API_VERSION = '2.0'
NOVA_NOTIFY_INTERVAL = 2


HTTP_OK = 200
HTTP_CREATED = 201
HTTP_BAD_REQUEST = 400
HTTP_NOT_FOUND = 404
HTTP_INTERNAL_SERVER_ERROR = 500

VFW_TOR_LINK_NET_PRE = '172.255.255.252'
VFW_TOR_LINK_NET_MASK = 30
VFW_TOR_LINK_V = '172.255.255.253'
VFW_TOR_LINK_T = '172.255.255.254'


PORT_TYPE_ROUTER = 'neutron:router'

NAT_PROTOCOL_ANY = 0
NAT_PORT_MIN_VALUE = 1
NAT_PORT_MAX_VALUE = 65535

VGW_LAN_PORT_IFINDEX = 10
VGW_WAN_PORT_IFINDEX = 1
VGW_WAN_QOS_MIN = 20971520
VGW_WAN_QOS_MAX = 20971520
VGW_LAN_QOS_MIN = 524288000
VGW_LAN_QOS_MAX = 524288000


VL2_DEFAULT_NET_INDEX = 1
CALLBACK_WAIT_TIME = 300
NAME_MAX_LEN = 254

ROUTER_VSYS = 'FIREWALL'
ROUTER_VRF = 'SWITCH'

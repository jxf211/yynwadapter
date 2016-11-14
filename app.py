import logging
import simplejson as json

from flask import Flask

from documentation import autodoc, document
from network_app import network_app
from pat_app import pat_app
from port_app import port_app
from subnet_app import subnet_app
from router_app import router_app
from arp_app import arp_app
from callback_app import callback_app

from utils import Response

log = logging.getLogger(__name__)

app = Flask(__name__)
autodoc.init_app(app)
app.register_blueprint(document)
app.register_blueprint(network_app)
app.register_blueprint(pat_app)
app.register_blueprint(port_app)
app.register_blueprint(subnet_app)
app.register_blueprint(router_app)
app.register_blueprint(arp_app)
app.register_blueprint(callback_app)


DEFAULT_QUOTA = {
    'floatingip': 50,
    'network': 10,
    'port': 50,
    'router': 10,
    'security_group': 10,
    'security_group_rule': 100,
    'subnet': 10,
    'arp': 10,
}


@app.route('/v2.0/quotas')
@app.route('/v2.0/quotas.json')
@app.route('/v2.0/quotas/<id>')
@app.route('/v2.0/quotas/<id>.json')
def quota_get_api(id=None):
    if id is not None:
        result = {'quota': DEFAULT_QUOTA}
    else:
        result = {'quotas': []}
    return Response(json.dumps(result)), 200


@app.route('/v2.0/extensions')
@app.route('/v2.0/extensions.json')
def extension_get_api():
    return Response(json.dumps({'extensions': []})), 200


@app.route('/v2.0/floatingips')
@app.route('/v2.0/floatingips.json')
def floatingip_get_api():
    return Response(json.dumps({'floatingips': []})), 200


@app.route('/v2.0/security-groups')
@app.route('/v2.0/security-groups.json')
def security_groups_get_api():
    return Response(json.dumps({'security_groups': []})), 200

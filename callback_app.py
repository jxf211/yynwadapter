import logging
import simplejson as json

from flask import Blueprint
from flask import request

import async
from const import API_PREFIX, NEUTRON_400, HTTP_BAD_REQUEST
from utils import Response

log = logging.getLogger(__name__)
callback_app = Blueprint('callback_app', __name__)


@callback_app.route(API_PREFIX + '/callbacks/', methods=['POST'])
def callback_post_api():
    req = request.json
    if 'TASK' not in req:
        return Response(json.dumps(NEUTRON_400)), HTTP_BAD_REQUEST
    async.Results.set(req['TASK'], req)
    return Response(), 200

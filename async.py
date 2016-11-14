from collections import defaultdict
import gevent
import gevent.event as ge
from const import CALLBACK_WAIT_TIME

class Results(object):
    results = defaultdict(ge.AsyncResult)
    waiting_list = set()

    @classmethod
    def set(cls, k, v):
        cls.results[k].set(v)

    @classmethod
    def get(cls, k, block=True, timeout=None):
        if k in cls.waiting_list:
            # talker may have been restarted
            cls.results[k].set_exception(IOError('Talker restarted'))
            del cls.results[k]

        cls.waiting_list.add(k)
        r = cls.results[k].get(block, timeout)
        del cls.results[k]
        cls.waiting_list.remove(k)
        return r


def get_callback_resp(resp):
    has_callback = False
    cb_result = None
    if 'TASK' not in resp:
        return has_callback, cb_result
    if 'WAIT_CALLBACK' not in resp:
        return has_callback, cb_result
    if resp['WAIT_CALLBACK']:
        has_callback = True
        try:
            cb_result = Results.get(resp['TASK'], timeout=CALLBACK_WAIT_TIME)
        except Exception:
            pass
        finally:
            return has_callback, cb_result
    else:
        return has_callback, cb_result


def get_callback_result(resp):
    has, ret = get_callback_resp(resp)
    if not has:
        return True, ''
    if not ret:
        return False, 'Timeout'
    if ret['OPT_STATUS'] != 'SUCCESS':
        return False, ret['DESCRIPTION']
    return True, ''

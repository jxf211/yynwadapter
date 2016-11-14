import os
import sys
import logging
from logging.handlers import TimedRotatingFileHandler

from app import app


def init_logger(args=None):
    if args and args.daemon:
        handler = LcTimedRotatingFileHandler('/var/log/neutronadapter.log',
                                             when='midnight')
    else:
        handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s T%(thread)d-%(threadName)s '
                                  '%(levelname)s %(module)s.'
                                  '%(funcName)s.%(lineno)d: %(message)s')
    handler.setFormatter(formatter)

    _log_levels = {
        'app': logging.DEBUG,
        'network_app': logging.DEBUG,
        'pat_app': logging.DEBUG,
        'port_app': logging.DEBUG,
        'subnet_app': logging.DEBUG,
        'router_app': logging.DEBUG,
        'arp_app': logging.DEBUG,
        'conf': logging.DEBUG,
        '__main__': logging.DEBUG,
    }
    for logger, level in _log_levels.items():
        log = logging.getLogger(logger)
        log.setLevel(level)
        log.addHandler(handler)

    app.logger.addHandler(handler)
    app.logger.setLevel(logging.DEBUG)

    gevent_log = logging.getLogger('gevent')
    gevent_log.addHandler(handler)
    gevent_log.setLevel(logging.DEBUG)


class LcTimedRotatingFileHandler(TimedRotatingFileHandler):

    def __init__(self, *args, **kwargs):
        TimedRotatingFileHandler.__init__(self, *args, **kwargs)
        # redirect stderr to log file
        os.dup2(self.stream.fileno(), sys.stderr.fileno())

    def doRollover(self):
        TimedRotatingFileHandler.doRollover(self)
        # redirect stderr to log file
        os.dup2(self.stream.fileno(), sys.stderr.fileno())

#! /usr/bin/python

from gevent.pywsgi import WSGIServer
from gevent import monkey
monkey.patch_all()

import argparse
import os
import signal
import sys
import logging

from app import app
from conf import conf
from const import LISTEN_PORT
import logger

log = logging.getLogger(__name__)


def daemonize(stdin='/dev/null', stdout='/dev/null', stderr='/dev/stderr'):
    """
    do the UNIX double-fork magic, see Stevens' "Advanced
    Programming in the UNIX Environment" for details (ISBN 0201563177)
    http://www.erlenstar.demon.co.uk/unix/faq_2.html#SEC16
    """
    try:
        pid = os.fork()
        if pid > 0:
            # exit first parent
            sys.exit(0)
    except OSError, e:
        sys.stderr.write("fork #1 failed: %d (%s)\n" % (e.errno, e.strerror))
        sys.exit(1)

    # decouple from parent environment
    os.chdir("/")
    os.setsid()
    os.umask(0)

    # do second fork
    try:
        pid = os.fork()
        if pid > 0:
            # exit from second parent
            sys.exit(0)
    except OSError, e:
        sys.stderr.write("fork #2 failed: %d (%s)\n" % (e.errno, e.strerror))
        sys.exit(1)

    # redirect standard file descriptors
    sys.stdout.flush()
    sys.stderr.flush()
    si = file(stdin, 'r')
    so = file(stdout, 'a+')
    se = file(stderr, 'a+', 0)
    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())


def clear_up():
    log.info('Gevent ceasing ...')


def signal_handler(sig, frame):
    if sig == signal.SIGTERM:
        log.info('Terminating Neutron Adapter ...')
    elif sig == signal.SIGHUP:
        log.info('Reloading livecloud.conf ...')
        conf.parse()
        log.info('livecloud.conf reloaded.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--daemon", help="run in background",
                        action="store_true")
    parser.add_argument("-g", "--debug", help="run in debug mode",
                        action="store_true")
    args = parser.parse_args()

    logger.init_logger(args)
    if not conf.is_valid():
        sys.exit(1)

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGHUP, signal_handler)

    log.info('======== Launching Neutron Adapter ========')

    if args.daemon and os.getppid() != 1:
        daemonize()

    try:
        log.info('Gevent approaching ...')

        log.debug('Listen %s:%d' % ('0.0.0.0', LISTEN_PORT))
        server = WSGIServer(('', LISTEN_PORT), app)
        server.serve_forever()

    except KeyboardInterrupt:
        clear_up()

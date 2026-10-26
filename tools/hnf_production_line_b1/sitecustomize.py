import json
import os
import socket

_LOG = os.environ.get('HNF_PRODUCTION_LINE_NETWORK_LOG')
_orig_connect = socket.socket.connect


def _log(kind, detail):
    if _LOG:
        with open(_LOG, 'a') as handle:
            handle.write(json.dumps({'kind': kind, 'detail': str(detail)}, sort_keys=True) + '\n')


def guarded_getaddrinfo(host, port, *args, **kwargs):
    _log('dns_simulated', host)
    local = host in ('localhost', '127.0.0.1', '::1') or str(host).endswith('.local')
    ip = '127.0.0.1' if local else '93.184.216.34'
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, port or 0))]


def guarded_connect(self, address):
    if self.family in (socket.AF_INET, socket.AF_INET6):
        _log('socket_blocked', address)
        raise OSError('HNF_EXTERNAL_NETWORK_BLOCKED')
    return _orig_connect(self, address)


socket.getaddrinfo = guarded_getaddrinfo
socket.socket.connect = guarded_connect

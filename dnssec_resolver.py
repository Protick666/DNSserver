#!/usr/bin/env python
"""
LICENSE http://www.apache.org/licenses/LICENSE-2.0
"""

import argparse
import logging
import socketserver
import sys
import threading
from logging.handlers import RotatingFileHandler

from dns import message, query

index = 0

try:
    from dnslib import *
except ImportError:
    print("Missing dependency dnslib: <https://pypi.python.org/pypi/dnslib>. Please install it with `pip`.")
    sys.exit(2)


logger = logging.getLogger('my_logger')
logger.setLevel(logging.INFO)
handler = RotatingFileHandler('log/my_log.log', maxBytes=50000000, backupCount=1000)
logger.addHandler(handler)

'''
tasks 
make log dir
put container ips

'''

class DomainName(str):
    def __getattr__(self, item):
        return DomainName(item + '.' + self)

container_ips = ['172.17.0.2', '172.17.0.3', '172.17.0.4', '172.17.0.5']

def dns_response(data, client_ip, is_udp):

    if is_udp:
        cline_Str = "UDP"
    else:
        cline_Str = "TCP"

    request = DNSRecord.parse(data)

    qname = request.q.qname
    qn = str(qname)
    qtype = request.q.qtype
    qt = QTYPE[qtype]

    logger.info("Query from {} {} {}".format(client_ip, qn, qt, cline_Str))

    msg = message.from_wire(data)

    chosen_index = random.randint(0, 3)
    chosen_container_ip = container_ips[chosen_index]

    if is_udp:
        answer = query.udp(msg, chosen_container_ip)
    else:
        answer = query.tcp(msg, chosen_container_ip)
    response_as_byte_arr = bytearray(answer.to_wire())
    re_msg = DNSRecord.parse(answer.to_wire())

    logger.info("good {} {} {} {} {} {}".format(client_ip,
                                                      time.time(), chosen_container_ip, qn,
                                                                             qt, cline_Str))

    return response_as_byte_arr


class BaseRequestHandler(socketserver.BaseRequestHandler):

    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        c_ip = self.client_address[0]

        try:
            data = self.get_data()
            # print(len(data), data)  # repr(data).replace('\\x', '')[1:-1]
            self.send_data(dns_response(data=data, client_ip=c_ip, is_udp= "UDP" in str(self.server)))
        except Exception:
            pass
            # traceback.print_exc(file=sys.stderr)


class TCPRequestHandler(BaseRequestHandler):

    def get_data(self):
        data = self.request.recv(8192).strip()
        sz = struct.unpack('>H', data[:2])[0]
        if sz < len(data) - 2:
            raise Exception("Wrong size of TCP packet")
        elif sz > len(data) - 2:
            raise Exception("Too big TCP packet")
        return data[2:]

    def send_data(self, data):
        sz = struct.pack('>H', len(data))
        return self.request.sendall(sz + data)


class UDPRequestHandler(BaseRequestHandler):

    def get_data(self):
        return self.request[0]

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)


def main():
    parser = argparse.ArgumentParser(description='Start a DNS implemented in Python.')
    parser = argparse.ArgumentParser(description='Start a DNS implemented in Python. Usually DNSs use UDP on port 53.')
    parser.add_argument('--port', default=5053, type=int, help='The port to listen on.')
    parser.add_argument('--tcp', action='store_true', help='Listen to TCP connections.')
    parser.add_argument('--udp', action='store_true', help='Listen to UDP datagrams.')

    args = parser.parse_args()

    if not (args.udp or args.tcp):
        parser.error("Please select at least one of --udp or --tcp.")

    print("Starting nameserver...")

    servers = []

    if args.udp:
        servers.append(socketserver.ThreadingUDPServer(('', args.port), UDPRequestHandler))
    if args.tcp:
        servers.append(socketserver.ThreadingTCPServer(('', args.port), TCPRequestHandler))

    for s in servers:
        thread = threading.Thread(target=s.serve_forever)  # that thread will start one more thread for each request
        thread.daemon = True  # exit the server thread when the main thread terminates
        thread.start()
        print("%s server loop running in thread: %s" % (s.RequestHandlerClass.__name__[:3], thread.name))

    try:
        while 1:
            time.sleep(1)
            sys.stderr.flush()
            sys.stdout.flush()

    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            s.shutdown()


if __name__ == '__main__':
    main()

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
from threading import Lock
import random

from dns import message, query

from redis_manager import *
from tools import *

index = 0

redis_lock = Lock()

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


def dns_response(data, client_ip, is_udp):

    cline_Str = ""
    if is_udp:
        cline_Str = "UDP"
    else:
        cline_Str = "TCP"

    request = DNSRecord.parse(data)
    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)

    qname = request.q.qname
    qn = str(qname)
    qtype = request.q.qtype
    qt = QTYPE[qtype]

    if 'live_dnssec' in qn:
        reply.header.rcode = 2
        return reply.pack()

    # TODO logger thik
    logger.info("Query from {} {} {}".format(client_ip, qn, qt, cline_Str))

    # ${uuid_str}.${exp_id}.${TTL}.${domain.asn}.${bucket_number}.${URL}.com
    # abcd.zeus_dnssec.60.12.test.cashcash.app
    meta_info_list = qn.split(".")

    m_ode = -1
    ednsflag = -1
    c_ip = -1

    msg = message.from_wire(data)

    if hasattr(msg, "ednsflags"):
        ednsflag = msg.ednsflags

    query_format = None

    if len(meta_info_list) == 6 and 'signsecprobing' in qn:
        query_format = "proper"
        # choose bucket
        uuid, exp_id, ttl, asn, bucket = meta_info_list[0], \
                                         meta_info_list[1], meta_info_list[2], \
                                         meta_info_list[3], meta_info_list[4]
        mode = 1
        m_ode = mode

        if is_lum_ip(resolver_ip=client_ip):
            chosen_ip = lum_resolver_list[0]
        else:
            chosen_ip = get_ip_wrapper(resolver_ip=client_ip, uuid=uuid, ttl=ttl, redis_lock=redis_lock,
                                       logger=logger)

        c_ip = chosen_ip

        logger.info("chosen {} {} {} ".format(qn, client_ip, chosen_ip))

        if chosen_ip in ip_to_container_ip:
            chosen_container_ip = ip_to_container_ip[chosen_ip]
        else:
            chosen_container_ip = "172.17.0.4"

        logger.info("chosen cont {} {} {} ".format(qn, client_ip, chosen_container_ip))

    else:
        if 'live_dnssec' in qn:
            reply.header.rcode = 2
            return reply.pack()

        query_format = "undetected"
        chosen_index = random.randint(0, len(container_ips) - 1)
        chosen_container_ip = container_ips[chosen_index]

    if is_udp:
        answer = query.udp(msg, chosen_container_ip)
    else:
        answer = query.tcp(msg, chosen_container_ip)
    response_as_byte_arr = bytearray(answer.to_wire())
    re_msg = DNSRecord.parse(answer.to_wire())
    tc_bit = re_msg.header.tc

    logger.info("good {} {} {} {} {} {} {} {} tc: {} do: {} {}".format(query_format, client_ip,
                                                      time.time(), m_ode, c_ip, chosen_container_ip, qn,
                                                                             qt, tc_bit, ednsflag, cline_Str))

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

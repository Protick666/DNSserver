#!/usr/bin/env python
"""
LICENSE http://www.apache.org/licenses/LICENSE-2.0
"""

import argparse
import datetime
import socketserver
import sys
import threading
import time
import traceback
from metadata import *
from redis_manager import *
from tools import *
from threading import Lock
import logging
from logging.handlers import RotatingFileHandler

index = 0

redis_lock = Lock()

try:
    from dnslib import *
except ImportError:
    print("Missing dependency dnslib: <https://pypi.python.org/pypi/dnslib>. Please install it with `pip`.")
    sys.exit(2)

'''
Worries:

Is this logging best ??

Alternatives ??

Identifier: 1 -> NXDOMAIN, 2 -> SERVFAIL, 3 - EMPTY RESPONSE

'''

'''
Checking:
    see telemtert nx domain response
    log directory
    resolv file
    transfer check
    lum transfer check
    dns pulse
    local file in Pulse master
    
    TOO ** close tttl -> only consider resolvers appearing before receiving time !!!
'''

logger = logging.getLogger('my_logger')
logger.setLevel(logging.INFO)
# TODO create log directory
handler = RotatingFileHandler('log/my_log.log', maxBytes=50000000, backupCount=1000)
logger.addHandler(handler)


class DomainName(str):
    def __getattr__(self, item):
        return DomainName(item + '.' + self)


record_dict = {}
index_to_record_tuple = {}
base_domain_name = None
D = None
soa_record = None
ns_records = None
NS_IP = None


def preprocess_info(domain_name, ns_ip):
    # base_domain_name = 'securekey.app.'
    global base_domain_name, D, soa_record, ns_records, record_dict, NS_IP

    NS_IP = ns_ip
    base_domain_name = domain_name
    D = DomainName(base_domain_name)


    soa_record = SOA(
        mname=D.ns1,  # primary name server
        rname=D.hostmaster,  # email of the domain administrator
        times=(
            201307231,  # serial number
            60 * 60 * 1,  # refresh
            60 * 60 * 3,  # retry
            60 * 60 * 24,  # expire
            60 * 60 * 1,  # minimum
        )
    )

    ns_records = [NS(D.ns1), NS(D.ns2)]

    for ip in get_all_ips():
        record_tuple = {
            D: [A(ip), soa_record] + ns_records,
            D.ns1: [A(NS_IP)],  # MX and NS records must never point to a CNAME alias (RFC 2181 section 10.3)
            D.ns2: [A(NS_IP)],
            D.__getattr__("*"): [A(ip)],
        }
        record_dict[ip] = record_tuple


def dns_response(data, client_ip):
    # TODO see sudhu A record i ashe kina**
    # TODO exp id er presense dekhio: zeus_reload

    request = DNSRecord.parse(data)

    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)

    qname = request.q.qname
    qn = str(qname)
    qtype = request.q.qtype
    qt = QTYPE[qtype]

    logger.info("Query from {} {} {}".format(client_ip, qn, qt))

    if qt == 'A' and (qn == 'ns1.{}'.format(base_domain_name) or qn == 'ns2.{}'.format(base_domain_name)):
        reply.add_answer(RR(rname=qname, rtype=getattr(QTYPE, 'A'), rclass=1, ttl=3600, rdata=A(NS_IP)))
        print("Returning NS {}".format(NS_IP))
        return reply.pack()
    elif qt != 'A':
        return reply.pack()

    if 'zeus_reload' not in qn:
        # TODO return NXdomain
        logger.info("nxmal {} {} {} {}".format(client_ip, time.time(), qn, qt))
        reply.header.rcode = 3
        return reply.pack()

    if 'event-' in qn:
        logger.info("goodevent {} {} {} {} {}".format(client_ip, time.time(), "xxx", qn, qt))
        reply.header.rcode = 3
        return reply.pack()

    # TODO changes: new identifier
    # ${uuid_str}.${exp_id}.${TTL}.${domain.asn}.${bucket_number}.{$exp_mid_behaviour}.${URL}
    meta_info_list = qn.split(".")
    uuid, exp_id, ttl, asn, bucket, exp_mid_behaviour = meta_info_list[0], \
                                                        meta_info_list[1], meta_info_list[2], \
                                                        meta_info_list[3], meta_info_list[4], \
                                                        meta_info_list[5]
    ttl = int(ttl) * 60
    # 1, 2, 3
    mode = get_mode(exp_id=exp_id)

    if mode == 1:
        if is_lum_ip(resolver_ip=client_ip):
            chosen_ip = lum_resolver_list[0]
        else:
            chosen_ip = get_ip_wrapper(resolver_ip=client_ip, uuid=uuid, ttl=ttl, redis_lock=redis_lock, logger=logger)
    elif mode == 3:
        chosen_ip = phase_2_ip_list[0]
    else:
        # mode  = 2
        # Identifier: 1 -> NXDOMAIN, 2 -> SERVFAIL, 3 - EMPTY RESPONSE
        # TODO changes log format
        exp_mid_behaviour = int(exp_mid_behaviour)
        logger.info("replymid {} {} {} {} {}".format(exp_mid_behaviour, client_ip, time.time(), qn, qt))

        if exp_mid_behaviour == 1:
            reply.header.rcode = 3
        elif exp_mid_behaviour == 2:
            reply.header.rcode = 2
        elif exp_mid_behaviour == 3:
            return reply.pack()
        return reply.pack()

    chosen_record = record_dict[chosen_ip]

    if qn == D or qn.endswith('.' + D):
        for name, rrs in chosen_record.items():
            if qn.endswith('.' + name):
                for rdata in rrs:
                    rqt = rdata.__class__.__name__
                    if qt in ['*', rqt]:
                        reply.add_answer(
                            RR(rname=qname, rtype=getattr(QTYPE, rqt), rclass=1, ttl=int(ttl), rdata=rdata))

        reply.add_auth(RR(rname=D, rtype=QTYPE.SOA, rclass=1, ttl=int(ttl), rdata=soa_record))
    logger.info("good {} {} {} {} {}".format(client_ip, time.time(), chosen_ip, qn, qt))

    return reply.pack()


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
            self.send_data(dns_response(data=data, client_ip=c_ip))
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
    parser.add_argument('--base_domain', type=str, help='The base domain')
    parser.add_argument('--own_ip', type=str, help='Own IP for NS')
    parser.add_argument('--tcp', action='store_true', help='Listen to TCP connections.')
    parser.add_argument('--udp', action='store_true', help='Listen to UDP datagrams.')

    args = parser.parse_args()

    if not args.base_domain:
        parser.error("Please provide the base domain name with ")
    domain = args.base_domain

    preprocess_info(domain_name=domain, ns_ip=args.own_ip)

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

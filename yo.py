import argparse
import datetime
import sys
import time
import threading
import traceback
import socketserver
import struct

import logging
from logging.handlers import RotatingFileHandler

from tools import is_lum_ip

try:
    from dnslib import *
except ImportError:
    print("Missing dependency dnslib: <https://pypi.python.org/pypi/dnslib>. Please install it with `pip`.")
    sys.exit(2)

logger = logging.getLogger('my_logger')
logger.setLevel(logging.INFO)
# TODO create log directory
handler = RotatingFileHandler('log/my_log.log', maxBytes=100000000, backupCount=1000)
logger.addHandler(handler)


class DomainName(str):
    def __getattr__(self, item):
        return DomainName(item + '.' + self)


D = DomainName('securekey.app.')
IP = '50.16.6.90'
TTL = 60 * 5

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


records = {
    D: [A(IP), soa_record] + ns_records,
    D.ns1: [A(IP)],  # MX and NS records must never point to a CNAME alias (RFC 2181 section 10.3)
    D.ns2: [A(IP)],
    D.__getattr__("*"): [A(IP)],
}


def dns_response(data, client_ip, is_udp):

    server_type = "udp" if is_udp else "tcp"

    request = DNSRecord.parse(data)

    # print(request)

    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)


    qname = request.q.qname
    qn = str(qname)
    qtype = request.q.qtype
    qt = QTYPE[qtype]

    # reply.header.rcode = 3
    # return reply.pack()

    if qt == 'A' and (qn == 'ns1.example.com.' or qn == 'ns2.example.com.'):
        reply.add_answer(RR(rname=qname, rtype=getattr(QTYPE, 'A'), rclass=1, ttl=5 * 60, rdata=A(IP)))
        return reply.pack()
    elif qt != 'A':
        return reply.pack()

    if qn == D or qn.endswith('.' + D):

        edns_size = -1
        try:
            for e in request.ar:
                try:
                    edns_size = e.edns_len
                except:
                    pass
        except:
            pass

        if 'zeus_edns' not in qn:
            # TODO return NXdomain
            # logger.info("ednexpother {} {} {} {} {} {}".format(client_ip, time.time(), qn, qt, edns_size, server_type))
            reply.header.rcode = 3
            return reply.pack()



        if is_udp:
            if not(is_lum_ip(resolver_ip=client_ip)):
                logger.info("ednexpnorm {} {} {} {} {} {}".format(client_ip, time.time(), qn, qt, edns_size, server_type))
                reply.header.tc = 1
                return reply.pack()
            else:
                logger.info(
                    "ednexplum {} {} {} {} {} {}".format(client_ip, time.time(), qn, qt, edns_size, server_type))
        # request.ar[0].edns_len
        else:
            if not (is_lum_ip(resolver_ip=client_ip)):
                logger.info("ednexpnorm {} {} {} {} {} {}".format(client_ip, time.time(), qn, qt, edns_size, server_type))
            else:
                logger.info(
                    "ednexplumweird {} {} {} {} {} {}".format(client_ip, time.time(), qn, qt, edns_size, server_type))


        for name, rrs in records.items():
            if qn.endswith('.' + name):
                for rdata in rrs:
                    rqt = rdata.__class__.__name__
                    if qt in ['*', rqt]:
                        reply.add_answer(
                            RR(rname=qname, rtype=getattr(QTYPE, rqt), rclass=1, ttl=5 * 60, rdata=rdata))

        # for rdata in ns_records:
        #     reply.add_ar(RR(rname=D, rtype=QTYPE.NS, rclass=1, ttl=TTL, rdata=rdata))

        reply.add_auth(RR(rname=D, rtype=QTYPE.SOA, rclass=1, ttl=TTL, rdata=soa_record))

    # print("---- Reply:\n", reply)
    return reply.pack()


class BaseRequestHandler(socketserver.BaseRequestHandler):

    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
        # print("\n\n%s request %s (%s %s):" % (self.__class__.__name__[:3], now, self.client_address[0],
        #                                       self.client_address[1]))
        try:
            c_ip = self.client_address[0]
            data = self.get_data()
            # print(len(data), data)  # repr(data).replace('\\x', '')[1:-1]
            self.send_data(dns_response(data, client_ip=c_ip, is_udp= "UDP" in str(self.server)))
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
        return self.request[0].strip()

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)


def main():
    parser = argparse.ArgumentParser(description='Start a DNS implemented in Python.')
    parser = argparse.ArgumentParser(description='Start a DNS implemented in Python. Usually DNSs use UDP on port 53.')
    parser.add_argument('--port', default=5053, type=int, help='The port to listen on.')
    parser.add_argument('--tcp', action='store_true', help='Listen to TCP connections.')
    parser.add_argument('--udp', action='store_true', help='Listen to UDP datagrams.')

    args = parser.parse_args()
    # if not (args.udp or args.tcp): parser.error("Please select at least one of --udp or --tcp.")

    print("Starting nameserver...")

    servers = []

    servers.append(socketserver.ThreadingUDPServer(('', args.port), UDPRequestHandler))
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
# TODO recheck luminati resolvers
# TODO
import json

import pyasn

lum_resolvers_asn = [15169, 20473, 36692, 14061, 30607, 24940, 27725]
asndb = pyasn.pyasn('data/ipsan_db.dat')

lst = None

global_ip_to_asn = {}
lum_dict = {}
undecided_dict = {}

############################
f = open("data/all_ips.json")
d = json.load(f)
for ip in d:
    global_ip_to_asn[ip] = 1
f = open("data/lum_ips.json")
d = json.load(f)
for ip in d:
    lum_dict[ip] = 1
###########################


def get_asn(ip):
    # TODO what returns for not present??
    try:
        asn = asndb.lookup(ip)[0]
        if type(asn) != type(1):
            return None
        return asn
    except:
        return None


def look_up(resolver_ip):
    asn = get_asn(resolver_ip)
    if asn is None:
        undecided_dict[resolver_ip] = 1
        return True
    else:
        global_ip_to_asn[resolver_ip] = asn
        if int(asn) in lum_resolvers_asn:
            lum_dict[resolver_ip] = 1
            return True
        else:
            return False


def is_lum_ip(resolver_ip):
    if resolver_ip not in global_ip_to_asn:
        if resolver_ip in undecided_dict:
            return True
        return look_up(resolver_ip)
    if resolver_ip in lum_dict:
        return True
    return False

a = 1


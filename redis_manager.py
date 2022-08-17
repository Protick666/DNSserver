import redis
from local import *
from metadata import *


if LOCAL:
    redis_pass = None
else:
    redis_pass = "20092010"


# Parent change: query format, exp id, api call

# log transfer, apache fix, redis restart

'''
Phase 1 -- Sleep -- Phase 2
1 min + TTL + 1 min 

mode: key: (bucket + ttl) ttl 2 min
      return [1, 2, 3]
      
      Phase 1 -- Sleep -- Phase 2
      1      2            3      2
      
      
is_uid_served_redis: 2 min
uid_resolver_to_ip_redis: 2 min
  
uid_to_list_redis: key uid   ttl 2 min
                   return [ip1, ip2, ip3]
                   
       Phase 1 -- Sleep -- Phase 2
       1      2            3      2
                   
'''
r = redis.Redis(host='localhost', port=6379, db=0, password=redis_pass, decode_responses=True)

GLOBAL_TTL = 2 * 60
# mode_redis = redis.Redis(host='localhost', port=6379, db=1, password=redis_pass, decode_responses=True)
# uid_to_list_redis = redis.Redis(host='localhost', port=6379, db=2, password=redis_pass, decode_responses=True)
# uid_resolver_to_ip_redis = redis.Redis(host='localhost', port=6379, db=3, password=redis_pass, decode_responses=True)
# is_uid_served_redis = redis.Redis(host='localhost', port=6379, db=4, password=redis_pass, decode_responses=True)

# TODO concurrency, expire

# int return
# USE DB 1
def get_mode(exp_id):
    mode_key = "mode-" + str(exp_id)
    mode = r.get(mode_key)
    if mode is None:
        return 2
    else:
        return int(mode)


def get_ip_wrapper(resolver_ip, uuid, ttl, redis_lock):
    try:
        redis_lock.acquire(blocking=True, timeout=2)
        ans = get_ip(resolver_ip, uuid, ttl)
        redis_lock.release()
        return ans
    except:
        redis_lock.release()


# USE DB 2, 4
def get_ip(resolver_ip, uuid, ttl):
    unified_allotment_key = "allot-" + uuid + "-" + resolver_ip
    allotted_ip = r.get(unified_allotment_key)

    if allotted_ip is not None:
        return allotted_ip
    else:
        # empty lists are automatically removed
        is_uid_served_redis_key = "serve-" + str(uuid)
        is_present = r.get(is_uid_served_redis_key)
        list_key = "lst-" + uuid

        if is_present is not None:
            # not first time, already exists
            ips_left = r.lrange(list_key, 0, -1)
            if len(ips_left) == 0:
                print("queue gone, lum ip")
                r.set(unified_allotment_key, lum_resolver_list[0])
                r.expire(unified_allotment_key, GLOBAL_TTL)
                return lum_resolver_list[0]
            else:
                chosen_ip = r.lpop(list_key)
                r.set(unified_allotment_key, chosen_ip)
                r.expire(unified_allotment_key, GLOBAL_TTL)
                return chosen_ip
            # The command returns -2 if the key does not exist.
            # The command returns -1 if the key exists but has no associated expire.
        else:
            # first time
            # is_uid_served_redis.set(str(uuid), "1")
            r.set(is_uid_served_redis_key, "1")
            r.expire(is_uid_served_redis_key, GLOBAL_TTL)
            r.lpush(list_key, ip_list)
            r.expire(list_key, GLOBAL_TTL)
            chosen_ip = r.lpop(list_key)
            r.set(unified_allotment_key, chosen_ip)
            r.expire(unified_allotment_key, GLOBAL_TTL)
            return chosen_ip

a = 1
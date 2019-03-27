#!/usr/bin/python3

import codecs
import json
from urllib.request import urlopen
from socket import timeout

API_URL = 'https://stat.ripe.net/data/announced-prefixes/data.json?resource='
NAMESPACE = 'https://www.cidr-report.org/as2.0/autnums.html'
HOSTILES = [
    'MYCOMUS-AS - MY.COM US, INC.',
    'SINGLEHOP-LLC - SingleHop LLC',
    'SINGLEHOP-LLC-2 - SingleHop LLC',
    'SINGLEHOP-LLC-2 - SingleHop LLC',
    'OVH-TELECOM',
    'OVH',
    'HETZNER-AS',
    'HETZNER',
    'CUZW-CN China Unicom Zhongwei Cloud',
    'CU-CDC-SH CHINA UNICOM CLOUD DATA COMPANY LIMITED Shanghai Branch',
    'AS-CHOOPA2 - Choopa, LLC',
    'AS-CHOOPA - Choopa, LLC',
    'AS-CHOOPA3 - Choopa, LLC',
    'CHOOPAEU',
    'CHOOPALLC-AS-AP Choopa, LLC',
    'ARUBACLOUDLTD-ASN',
    'ARUBA-CLOUD-ASN',
    'ARUBA-CLOUD',
    'RedeHost Internet Ltda.',
    'VORBOSS-US - Vorboss US Inc.',
    'VORBOSS_AS'
]


import time
from functools import wraps


def retry(exceptions, tries=4, delay=3, backoff=2, logger=None):
    """
    Retry calling the decorated function using an exponential backoff.

    Args:
        exceptions: The exception to check. may be a tuple of
            exceptions to check.
        tries: Number of times to try (not retry) before giving up.
        delay: Initial delay between retries in seconds.
        backoff: Backoff multiplier (e.g. value of 2 will double the delay
            each retry).
        logger: Logger to use. If None, print.
    """
    def deco_retry(f):

        @wraps(f)
        def f_retry(*args, **kwargs):
            mtries, mdelay = tries, delay
            while mtries > 1:
                try:
                    return f(*args, **kwargs)
                except exceptions as e:
                    msg = '{}, Retrying in {} seconds...'.format(e, mdelay)
                    if logger:
                        logger.warning(msg)
                    else:
                        print(msg)
                    time.sleep(mdelay)
                    mtries -= 1
                    mdelay *= backoff
            return f(*args, **kwargs)

        return f_retry  # true decorator

    return deco_retry


#@retry(timeout, tries=4, delay=2, backoff=1)
def urlopen_with_retry(url, timeout):
    return urlopen(url) #, timeout=timeout)

def get_prefixes(asn):
    """
    Get IP Prefixes for ASN
    This API is documented on https://stat.ripe.net/docs/data_api
    """

    api_response = urlopen_with_retry(API_URL
                                      + str(asn)
                                      + '&starttime='
                                      + '2011-12-12T12:00',0)
    raw_data = str(api_response.read().decode(encoding='UTF-8'))
    api_response.close()
    json_data = json.loads(raw_data)

    prefix_list = []
    for record in json_data['data']['prefixes']:
        prefix_list.append(record['prefix'])
    return prefix_list


with codecs.open('autnums.html',
                 'r',
                 encoding='utf-8',
                 errors='ignore') as namesource:
    sourcelines = namesource.readlines()
    entries = [line.replace('\n', '') for line in sourcelines
               if line[:18] == '<a href="/cgi-bin/']

    asns = {}
    for entry in entries:
        entry, country = (entry[:-4], entry[-2:])
        entry = entry.split('>', 1)[1]
        asn, entry = entry.split('</a> ', 1)
        value = [asn, country]
        if entry not in asns.keys():
            asns[entry] = []
        asns[entry].append(value)

print('geo $manual_blocklist {')
print('    default 0;')
for desc in [desc for desc in asns if desc in HOSTILES]:
    print('\n    #', desc)
    for asn in asns[desc]:
        prefixes = get_prefixes(asn[0])
        for prefix in prefixes:
            print('    ' + str(prefix) + ' 1;')
print('}')

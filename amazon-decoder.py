#!/usr/bin/python3

import argparse
import json
import urllib.request as request

NETBLOCK = "https://ip-ranges.amazonaws.com/ip-ranges.json"


def get_aws_ranges():
    response = request.urlopen(NETBLOCK)
    json_data = response.read()
    return json_data


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Outputs an NGINX deny list for all Amazon servers, as an anti-scraping technique.", prog="amazon-decoder.py", usage="amazon-decoder.py > /etc/nginx/amazon_blocklist.conf")
    _args = parser.parse_args()
    ipranges = json.loads(get_aws_ranges())
    veefour = ipranges["prefixes"]
    veesix = ipranges["ipv6_prefixes"]
    print("geo $amazon_blocklist {")
    print("	default 0;")
    ranges = set()
    for range in veefour:
        ranges.add(range["ip_prefix"])
    for range in veesix:
        ranges.add(range["ipv6_prefix"])

    for range in ranges:
        print("	" + range + " 1;")
    print("}")

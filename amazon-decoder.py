#!/usr/bin/python3

import argparse
import json
import urllib.request as request

def get_aws_ranges():
    url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
    response = request.urlopen(url)
    json_data = response.read()
    return json_data

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Outputs an NGINX deny list for all Amazon servers, as an anti-scraping technique.", prog="amazon-decoder", usage="amazon-decoder > /etc/nginx/amazon_blocklist.conf")
    _args = parser.parse_args()
    ipranges = json.loads(get_aws_ranges())
    veefour = ipranges["prefixes"]
    veesix = ipranges["ipv6_prefixes"]
    for range in veefour:
        print("deny " + range["ip_prefix"] + ";")
    for range in veesix:
        print("deny " + range["ipv6_prefix"] + ";")

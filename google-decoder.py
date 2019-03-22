#!/usr/bin/python2

import dns.resolver
import argparse

NETBLOCK = "_cloud-netblocks.googleusercontent.com"


def return_type(itemlist, wanttype="include"):
    contents = []
    for item in itemlist:
        split_items = item.split(':', 1)
        if len(split_items) > 1:
            itemtype, itemvalue = split_items
            if itemtype == wanttype:
                contents.append(itemvalue)
    return contents


def get_response(hostname):
    response = []
    answer = dns.resolver.query(hostname, "txt")
    for data in answer:
        items = data.to_text(data).split(" ")
        for item in items:
            response.append(item.replace("\"", ""))
    return response


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Outputs an NGINX deny list for all Google Cloud servers, as an anti-scraping technique.", prog="google-decoder.py", usage="google-decoder.py > /etc/nginx/google_blocklist.conf")
    _args = parser.parse_args()
    first_request = get_response(NETBLOCK)
    includes = return_type(first_request, "include")
    addresses = []
    for include in includes:
        next_request = get_response(include)
        supplementary_includes = return_type(next_request, "include")
        if supplementary_includes:
            for new_include in supplementary_includes:
                if new_include not in includes:
                    includes.append(new_include)
        addresses += return_type(next_request, "ip4")
        addresses += return_type(next_request, "ip6")

    print("geo $google_blocklist {")
    for address in addresses:
        print("    " + str(address) + " 1;")
    print("}")

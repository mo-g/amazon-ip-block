#!/usr/bin/python3

import argparse
import xml.etree.ElementTree as xml
#import json
#import urllib.request as request

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Outputs an NGINX deny list for all Azure servers, as an anti-scraping technique.", prog="amazon-decoder", usage="azure-decoder > /etc/nginx/azure_blocklist.conf")
    _args = parser.parse_args()
    xmltree = xml.parse('PublicIPs_20190107.xml')
    xmlroot = xmltree.getroot()

    for region in xmlroot:
        for iprange in region:
            print("deny " + iprange.attrib["Subnet"] + ";")

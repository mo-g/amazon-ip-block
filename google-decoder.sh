#!/bin/bash

# Shamelessly "borrowed" from n0531m on Github.

addresses=$( for LINE in `dig txt _cloud-netblocks.googleusercontent.com +short | tr " " "\n" | grep include | cut -f 2 -d :`
do
	dig txt $LINE +short
done | tr " " "\n" | grep ip4  | cut -f 2 -d : | sort -n )

echo "geo \$google_blocklist {"
echo "    default 0;"
echo "$addresses" | while read lines ; do echo "   " "$lines" "1;" ; done
echo "}"


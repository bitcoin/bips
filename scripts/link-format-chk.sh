#!/usr/bin/env bash
#
# Copyright (c) 2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Check wrong mediawiki link format

ECODE=0
FILES=""
for fname in *.mediawiki; do
    GRES=$(grep -n '](http' $fname)
    if [ "$GRES" != "" ]; then
        if [ $ECODE -eq 0 ]; then
            >&2 echo "Github Mediawiki format writes link as [URL text], not as [text](url):"
        fi
        ECODE=1
        echo "- $fname:$GRES"
    fi
done
exit $ECODE

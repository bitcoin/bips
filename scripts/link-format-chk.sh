#!/usr/bin/env bash
#
# Copyright (c) 2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Check wrong mediawiki and markdown link formats

ECODE=0
MEDIAWIKI_ECODE=0
while IFS= read -r fname; do
    GRES=$(grep -nE '\]\((https?://|\.\./bip-|/bip-)' "$fname")
    if [ "$GRES" != "" ]; then
        if [ $MEDIAWIKI_ECODE -eq 0 ]; then
            >&2 echo "Github Mediawiki format writes links as [URL text], not as [text](URL):"
        fi
        MEDIAWIKI_ECODE=1
        ECODE=1
        while IFS= read -r line; do
            echo "- ${fname#./}:$line"
        done <<< "$GRES"
    fi
done < <(find . -type f -name '*.mediawiki' | sort)

MARKDOWN_ECODE=0
while IFS= read -r fname; do
    GRES=$(grep -nE '\[[[:space:]]*https?://[^][[:space:]]+[[:space:]]+[^][]*\]|\[\[https?://[^][]*\]\]|\[\[(\.\./|/)?bip-[^][]*\]\]' "$fname")
    if [ "$GRES" != "" ]; then
        if [ $MARKDOWN_ECODE -eq 0 ]; then
            >&2 echo "Github Markdown format writes links as [text](URL), not as [URL text] or [[URL|text]]:"
        fi
        MARKDOWN_ECODE=1
        ECODE=1
        while IFS= read -r line; do
            echo "- ${fname#./}:$line"
        done <<< "$GRES"
    fi
done < <(find . -type f -name '*.md' | sort)
exit $ECODE

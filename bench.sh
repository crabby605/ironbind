#!/usr/bin/env bash
# ./bench.sh NAME [N]: query each resolver N times, print ms. NAME=cold uses a fresh random name every query.
name=$1; n=${2:-5}
for r in "ironbind:127.0.0.1 -p 5300" "quad9:9.9.9.9" "google:8.8.8.8" "cloudflare:1.1.1.1"; do
  printf '%-12s' "${r%%:*}"
  for i in $(seq "$n"); do
    q=$name; [ "$name" = cold ] && q="c$RANDOM$RANDOM.wikipedia.org"
    dig +nocmd @${r#*:} "$q" +noall +stats +tries=1 +time=3
  done | awk '/Query time/ { t += $4; c++; printf "%6d", $4 } END { printf "   avg %6.1f ms\n", t / c }'
done

#!/bin/bash
echo "Start, stop, transactions, failed, max rtt, min rtt, avg rtt, retries, client sent, server sent, start port, stop port" > nattorture.csv
for i in {1..200}
do
  echo "Run $i"
 build/dist/bin/stunclient -i en0 192.168.1.117 -j 60 --csv >> nattorture.csv
done

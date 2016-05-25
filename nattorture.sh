#!/bin/bash

#usage ./nattorture.sh [interface[] [ip] [number of runs] [outfile]

# A POSIX variable
OPTIND=1         # Reset in case getopts has been used previously in the shell.

# Initialize our own variables:

interface="eth0"
ip=""
runs=10
output_file="out.csv"
test_name="test"

lockfile=nattorture.lock

touch $lockfile

while getopts "h?i:f:r:o:t:" opt; do
    case "$opt" in
    h|\?)
        show_help
        exit 0
        ;;
    r)  runs=$OPTARG
        ;;
    i)  interface=$OPTARG
        ;;
    f)  output_file=$OPTARG
        ;;
    t)  test_name=$OPTARG
        ;;
    esac
done

shift $((OPTIND-1))

[ "$1" = "--" ] && shift

ip=$@
echo "interface=$interface, output_file='$output_file',runs='$runs', ip: $ip"

rm output_file
printf "Name, run, Start, stop, transactions, failed, max rtt, min rtt, avg rtt, retries, client sent, server sent, start port, stop port\n" > $output_file
for (( i=1; i<=$runs; i++ ))
do
  echo "Run $i"
  printf "$test_name, $i, " >> $output_file
 build/dist/bin/stunclient -i $interface $ip -j 60 --csv >> $output_file
done

rm $lockfile

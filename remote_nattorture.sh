#!/bin/bash

filename=ip_list.conf
stun_server=pem@192.168.1.10

if [ ! -f $filename ]; then
    echo "No Raspberry IPs found. Running nmap (requires sudo)"
    ./ip_list_update.sh
fi
#start the stun server(s)

ssh -n -f $stun_server "sh -c 'cd /home/pem/development/stunserver/; nohup ./nattorture_start.sh -i eth0 -f nattorture.csv > /dev/null 2>&1 &'"

while read -r ip
do
    echo "Starting job on: $ip"
    ssh -n -f pi@$ip "sh -c 'cd /home/pi/development/stunclient/; nohup ./nattorture.sh -i eth0 -r 400 -f nattorture.csv 192.168.1.10> /dev/null 2>&1 &'"
done < "$filename"

echo "Waiting for server to finish.."
ssh $stun_server 'cd /home/pem/development/stunserver; ./doneyet.sh'

mkdir pack
while read -r ip
do
    echo "Retrieving client logs: $ip"
    scp pi@$ip:/home/pi/development/stunclient/nattorture.csv pack/"$ip"_nattorture.csv
done < "$filename"

echo "Retrieving server log"
scp $stun_server:/home/pem/development/stunserver/nattorture.csv pack/server_nattorture.csv

echo "Packing up"
cd pack
tar -cvzf  ../nattorture.tar.gz *.csv
cd ..
rm -rf pack

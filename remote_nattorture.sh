#!/bin/bash

#ips=$(sudo nmap -sP 192.168.0.1/24 | awk '/^Nmap/ { printf $5" " } /MAC/ { print }' - | grep Raspberry |awk '{print $1}')
filename=ip_list.conf
if [ ! -f $filename ]; then
    echo "No Raspberry IPs found. Running nmap (requires sudo)"
    ./ip_list_update.sh
fi

while read -r ip
do
    echo $ip
    ssh -n -f pi@$ip "sh -c 'cd /home/pi/development/stunclient/; nohup ./nattorture.sh -i eth0 -r 400 -f nattorture.csv 192.168.1.10> /dev/null 2>&1 &'"
done < "$filename"

#ips="192.168.0.106 192.168.0.102 192.168.0.103 192.168.0.100"
#for i in $ips; do
#  ssh -n -f pi@$i "sh -c 'cd /home/pi/development/stunclient/; nohup ./nattorture.sh -i eth0 -r 400 -f nattorture.csv 192.168.1.10> /dev/null 2>&1 &'"
#done

#ssh -n -f pi@192.168.0.106 "sh -c 'cd /home/pi/development/stunclient/; nohup ./nattorture.sh -i eth0 -r 400 -f nattorture.csv 192.168.1.10> /dev/null 2>&1 &'"
#ssh -n -f pi@192.168.0.102 "sh -c 'cd /home/pi/development/stunclient/; nohup ./nattorture.sh -i eth0 -r 400 -f nattorture.csv 192.168.1.10> /dev/null 2>&1 &'"
#ssh -n -f pi@192.168.0.103 "sh -c 'cd /home/pi/development/stunclient/; nohup ./nattorture.sh -i eth0 -r 400 -f nattorture.csv 192.168.1.10> /dev/null 2>&1 &'"

#Start one loccaly as well
#./nattorture.sh -i en0 -r 400 -o nattorture.csv 192.168.1.10
#done

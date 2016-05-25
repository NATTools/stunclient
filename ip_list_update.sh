
#!/bin/bash
filename=ip_list.conf
sudo nmap -sP 192.168.0.1/24 | awk '/^Nmap/ { printf $5" " } /MAC/ { print }' - | grep Raspberry | awk '{ print $1 }' >$filename


while read -r ip
do
    echo $ip
done < "$filename"

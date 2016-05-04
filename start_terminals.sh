#!/bin/bash

filename=ip_list.conf
script_file=term.scpt
x=850
y=400
startx=800
starty=160
i=0
j=0

if [ ! -f $filename ]; then
    echo "No Raspberry IPs found. Running nmap (requires sudo)"
    ./ip_list_update.sh
fi

while read -r ip
do
  this_ip=$ip
  echo "tell app \"Terminal\" ">$script_file
  echo "do script \"ssh pi@$ip \\\"tail -f development/stunclient/nattorture.csv\\\"\"">>$script_file
  echo "tell window 1">>$script_file
  echo "set size to {$x, $y}">>$script_file
  echo "set position to {$((startx+i*x)), $((starty+j*y))}">>$script_file
  echo "end tell">>$script_file
  echo "end tell">>$script_file
  echo "">>$script_file
  echo "">>$script_file

  i=$((i+1))
  if (($i > 1)); then
    i=0;
    j=$((j+1))
  fi
  osascript $script_file
  #rm term.scpt

done < "$filename"

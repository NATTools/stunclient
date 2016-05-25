
sudo apt-get install build-essential
sudo apt-get install checkinstall

wget http://www.cmake.org/files/v3.5/cmake-3.5.2.tar.gz
tar xf cmake-3.5.2.tar.gz
cd cmake-3.5.2
./configure
make
sudo checkinstall

sudo apt-get install libbsd-dev
sudo apt-get install libssl-dev

sudo nmap -sP 192.168.0.1/24 | awk '/^Nmap/ { printf $5" " } /MAC/ { print }' - | grep Raspberry

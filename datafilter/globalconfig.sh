#!/bin/sh
echo "deleting old build"
sudo rm -rf /usr/src/linux-headers-`uname -r`/
echo "OK"

echo "generating headers"
cd /home/giogge/linux 
make headers_install
echo "OK"

echo "creating new include headers folder"
sudo mkdir /usr/src/linux-headers-`uname -r`
sudo cp -r /home/giogge/linux/include/ /usr/src/linux-headers-`uname -r`/
echo "OK"

echo "creating new arch headers folder"
sudo mkdir /usr/src/linux-headers-`uname -r`/arch
sudo mkdir /usr/src/linux-headers-`uname -r`/arch/x86
sudo cp -r /home/giogge/linux/arch/x86/include/ /usr/src/linux-headers-`uname -r`/arch/x86/
echo "OK"
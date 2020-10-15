## guide to setup bpf infrastructure

I use a ubuntu 18.4 server virtual machine with kvm ( https://releases.ubuntu.com/18.04/ ) with 120GB HDD and 16GB of RAM

After installation, I get the ip address with
```
virsh net-dhcp-leases default
```

install dependencies
```
sudo apt-get install gcc clang llc llvm
sudo apt-get install ibncurses-dev flex bison openssl libssl-dev dkms libelf-dev libudev-dev libpci-dev libiberty-dev autoconf

```
clone the git repositories

```
git clone --branch stable5.7 https://github.com/giuliafrascaria/linux.git
git clone https://github.com/giuliafrascaria/ebpf-data-filter.git
git clone https://github.com/libbpf/libbpf
```
build libbpf and copy /libbpf/src/ in /ebpf-data-filter/datafilter/libbpf/src/

checkout the tag and compile linux with the given config file for the bpf flags
```
make oldconfig
make
sudo make modules_install
sudo make install

```
I edit my /etc/default/grub file like this so I always can choose the kernel to boot from, just in case
```
GRUB_DEFAULT=0
#GRUB_TIMEOUT_STYLE=hidden
GRUB_TIMEOUT=-1
GRUB_DISTRIBUTOR=`lsb_release -i -s 2> /dev/null || echo Debian`
GRUB_CMDLINE_LINUX_DEFAULT="maybe-ubiquity"
GRUB_CMDLINE_LINUX=""
GRUB_SAVEDEFAULT=true
GRUB_DEFAULT=saved
```

reboot and then from the linux folder create the new global and local headers
```
make headers_install

sudo mkdir /usr/src/linux-headers-`uname -r`
sudo mkdir /usr/src/linux-headers-`uname -r`/arch
sudo mkdir /usr/src/linux-headers-`uname -r`/arch/x86

sudo cp -r include/ /usr/src/linux-headers-`uname -r`/
sudo cp -r arch/x86/include/ /usr/src/linux-headers-`uname -r`/arch/x86/
```

if all goes as expected the script ./make.sh should work
the compiled files are in /compiled. the bug happens in ./override_exec and is benchmarked in ./iter.sh

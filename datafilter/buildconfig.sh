#!/bin/sh


echo "creating own copy of hdr"
rm -rf /home/giogge/thesis/ebpf-experiments/57/usr/include/
cp -r /home/giogge/linux/usr/include/ /home/giogge/thesis/ebpf-experiments/57/usr/
echo "OK"

echo "creating own copy of tools folder"
rm -rf /home/giogge/thesis/ebpf-experiments/57/tools/
cp -r /home/giogge/linux/tools/ /home/giogge/thesis/ebpf-experiments/57/
echo "OK"

#echo "copying bpf fundamentals"
#cp /home/giogge/thesis/ebpf-experiments/fundamentals/* /home/giogge/thesis/ebpf-experiments/57/
#echo "OK"


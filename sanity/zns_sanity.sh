#!/bin/bash
rm sanity*.txt
printf "\n Delete zones and create new zone and format\n"
sudo nvme delete-ns /dev/nvme1 -n 0xffffffff
sudo nvme create-ns /dev/nvme1 -s 0x100000 -c 0x100000 -f 0 --csi 0   
sudo nvme attach-ns /dev/nvme1 -c 0 -n 1
sudo nvme create-ns /dev/nvme1 -s 0xE2800000 -c 0xE2800000 -f 0 --csi 2 #906 zones
sudo nvme attach-ns /dev/nvme1 -c 0 -n 2
#sleep 5
sudo nvme format /dev/nvme1 -n 0xffffffff -l 0 -f -r
printf "\n start two_ns_bbc_bbz_512b_format.fio\n"
fio two_ns_bbc_bbz_512b_format.fio --output=sanity.txt
if [ $? != 0 ] ; 
then
  exit 1
fi
printf "\n starting zns_fio_sanity.py\n"
python2 zns_fio_sanity.py -c /dev/nvme1
if [ $? != 0 ] ; 
then
  exit 1
fi
exit 0

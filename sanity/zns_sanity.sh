#!/bin/bash
rm sanity*.txt
printf "\n Delete zones and create new namespaces with 300 zone and format\n"
nvme delete-ns /dev/nvme1 -n 0xffffffff
nvme create-ns -s 0x9600000 -c 0x9600000 /dev/nvme1 -f 2 --csi 2  #300 zones
nvme attach-ns /dev/nvme1 -c 0 -n 1
sleep 5
nvme format /dev/nvme1n1 -l 2 -f
nvme create-ns -s 0x9600000 -c 0x9600000 /dev/nvme1 -f 2 --csi 2  #300 zones
nvme attach-ns /dev/nvme1 -c 0 -n 2
sleep 5
nvme format /dev/nvme1n2 -l 2 -f
printf "\n starting zns_rand_zone_4tb_full_drive_write_2pcOW_12z_2ns\n"
fio zns_rand_zone_4tb_full_drive_write_2pcOW_12z_2ns.fio --output=sanity.txt
if [ $? != 0 ] ; 
then
  exit 1
fi
nvme zns reset-zone /dev/nvme1n1 -a -s 0 -n 1
nvme zns reset-zone /dev/nvme1n2 -a -s 0 -n 2
printf "\n starting zns_rand_zone_4tb_full_drive_write_2pcOW_12z.fio\n"
fio zns_rand_zone_4tb_full_drive_write_2pcOW_12z.fio --output=sanity.txt
if [ $? != 0 ] ; 
then
  exit 1
fi
nvme zns reset-zone /dev/nvme1n1 -a -s 0 -n 1
nvme zns reset-zone /dev/nvme1n2 -a -s 0 -n 2
printf "\n starting zns_rand_zone_4tb_full_drive_write_2pcOW_12z_e.fio\n"
fio zns_rand_zone_4tb_full_drive_write_2pcOW_12z_e.fio --output=sanity.txt
if [ $? != 0 ] ; 
then
  exit 1
fi
printf "\n Delete zones and create new namespace with 300 zones and format\n"
nvme delete-ns /dev/nvme1 -n 0xffffffff
nvme create-ns -s 0x9600000 -c 0x9600000 /dev/nvme1 -f 2 --csi 2  #300 zones
nvme attach-ns /dev/nvme1 -c 0 -n 1
sleep 5
nvme format /dev/nvme1n1 -l 2 -f
echo "none" | tee /sys/block/nvme1n1/queue/scheduler
printf "\n starting bs128k_zrwa.fio\n"
fio bs128k_zrwa.fio --output=sanity.txt
if [ $? != 0 ] ; 
then
  printf "\n bs128k_zrwa.fio failed\n"
  exit 1
fi
echo "mq-deadline" | tee /sys/block/nvme1n1/queue/scheduler
printf "\n starting seq_readwrite_5o_pct_timed.fio\n"
fio seq_readwrite_5o_pct_timed.fio --output=sanity.txt
if [ $? != 0 ] ; 
then
  printf "\n seq_readwrite_5o_pct_timed.fio failed\n"
  exit 1
fi
nvme zns reset-zone /dev/nvme1n1 -a -s 0 -n 1
echo "none" | tee /sys/block/nvme1n1/queue/scheduler
printf "\n starting explicit_commit_64k_256qd.fio\n"
fio explicit_commit_64k_256qd.fio --output=sanity.txt
if [ $? != 0 ] ; 
then
  printf "\n explicit_commit_64k_256qd.fio failed\n"
  exit 1
fi
printf "\n Delete zones and create new namespace with 600 zones and format\n"
nvme delete-ns /dev/nvme1 -n 0xffffffff
nvme create-ns -s 0x12C00000 -c 0x12c00000 /dev/nvme1 -f 2 --csi 2  #600 zones
nvme attach-ns /dev/nvme1 -c 0 -n 1
sleep 5
nvme format /dev/nvme1n1 -l 2 -f
echo "none" | tee /sys/block/nvme1n1/queue/scheduler
printf "\n starting zns_implicit_full_drive_write_1pcoverwrite_12z_e_pct\n"
fio zns_implicit_full_drive_write_1pcoverwrite_12z_e_pct.fio --output=sanity.txt
if [ $? != 0 ] ; 
then
  printf "\n zns_implicit_full_drive_write_1pcoverwrite_12z_e_pct failed\n"
  exit 1
fi
echo  "none" | tee /sys/block/nvme1n1/queue/scheduler
printf "\n starting per_job_parameters.fio\n"
fio per_job_parameters.fio --output=sanity.txt
if [ $? != 0 ] ; 
then
  printf "\n per_job_parameters.fio failed\n"
  exit 1
fi
echo  "none" | tee /sys/block/nvme1n1/queue/scheduler
printf "\n starting per_job_parameters_num_jobs.fio\n"
fio per_job_parameters_num_jobs.fio --output=sanity.txt
if [ $? != 0 ] ; 
then
  printf "\n per_job_parameters_num_jobs.fio failed\n"
  exit 1
fi
echo "mq-deadline" | tee /sys/block/nvme1n1/queue/scheduler
printf "\n starting zns_random_full_drive_write_12z\n"
fio  zns_random_full_drive_write_12z.fio --output=sanity.txt
if [ $? != 0 ] ; 
then
  printf "\n zns_random_full_drive_write_12z failed\n"
  exit 1
fi
nvme zns reset-zone /dev/nvme1n1 -a -s 0 -n 1
printf "\n starting zns_random_full_drive_write_14z_e\n"
fio  zns_random_full_drive_write_14z_e.fio --output=sanity.txt
if [ $? != 0 ] ; 
then
  printf "\n zns_random_full_drive_write_14z_e failed\n"
  exit 1
fi
nvme zns reset-zone /dev/nvme1n1 -a -s 0 -n 1
printf "\n starting zns_random_full_drive_write_12z_finish\n"
fio  zns_random_full_drive_write_12z_finish.fio --output=sanity.txt
if [ $? != 0 ] ; 
then
  exit 1
fi
nvme zns reset-zone /dev/nvme1n1 -a -s 0 -n 1
echo "none" | tee /sys/block/nvme1n1/queue/scheduler
printf "\n starting zns_implicit_full_drive_write_2pcoverwrite.fio\n"
fio  zns_implicit_full_drive_write_2pcoverwrite.fio --output=sanity.txt
if [ $? != 0 ] ; 
then
  exit 1
fi
printf "\n starting zns_implicit_full_drive_write.fio\n"
fio  zns_implicit_full_drive_write.fio --output=sanity.txt    #reset_all_zones_first
if [ $? != 0 ] ; 
then
  exit 1
fi
nvme zns reset-zone /dev/nvme1n1 -a -s 0 -n 1
printf "\n Starting random_wl\n"
fio  random_wl.fio --output=sanity.txt
if [ $? != 0 ] ; 
then
  exit 1
fi
printf "\n starting zns_implicit_full_drive_write_1pcoverwrite.fio \n"
fio  zns_implicit_full_drive_write_1pcoverwrite.fio  --output=sanity.txt
if [ $? != 0 ] ; 
then
  exit 1
fi
nvme zns reset-zone /dev/nvme1n1 -a -s 0 -n 1
printf "\n starting zns_implicit_full_drive_write_1pcrandow.fio \n"
fio  zns_implicit_full_drive_write_1pcrandow.fio  --output=sanity.txt
if [ $? != 0 ] ; 
then
  exit 1
fi
nvme zns reset-zone /dev/nvme1n1 -a -s 0 -n 1
printf "\n starting zrwa_seq_write_6_jobs.fio \n"
fio  zrwa_seq_write_6_jobs.fio --output=sanity.txt --output=sanity.txt
if [ $? != 0 ] ; 
then
  exit 1
fi
nvme zns reset-zone /dev/nvme1n1 -a -s 0 -n 1
printf "\n starting open_zone_assert.fio.fio \n"
fio  open_zone_assert.fio --output=sanity.txt
if [ $? != 0 ] ; 
then
  exit 1
fi
nvme zns reset-zone /dev/nvme1n1 -a -s 0 -n 1
echo "mq-deadline" | tee /sys/block/nvme1n1/queue/scheduler
printf "\n zns_random_full_drive_write_12z_timed.fio \n"
fio  zns_random_full_drive_write_12z_timed.fio --output=sanity.txt
if [ $? != 0 ] ; 
then
 exit 1
fi
echo "none" | tee /sys/block/nvme1n1/queue/scheduler
nvme zns reset-zone /dev/nvme1n1 -a -s 0 -n 1
printf "\n start zns_implicit_full_drive_write_1pcoverwrite_12z.fio \n"
fio  zns_implicit_full_drive_write_1pcoverwrite_12z.fio --output=sanity.txt 
if [ $? != 0 ] ; 
then
  exit 1
fi
nvme zns reset-zone /dev/nvme1n1 -a -s 0 -n 1
printf "\n start zns_implicit_full_drive_write_1pcoverwrite_12z_e.fio \n"
fio  zns_implicit_full_drive_write_1pcoverwrite_12z_e.fio --output=sanity.txt   
if [ $? != 0 ] ; 
then
  exit 1
fi
nvme zns reset-zone /dev/nvme1n1 -a -s 0 -n 1
printf "\n start zns_implicit_full_drive_write_12z.fio\n"
fio  zns_implicit_full_drive_write_12z.fio --output=sanity.txt
if [ $? != 0 ] ; 
then
  exit 1
fi
nvme zns reset-zone /dev/nvme1n1 -a -s 0 -n 1
printf "\n start zns_implicit_full_drive_write_12z_e.fio\n"
fio  zns_implicit_full_drive_write_12z_e.fio --output=sanity.txt
if [ $? != 0 ] ; 
then
  exit 1
fi
echo "mq-deadline" | tee /sys/block/nvme1n1/queue/scheduler
nvme zns reset-zone /dev/nvme1n1 -a -s 0 -n 1
printf "\n start zns_sequential_full_drive_write.fio\n"
fio  zns_sequential_full_drive_write.fio --output=sanity.txt
if [ $? != 0 ] ; 
then
  exit 1
fi
nvme zns reset-zone /dev/nvme1n1 -a -s 0 -n 1
printf "\n start full-drive-sequential-write.fio\n"
fio  full-drive-sequential-write.fio  --output=sanity.txt 
if [ $? != 0 ] ; 
then
  exit 1
fi
echo "none" | tee /sys/block/nvme1n1/queue/scheduler
nvme zns reset-zone /dev/nvme1n1 -a -s 0 -n 1
printf "\n start write_wl_holes.fio\n"
fio  write_wl_holes.fio  --output=sanity.txt 
if [ $? != 0 ] ; 
then
  exit 1
fi
nvme zns reset-zone /dev/nvme1n1 -a -s 0 -n 1
printf "\n start Random_Mixed.fio\n"
fio  Random_Mixed.fio --output=sanity.txt
if [ $? != 0 ] ; 
then
  exit 1
fi
nvme zns reset-zone /dev/nvme1n1 -a -s 0 -n 1
printf "\n start mixed_multiple_zones.fio\n"
fio  mixed_multiple_zones.fio --output=sanity.txt
if [ $? != 0 ] ; 
then
  exit 1
fi
nvme zns reset-zone /dev/nvme1n1 -a -s 0 -n 1
printf "\n start unaligned_workloads.fio\n"
fio  unaligned_workloads.fio --output=sanity.txt
if [ $? != 0 ] ; 
then
  exit 1
fi
nvme zns reset-zone /dev/nvme1n1 -a -s 0 -n 1
printf "\n start 1job_4activeZone_5pcOW_empty_first.fio\n"
fio  1job_4activeZone_5pcOW_empty_first.fio --output=sanity.txt
if [ $? != 0 ] ; 
then
  exit 1
fi
nvme zns reset-zone /dev/nvme1n1 -a -s 0 -n 1
echo "mq-deadline" | tee /sys/block/nvme1n1/queue/scheduler
printf "\n start random_14_zones_260k.fio\n"
fio  random_14_zones_260k.fio --output=sanity.txt
if [ $? != 0 ] ; 
then
  exit 1
fi
nvme zns reset-zone /dev/nvme1n1 -a -s 0 -n 1
echo "mq-deadline" | tee /sys/block/nvme1n1/queue/scheduler
printf "\n start random_14_zones_64k.fio\n"
fio  random_14_zones_64k.fio --output=sanity.txt
if [ $? != 0 ] ; 
then
  exit 1
fi
nvme zns reset-zone /dev/nvme1n1 -a -s 0 -n 1
echo "mq-deadline" | tee /sys/block/nvme1n1/queue/scheduler
printf "\n start non_zrwa_workload.fio\n"
fio  non_zrwa_workload.fio --output=sanity.txt
if [ $? != 0 ] ; 
then
  exit 1
fi
echo "none" | tee /sys/block/nvme1n1/queue/scheduler
printf "\n start zrwa_workload.fio.fio\n"
fio  zrwa_workload.fio --output=sanity.txt
if [ $? != 0 ] ; 
then
  exit 1
fi
printf "\n Delete zones and create new namespace with 36 zones and format\n"
nvme delete-ns /dev/nvme1 -n 0xffffffff
nvme create-ns -s 0x1200000 -c 0x1200000 /dev/nvme1 -f 2 --csi 2  #36 zones
nvme attach-ns /dev/nvme1 -c 0 -n 1
sleep 5
nvme format /dev/nvme1n1 -l 2 -f
echo "none" | tee /sys/block/nvme1n1/queue/scheduler
printf "\n start multiple_job_seq_write.fio\n"
fio multiple_job_seq_write.fio --output=sanity.txt
if [ $? != 0 ] ; 
then
  exit 1
fi
printf "\n start multiple_job_seq_write_num_zones.fio\n"
fio multiple_job_seq_write_num_zones.fio --output=sanity.txt
if [ $? != 0 ] ; 
then
  exit 1
fi
echo "mq-deadline" | sudo tee /sys/block/nvme1n1/queue/scheduler
printf "\n start num_zones_seq_write_2_jobs.fio\n"
fio num_zones_seq_write_2_jobs.fio --output=sanity.txt
if [ $? != 0 ] ; 
then
  exit 1
fi
echo "none" | tee /sys/block/nvme1n1/queue/scheduler
printf "\n start num_zones_seq_write_2_jobs_zrwa.fio\n"
fio num_zones_seq_write_2_jobs_zrwa.fio --output=sanity.txt
if [ $? != 0 ] ; 
then
  exit 1
fi
printf "\n start num_zones_rand_write_2_jobs_zrwa.fio\n"
fio num_zones_rand_write_2_jobs_zrwa.fio --output=sanity.txt
if [ $? != 0 ] ; 
then
  exit 1
fi
printf "\n Delete zones and create new zone and format\n"
nvme delete-ns /dev/nvme1 -n 0xffffffff
nvme create-ns -s 0x80000 -c 0x80000 /dev/nvme1 -b 4096 -csi 0  
nvme attach-ns /dev/nvme1 -c 0 -n 1
nvme create-ns -s 0x1200000 -c 0x1200000 /dev/nvme1 -f 2 --csi 2  #36 zones
nvme attach-ns /dev/nvme1 -c 0 -n 2
sleep 5
nvme format /dev/nvme1n1 -l 2 -f
sleep 5
nvme format /dev/nvme1n2 -l 2 -f
printf "\n start two_ns_bbc_bbz.fio\n"
fio two_ns_bbc_bbz.fio --output=sanity.txt
if [ $? != 0 ] ; 
then
  exit 1
fi
echo "mq-deadline" | tee /sys/block/nvme1n2/queue/scheduler
nvme zns reset-zone /dev/nvme1n2 -a -s 0 -n 2
printf "\n start rand_bssplit_1st_half.fio\n"
fio rand_bssplit_1st_half.fio --output=sanity.txt
if [ $? != 0 ] ; 
then
  exit 1
fi
printf "\n start rand_bssplit_2nd_half.fio\n"
echo "mq-deadline" | tee /sys/block/nvme1n2/queue/scheduler
fio rand_bssplit_2nd_half.fio --output=sanity.txt
if [ $? != 0 ] ; 
then
  exit 1
fi
printf "\n start conv_ns_randwrite.fio\n"
fio conv_ns_randwrite.fio --output=sanity.txt
if [ $? != 0 ] ; 
then
  exit 1
fi
echo "none" | tee /sys/block/nvme1n2/queue/scheduler
printf "\n start fill_all_36_zones_zrwa.fio\n"
fio fill_all_36_zones_zrwa.fio --output=sanity.txt
if [ $? != 0 ] ; 
then
  exit 1
fi
printf "\n Delete zones and create new zone and format\n"
sudo nvme delete-ns /dev/nvme1 -n 0xffffffff
sudo nvme create-ns -s 0x600000 -c 0x600000 /dev/nvme1 -f 2 --csi 2  #12 zones
sudo nvme attach-ns /dev/nvme1 -c 0 -n 1
sleep 5
sudo nvme format /dev/nvme1n1 -l 2 -f
echo "mq-deadline" | tee /sys/block/nvme1n1/queue/scheduler
printf "\n start zonesize_zonerange.fio.fio\n"
fio zonesize_zonerange.fio --output=sanity.txt
if [ $? != 0 ] ; 
then
  exit 1
fi
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

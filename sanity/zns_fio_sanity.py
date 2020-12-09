#!/usr/bin/env python

import argparse
import os
import subprocess
import sys
import time

#4096 Tests
class FIO_TESTS:

    def __init__(self, zns, cns=None):
        self.zns = zns
        self.cns = cns
        self.ns_id = int(zns[11:])
        self.format_namespace(self.zns)
        self.total_zones = self.get_empty_zones()

    #Formats the given namespace
    def format_namespace(self, ns):
        cmd = ("nvme format {} -b 4096 -f".format(ns))
        print("Formatting namespace")
        os.system(cmd)
    
    # Switches the ioscheduler to the given one
    def scheduler_switch(self, scheduler, path):
        try:
            subprocess.check_call("echo {} > /sys/block{}/queue/scheduler".format(scheduler, path), shell=True)
            print("Scheduler switched to {}".format(scheduler))
        except subprocess.CalledProcessError:
            raise Exception("Scheduler switch failed \n")
    
    def run_fio(self, bs, iodepth, runtime, readwrite, rwmixread, max_open_zones=12, io_size=None, size=None, zrwa=0, overwrite_percentage=0, exp_commit=0):
        zone_params = ''
        time_params = ''
        zone_params += ' --zonemode=zbd --max_open_zones={}'.format(max_open_zones)
        if size!=None:
            zone_params += ' --size={}'.format(size)
        if io_size!=None:
            zone_params += ' --io_size={}'.format(io_size)
        if zrwa:
            zone_params += ' --zrwa_alloc=1 --ns_id={} --issue_zone_finish=1 --zrwa_overwrite_percent={}'.format(self.ns_id, overwrite_percentage)
            if exp_commit:
                zone_params += ' --commit_gran=16384 --exp_commit={}'.format(exp_commit)

        path = self.zns.replace("/dev", "")
        #zrwa uses 'none' scheduler and non-zrwa 'mq-dealine' scheduler
        if zrwa:
            self.scheduler_switch('none', path)
        else:
            self.scheduler_switch('mq-deadline', path)
        #Format before every run
        self.format_namespace(self.zns)
        if runtime:
            time_params += ' --time_based --runtime={}'.format(runtime)
            start_time = time.time()
        fio_cmd = 'fio --direct=1 --rw={} --rwmixread={} --bs={} --iodepth={} --ioengine=libaio --name={} --filename={}'.format(readwrite, rwmixread, bs, iodepth, self.zns, self.zns)
        fio_cmd += time_params + zone_params
        print('Running the following command:\n' + fio_cmd + '\n')
        proc = subprocess.Popen(fio_cmd, shell=True, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
        output =  proc.stdout.read().decode('utf-8')
        print(output)
        if(runtime):
            execution_time = int(time.time() - start_time)
            if(execution_time - runtime <= 2):
                print("\n FIO ran successfully for expected given time! \n")
            else:
                print("\n FIO didnt run for given time! \n")
                sys.exit(1)
        if (output.find('err= 0') != -1):
            print ("\n ####  FIO RUN PASSED #### \n")
        else:
            print ("\n ####  FIO RUN FAILED #### \n")
            sys.exit(1)

    def get_empty_zones(self):
        cmd = ("nvme zns report-zones {} -s 0 | grep -c EMPTY".format(self.zns))
        proc = subprocess.Popen(cmd, shell=True, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
        return int(proc.stdout.read())

    def get_open_zones(self):
        cmd = ("nvme zns report-zones {}  -s 0 | grep -c OPEN".format(self.zns))
        proc = subprocess.Popen(cmd, shell=True, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
        return int(proc.stdout.read())

    def get_full_zones(self):
        cmd = ("nvme zns report-zones {} -s 0 | grep -c FULL".format(self.zns))
        proc = subprocess.Popen(cmd, shell=True, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
        return int(proc.stdout.read())

    def get_zone_state_counts(self, full_zones, empty_zones, open_zones):
        print("Number of FULL zones: {} \n".format(full_zones))
        print("Number of OPEN zones: {} \n".format(open_zones))
        print("Number of EMPTY zones: {} \n".format(empty_zones))


class Multinamespace_Tests(FIO_TESTS):
    # Test Description: The test runs two separate jobs on the drive having 1 cns and 1 zns configuration.
    #                   Run time for both jobs is 60 seconds
    #                   First job is a write workload that runs on CNS with iodepth as 32 and blocksize as 256k
    #                   Second job is a write workload that runs on ZNS and opens a SEQ zone(QD = 1 and BS = 128k) with max open zones as 1    
    def test_cns_zns_config(self):
        runtime = 60
        path = self.zns.replace("/dev", "")
        self.scheduler_switch('mq-deadline', path)
        print("\n #### Two jobs one on CNS and one on ZNS for 60 sec #### \n ")
        fio_cmd_global = "fio --name=global --direct=1 --ioengine=libaio --rw=write --rwmixread=0 --runtime={} --time_based".format(runtime)
        fio_cmd_job1 = " --name=job1 --filename={} --iodepth=32 --bs=256k --offset=0".format(self.cns)
        fio_cmd_job2 = " --name=job2 --filename={} --zonemode=zbd --max_open_zones=1 --iodepth=1 --bs=128k --offset=0".format(self.zns)
        fio_cmd = fio_cmd_global + fio_cmd_job1 + fio_cmd_job2
        print("\n" + fio_cmd)
        start_time = time.time()
        proc = subprocess.Popen(fio_cmd, shell=True, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
        output =  proc.stdout.read().decode('utf-8')
        print(output)
        if (output.find('err= 0') != -1):
            print ("\n ####  FIO RUN PASSED #### \n")
        else:
            print ("\n ####  FIO RUN FAILED #### \n")
            sys.exit(1)
        execution_time = int(time.time() - start_time)
        if(execution_time - runtime <= 2):
            print("\n FIO ran successfully for expected given time! \n")
        else:
            print("\n FIO didnt run for given time! \n")
            sys.exit(1)


class Sequential_Tests(FIO_TESTS):

    def test_001_time_based(self):
        ## TODO:After SBBB-2270 is checked in the write WL needs to be changed to randwrite ###
        # Test Description: The test runs a single job for 60 seconds on a SEQ zone
        #                   The workload is a randwrite WL that opens 12 zones at a time
        #                   QD=1 and BS=256k
        print("\n #### sequential write WL for 60 sec with 256k bs #### \n ")
        self.run_fio('256k', 1, 60, 'write', 0)
        # Test Description: The test runs a single job for 60 seconds on a SEQ zone
        #                   The workload is a mixed(Read/Write) WL that opens 12 zones at a time
        #                   QD=1 and BS=256k and Read/Write ratio = 50/50
        print("\n #### sequential mixed WL for 60 sec with 256k bs #### \n ")
        self.run_fio('256k', 1, 60, 'readwrite', 50)

    def test_002_100_zones(self):
        # Test Description: The test runs a single job on 100 SEQ zones 
        #                   The workload is a write WL that opens 1 zones at a time
        #                   QD=1, BS=256k, io_size = 100 x 1077MB(zone capacity), size = 100 x 2GB(zone size) 
        print("\n ###### Run fio (writes) on 100 seq zones with max 1 open zone ###### \n")
        # This test runs fio on 100 zones and verifies 100 zones are in FULL state after the run"
        self.run_fio('256k', 1, 0, 'write', 0, 1, 112931635200) # io_size = 100 x 1077 x 1024 x 1024
        full_zones  = self.get_full_zones()
        empty_zones = self.get_empty_zones()
        open_zones  = self.get_open_zones()
        self.get_zone_state_counts(full_zones, empty_zones, open_zones)
        if((full_zones != 100) or (open_zones !=0) or (empty_zones != self.total_zones - full_zones)):
            print("Zone states are not as expected \n")
            sys.exit(1)
        
        ## TODO:After SBBB-2270 is checked in the write WL needs to be changed to randwrite ###
        # Test Description: The test runs a single job on 100 SEQ zones 
        #                   The workload is a randwrite WL that opens 12 zones at a time
        #                   QD=1, BS=256k, io_size = 100 x 1077MB(zone capacity), size = 100 x 2GB(zone size)
        print("\n ###### Run fio (writes) on 100 seq zones with max 12 open zones ###### \n")
        # This test runs fio on 100 zones io_size and verifies the no of zones that are in FULL state are between 88-100 after the run"
        self.run_fio('256k', 1, 0, 'write', 0, 12, 112931635200)
        full_zones  = self.get_full_zones()
        empty_zones = self.get_empty_zones()
        open_zones  = self.get_open_zones()
        self.get_zone_state_counts(full_zones, empty_zones, open_zones)
        if((full_zones > 100 or full_zones < 88) or (open_zones > 12) or (empty_zones != self.total_zones - full_zones - open_zones)):
            print("Zone states are not as expected \n")
            sys.exit(1)

    def test_003_multi_job(self):
        # Test Description: The test runs two separate jobs parallely on a zns.
        #                   Run time for both jobs is 60 seconds
        #                   First job is a write workload that runs with iodepth as 1 and blocksize as 256k and offset at first zone
        #                   Second job is a write workload that runs with iodepth as 1 and blocksize as 128k and offset at zone 100        
        runtime = 60
        path = self.zns.replace("/dev", "")
        self.scheduler_switch('mq-deadline', path)
        print("\n #### sequential multiple jobs for 60 sec with different bs #### \n ")
        fio_cmd_global = "fio --name=global --direct=1 --ioengine=libaio --filename={} --rw=write --rwmixread=0 --zonemode=zbd --max_open_zones=1 --runtime={} --time_based".format(self.zns, runtime)
        fio_cmd_job1 = " --name=job1 --iodepth=1 --bs=256k --offset=0"
        fio_cmd_job2 = " --name=job2 --iodepth=1 --bs=128k --offset=214748364800"
        fio_cmd = fio_cmd_global + fio_cmd_job1 + fio_cmd_job2
        print("\n" + fio_cmd)
        start_time = time.time()
        proc = subprocess.Popen(fio_cmd, shell=True, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
        output =  proc.stdout.read().decode('utf-8')
        print(output)
        if (output.find('err= 0') != -1):
            print ("\n ####  FIO RUN PASSED #### \n")
        else:
            print ("\n ####  FIO RUN FAILED #### \n")
            sys.exit(1)
        execution_time = int(time.time() - start_time)
        if(execution_time - runtime <= 2):
            print("\n FIO ran successfully for expected given time! \n")
        else:
            print("\n FIO didnt run for given time! \n")
            sys.exit(1)
        

class ZRWA_Tests(FIO_TESTS):

    def test_001_time_based(self):
        # Test Description: The test runs a single job for 60 seconds on a ZRWA zone
        #                   The workload is a randwrite WL that opens 12 zones at a time
        #                   QD=4 and BS=256k
        print("\n #### zrwa write WL for 60 sec with 256k bs and 4 QD #### \n ")
        self.run_fio('256k', 4, 60, 'randwrite', 0, 12, None, None, 1)
        print("\n #### zrwa read/write WL for 60 sec with 256k bs and 4 QD #### \n ")
        # Test Description: The test runs a single job for 60 seconds on a ZRWA zone
        #                   The workload is a mixed(Read/Write) WL that opens 12 zones at a time
        #                   QD=4 and BS=256k
        self.run_fio('256k', 4, 60, 'readwrite', 50, 12, None, None, 1)

    def test_002_100_zones_no_overwrite(self):
        # Test Description: The test runs a single job on 100 ZRWA zones with no Overwrites
        #                   The workload is a write WL that opens 1 zones at a time
        #                   QD=4, BS=256k, io_size = 100 x 1077MB(zone capacity), size = 100 x 2GB(zone size) 
        print("\n ###### Run fio(writes) on 100 zrwa zones with max 1 open zone (no-overwrite) ###### \n")
        # This test runs fio on 100 zones and verifies 100 zones are in FULL state after the run"
        self.run_fio('256k', 4, 0, 'write', 0, 1, 112931635200, 214748364800, 1) # io_size = 100 x 1077 x 1024 x 1024
        full_zones  = self.get_full_zones()
        empty_zones = self.get_empty_zones()
        open_zones  = self.get_open_zones()
        self.get_zone_state_counts(full_zones, empty_zones, open_zones)
        if((full_zones != 100) or (open_zones !=0) or (empty_zones != self.total_zones - full_zones)):
            print("Zone states are not as expected \n")
            sys.exit(1)
        
        #TODO: Currently randwrite with ZRWA has a bug where its only filling 60 zones, hence doing "write" WL for now        
        # Test Description: The test runs a single job on 100 ZRWA zones with no Overwrites
        #                   The workload is a randwrite WL that opens 12 zones at a time
        #                   QD=4, BS=256k, io_size = 100 x 1077MB(zone capacity), size = 100 x 2GB(zone size) 
        print("\n ###### Run fio(writes) on 100  zones with max 12 open zones (no-overwrite) ###### \n")
        # This test runs fio on 100 zones io_size and verifies the no of zones that are in FULL state are between 88-100 after the run"
        self.run_fio('256k', 4, 0, 'write', 0, 12, 112931635200, 214748364800, 1)
        full_zones  = self.get_full_zones()
        empty_zones = self.get_empty_zones()
        open_zones  = self.get_open_zones()
        self.get_zone_state_counts(full_zones, empty_zones, open_zones)
        if((full_zones > 100 or full_zones < 88) or (open_zones > 12) or (empty_zones != self.total_zones - full_zones - open_zones)):
            print("Zone states are not as expected \n")
            sys.exit(1)

    def test_003_100_zones_with_2p_overwrite(self):
        # Test Description: The test runs a single job on 100 ZRWA zones with 2 percent Overwrites
        #                   The workload is a write WL that opens 1 zones at a time
        #                   QD=4, BS=256k, io_size = 100 x 1077MB(zone capacity), size = 100 x 2GB(zone size) 
        print("\n ###### Run fio (writes) on 100 zrwa zones with max 1 open zone (2p-overwrite) ###### \n")
        # This test runs fio on 100 zones and verifies 100 zones are in FULL state after the run"
        self.run_fio('256k', 4, 0, 'write', 0, 1, 112931635200, 214748364800, 1, 2) # io_size = (100 x 1077 x 1024 x 1024) # size = (100 x 2048 x 1024 x 1024)
        full_zones  = self.get_full_zones()
        empty_zones = self.get_empty_zones()
        open_zones  = self.get_open_zones()
        self.get_zone_state_counts(full_zones, empty_zones, open_zones)
        if((full_zones != 100) or (open_zones !=0) or (empty_zones != self.total_zones - full_zones)):
            print("Zone states are not as expected \n")
            sys.exit(1)
        
        #TODO: Currently randwrite with ZRWA has a bug where its only filling 60 zones, hence doing "write" WL for now        
        # Test Description: The test runs a single job on 100 ZRWA zones with 2 percent Overwrites
        #                   The workload is a randwrite WL that opens 12 zones at a time
        #                   QD=4, BS=256k, io_size = 100 x 1077MB(zone capacity), size = 100 x 2GB(zone size)
        print("\n ###### Run fio (writes) on 100  zones with max 12 open zones (2p-overwrite) ###### \n")
        # This test runs fio on 100 zones io_size and verifies the no of zones that are in FULL state are between 88-100 after the run"
        self.run_fio('256k', 4, 0, 'write', 0, 12, 112931635200, 214748364800, 1, 2)
        full_zones  = self.get_full_zones()
        empty_zones = self.get_empty_zones()
        open_zones  = self.get_open_zones()
        self.get_zone_state_counts(full_zones, empty_zones, open_zones)
        if((full_zones > 100 or full_zones < 88) or (open_zones > 12) or (empty_zones != self.total_zones - full_zones - open_zones)):
            print("Zone states are not as expected \n")
            sys.exit(1)

    def test_004_multi_job(self):
        # Test Description: The test runs three separate jobs parallely on a zns.
        #                   Run time for both jobs is 60 seconds
        #                   First job is a write workload that runs with iodepth as 4 and blocksize as 256k and offset at first zone (Overwrites = none)
        #                   Second job is a write workload that runs with iodepth as 8 and blocksize as 128k and offset at zone 100 (Overwrites = none)
        #                   First job is a write workload that runs with iodepth as 4 and blocksize as 256k and offset at zone 200 (Overwrites = 2 percent)         
        runtime = 60
        self.format_namespace(self.zns)
        path = self.zns.replace("/dev", "")
        self.scheduler_switch('none', path)
        print("\n #### ZRWA multiple jobs for 60 sec with different bs/qd/ow percentages #### \n ")
        start_time = time.time()
        fio_cmd_global = "fio --name=global --direct=1 --ioengine=libaio --filename={} --rw=write --rwmixread=0 --zonemode=zbd --max_open_zones=1 --runtime={} --time_based --zrwa_alloc=1 --ns_id={} --issue_zone_finish=1 ".format(self.zns, runtime, self.ns_id)
        fio_cmd_job1 = " --name=job1 --iodepth=4 --bs=256k --zrwa_overwrite_percent=0 --offset=0"
        fio_cmd_job2 = " --name=job2 --iodepth=8 --bs=128k  --zrwa_overwrite_percent=0 --offset=214748364800"
        fio_cmd_job3 = " --name=job3 --iodepth=4 --bs=256k --zrwa_overwrite_percent=2 --offset=429496729600"
        fio_cmd = fio_cmd_global + fio_cmd_job1 + fio_cmd_job2 + fio_cmd_job3
        print("\n" + fio_cmd)
        proc = subprocess.Popen(fio_cmd, shell=True, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
        output =  proc.stdout.read().decode('utf-8')
        print(output)
        if (output.find('err= 0') != -1):
            print ("\n ####  FIO RUN PASSED #### \n")
        else:
            print ("\n ####  FIO RUN FAILED #### \n")
            sys.exit(1)
        execution_time = int(time.time() - start_time)
        if(execution_time - runtime <= 2):
            print("\n FIO ran successfully for expected given time! \n")
        else:
            print("\n FIO didnt run for given time! \n")
            sys.exit(1)


def create_namespace(ctrl, size, type):
    cmd = "nvme create-ns -s %d -c %d -b 4096 -csi %d %s" % (size, size, type, ctrl)
    print(cmd)
    proc = subprocess.Popen(cmd, shell=True, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
    output =  proc.stdout.read().decode('utf-8')
    if ("create-ns: Success" not in output):
        print("Create-ns failed")
        sys.exit(1)

def attach_namespace(ctrl, nsid):
    cmd = "nvme attach-ns -n %s -c 0 %s" % (nsid, ctrl)
    print(cmd)
    proc = subprocess.Popen(cmd, shell=True, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
    output =  proc.stdout.read().decode('utf-8')
    if ("attach-ns: Success" not in output):
        print("Attach-ns failed")
        sys.exit(1)

def parse_command_line(args):
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Script to validate FIO', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-c','--ctrl', dest='ctrl', required= True, help='The controller the fio runs on')

    try:
        import argcomplete
        argcomplete.autocomplete(parser)
    except ImportError:
        pass

    args = parser.parse_args(args)
    return args

def main(args=sys.argv[1:]):
    args = parse_command_line(args)
    found = os.popen("ls /dev | grep {} | wc -l".format(args.ctrl.split("/")[2])).read()
    if int(found, 10) == 0:
        print ("Invalid argument {}".format(args.ctrl))
        sys.exit(1)

    
    #Prepping the drive (Deletes all namespaces and creates 1 CNS(2GB) + 1 ZNS(1.2TB))
    delete_namespace = "nvme delete-ns {} -n 0xFFFFFFFF".format(args.ctrl)
    os.system(delete_namespace)
    create_namespace(args.ctrl, 524288, 0)
    attach_namespace(args.ctrl, 1)
    time.sleep(2)
    create_namespace(args.ctrl, 314572800, 2)
    attach_namespace(args.ctrl, 2)
    time.sleep(2)
    print("\n Created the following namespaces \n")
    print_ns_list = "nvme list"
    os.system(print_ns_list)
    print("\n \n")
    cns = "{}n1".format(args.ctrl)
    zns = "{}n2".format(args.ctrl)
    
    #Tests to run
    multi_ns_tests = Multinamespace_Tests(zns,cns)
    seq_tests = Sequential_Tests(zns)
    zrwa_tests = ZRWA_Tests(zns)
    #Multi-ns tests
    multi_ns_tests.test_cns_zns_config()
    #Sequnetial Write req zones tests
    seq_tests.test_001_time_based()
    seq_tests.test_002_100_zones()
    seq_tests.test_003_multi_job()
    #ZRWA zone tests
    zrwa_tests.test_001_time_based()
    zrwa_tests.test_002_100_zones_no_overwrite()
    zrwa_tests.test_003_100_zones_with_2p_overwrite()
    zrwa_tests.test_004_multi_job()
    print("All tests passed successfully")

if __name__ == '__main__':
    main()

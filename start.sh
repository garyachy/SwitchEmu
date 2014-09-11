export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:dpdkpcap
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/denis/projects/dpdkadapter/dpdk-1.7.0/x86_64-native-linuxapp-gcc/lib/

./dpdkpcap_test 1000000

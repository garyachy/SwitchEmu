#include <net/if.h>
#include <linux/if_tun.h>

#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <pcap.h>
#include <net/if_arp.h>
#include <map>
#include <vector>
#include <string.h>
#include <iostream>
#include <fstream>
#include <utility>
#include <thread>

#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <mutex>

#include "classes.h"

extern "C" {
#include "tapcfg_bin-1.0.0/include/tapcfg.h"
}

using namespace std;

void createInterfaceThread();

bool traceFlag = true;
int tapNum = 0;
int macNum = 1;

PortChange portsObserver;
PacketObserver packetObserver;

int pid = 0;

int myPrintf(const char* format, ...) 
{
  if (traceFlag == false)
  {
    return 0;
  }

  va_list vl;
  va_start(vl, format);
  vprintf(format, vl);
  va_end(vl);
}

std::ostream debug(cout.rdbuf());
static std::ofstream null;

void trace_init()
{
    null.open("/dev/null");
    if(!traceFlag) {  // put whatever your condition is here
        debug.rdbuf(null.rdbuf());
    }
}

void trace_done()
{
    null.close();
}

void writePidFile()
{
  fstream qFile("SwitchEmu.dat", ios::out | ios::binary);
  qFile.write((char*)&(pid), sizeof(int));
  qFile.close();
}

void readPidFile()
{
  fstream qFile("SwitchEmu.dat", ios::in | ios::binary);
  if (qFile.good())
  {
    qFile.read((char*)&pid, sizeof(int));
    qFile.close();
  }
}

std::vector<pcap_t*> tapHandles;
static vector<std::thread> threads;

static TFdb FDB;

void printPorts()
{
  unsigned int i = 0;

  for(i = 0; i < tapHandles.size(); i++)   
  {
    cout << "tap" << i << endl;
  }  
}

void inputThreadFunc()
{
  while ( true )
  {
    // Show prompt.
    cout << "SwitchEmu" << ">> " << flush;
    char command[128];
    cin.getline( command, 128 );

    vector<char*> args;
    char* prog = strtok( command, " " );
    char* tmp = prog;
    while ( tmp != NULL )
    {
      args.push_back( tmp );
      tmp = strtok( NULL, " " );
    }

    if ( strcmp( command, "quit" ) == 0 )
    {
      readPidFile();
      pid--;
      writePidFile();
      std::exit(1);
    }

    if ( strcmp( command, "show" ) == 0 )
    {
      if ( (args.size() > 1) && (strcmp(args[1], "fdb") == 0) )
      {
        FDB.printFDB();
      }

      if ( (args.size() > 1) && (strcmp(args[1], "ports") == 0) )
      {
        printPorts();
      }

      if ( (args.size() > 1) && (strcmp(args[1], "pid") == 0) )
      {
        cout << "pid = "  << pid << endl;
      }      
    }

    if ( strcmp( command, "trace" ) == 0 )
    {
      if ( (args.size() > 1) && (strcmp(args[1], "on") == 0) )
      {
        cout << "on" << endl;
        traceFlag = true;
        cout << "Executed" << endl;
      }

      if ( (args.size() > 1) && (strcmp(args[1], "off") == 0) )
      {
        cout << "off" << endl;
        traceFlag = false;
        cout << "Executed" << endl;
      }
    }

    if ( strcmp( command, "fdb" ) == 0 )
    {
      if ( (args.size() > 1) && (strcmp(args[1], "add") == 0) )
      {
        if ( (args.size() > 4) && (strcmp(args[3], "port") == 0) )
        {
          mapKey entryKey(args[2]);
          unsigned int port = std::atoi(args[4]); 

          FDB.insertEntry(entryKey, port);
          cout << "Executed" << endl;
        }
      }

      if ( (args.size() > 1) && (strcmp(args[1], "delete") == 0) )
      {
        if (args.size() > 2)
        {
          mapKey entryKey(args[2]);

          FDB.deleteEntry(entryKey);
          cout << "Executed" << endl;
        }
      }
    }

    if ( strcmp( command, "port" ) == 0 )
    {
      createInterfaceThread();
      cout << "Executed" << endl;
    }

    if ( strcmp( command, "help" ) == 0 )
    {
      cout << "List of commands:" << endl;
      cout << "1. quit - terminate the program" << endl;
      cout << "2. show fdb - print the FDB" << endl;
      cout << "3. show ports - print the interfaces" << endl;
      cout << "4. trace on/off - enable/disable tracing" << endl;
      cout << "5. fdb add/delete [mac] port [port] - add/delete FDB entry" << endl;
      cout << "6. port - add tap interface" << endl;
    } 
  }
}

void my_callback(u_char *useless, const struct pcap_pkthdr* pkthdr, const u_char*packet)
{   
   struct ether_header *eptr;
   mapKey srcKey;
   mapKey dstKey;

   int port = (int)useless;

   eptr = (struct ether_header *) packet;
   memcpy(&srcKey.mac, eptr->ether_shost, sizeof(srcKey.mac));
   memcpy(&dstKey.mac, eptr->ether_dhost, sizeof(dstKey.mac));

   myPrintf("Received a packet length [%d], ", pkthdr->len);
   myPrintf("SRC ");
   debug << srcKey.printKey();
   myPrintf(" DST ");
   debug << dstKey.printKey();
   myPrintf(" on port %d\n", port);

   //packetObserver.notify();

   FDB.insertEntry(srcKey, port);
   FDB.forwardPacket(dstKey, port, pkthdr, packet);
}

void workerFunc(int port)  
{
    pcap_pkthdr pkthdr;
    u_char* packet = NULL;
    
    /*boost::posix_time::seconds workTime(3);
    boost::this_thread::sleep(workTime);  */

    sleep(3);
       
    myPrintf("Port %d is monitored\n", port);
    
    pcap_loop(tapHandles[port], -1, my_callback, (u_char *)port);
      
    myPrintf("Port %d is not monitored anymore\n", port);
}  

int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;
  const char *clonedev = "/dev/net/tun";

  /* Arguments taken by the function:
   *
   * char *dev: the name of an interface (or '\0'). MUST have enough
   *   space to hold the interface name if '\0' is passed
   * int flags: interface flags (eg, IFF_TUN etc.)
   */

   /* open the clone device */
   if( (fd = open(clonedev, O_RDWR)) < 0 ) {
     return fd;
   }

   /* preparation of the struct ifr, of type "struct ifreq" */
   memset(&ifr, 0, sizeof(ifr));

   ifr.ifr_flags = flags;   /* IFF_TUN or IFF_TAP, plus maybe IFF_NO_PI */

   if (*dev) {
     /* if a device name was specified, put it in the structure; otherwise,
      * the kernel will try to allocate the "next" device of the
      * specified type */
     strncpy(ifr.ifr_name, dev, IFNAMSIZ);
   }

   /* try to create the device */
   if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
     close(fd);
     return err;
   }

  /* if the operation was successful, write back the name of the
   * interface to the variable "dev", so the caller can know
   * it. Note that the caller MUST reserve space in *dev (see calling
   * code below) */
  strcpy(dev, ifr.ifr_name);

  /* this is the special file descriptor that the caller will use to talk
   * with the virtual interface */
  return fd;
}

pcap_t* createInterface(const char* ifName, const char* mac)
{
    char tap_name[IFNAMSIZ];
    int tap_fd;
    tapcfg_t* tapCfg;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    myPrintf("Creating device %s\n", ifName);

    tapCfg = tapcfg_init();
    tapcfg_start(tapCfg, ifName, 1);
    tapcfg_iface_set_hwaddr(tapCfg, mac, 6);
    tapcfg_iface_set_mtu(tapCfg, 1500);
    /*tapcfg_iface_set_ipv4(tapCfg, "192.168.10.1", 16);*/
    tapcfg_iface_set_status(tapCfg, TAPCFG_STATUS_IPV4_UP);

    handle = pcap_open_live(ifName, BUFSIZ, 1, -1, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", ifName, errbuf);
        return NULL;
    }

    myPrintf("Device: %s\n", ifName);
    myPrintf("tapHandle [%p]\n", handle);   

    return handle;
}

void createInterfaceThread()
{
  char mac[20] = {0};
  char device[32];

  sprintf(device, "tap%d", pid * 100 + tapNum);
  sprintf(mac, "000000%d", pid * 100 + macNum);

  myPrintf("MAC: %s\n", mac);

  tapHandles.push_back(createInterface(device, mac));
  threads.push_back(thread(workerFunc, tapNum));

  tapNum++;
  macNum++;
}

int main()
{
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    const u_char *packet;
    int i;
    std::vector<std::thread>::iterator threadVectIter;

    std:thread inputThread(inputThreadFunc);

    trace_init();
    trace_done();

    readPidFile();
    pid++;
    writePidFile();
    
    /*tapHandles[0] = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (tapHandles[0] == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", "eth0", errbuf);
        return(2);
    }
    
    threads[0] = new thread(workerFunc, 0);*/

    PacketListener packetListener;
    packetObserver.attach(&packetListener);
    
    
    myPrintf("main: waiting for threads\n");  
    
    inputThread.join();

    for(threadVectIter = threads.begin(); 
        threadVectIter != threads.end();
        threadVectIter++)
    {
      (*threadVectIter).join();
    }
       
    return (0);
}


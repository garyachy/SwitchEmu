#include <arpa/inet.h>
#include <net/ethernet.h>
 
#ifdef LINUX
#include <netinet/ether.h>
#endif

#include <map>

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
#include <pcap.h>
#include <net/if_arp.h>
#include <map>
#include <vector>
#include <string.h>
#include <iostream>
#include <utility>
#include <thread>

#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <mutex>

class mapKey
{
public:
  unsigned char mac[ETHER_ADDR_LEN];
  bool operator<(const mapKey& other) const;
  mapKey& operator=(const mapKey& other);
  mapKey();
  mapKey(char* macStr);
  std::string printKey() const;
};

class fdbValue
{
public:
  unsigned int _port;
  unsigned int _timeout;
  fdbValue();
  fdbValue(int port);
};

typedef std::map<mapKey, fdbValue> TFdbMap;
typedef std::pair<mapKey, fdbValue> TFdbMapPair;

class TFdb
{
public:
  TFdb();
  void insertEntry(mapKey& srcKey, int port);
  void deleteEntry(mapKey& srcKey);
  void printFDB();
  void timerFDB();
  void forwardPacket(mapKey& dstKey, int port, const struct pcap_pkthdr* pkthdr, const u_char*packet);
private:
  TFdbMap _FDB;
  std::mutex _mutexFDB;
  std::thread _timerThread;
};

class Observer;

class Listener
{
  public:
    virtual void update(Observer *) = 0;
};

class Observer
{
    std::vector < Listener * > listeners;
  public:
    void attach(Listener *al)
    {
        listeners.push_back(al);
    }
    void notify()
    {
        for (int i = 0; i < listeners.size(); i++)
          listeners[i]->update(this);
    }
    virtual void getEventType() = 0;
};

class PortChange: public Observer
{
  public:
     /*virtual*/void getEventType();
};

class PacketObserver: public Observer
{
  public:
     /*virtual*/void getEventType();
};

class PacketListener: public Listener
{
  public:
     /*virtual*/void update(Observer *);
};

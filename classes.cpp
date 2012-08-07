#include <stdio.h>
#include <string.h>
#include <iostream>
#include "classes.h"

extern std::vector<pcap_t*> tapHandles;
extern int myPrintf(const char* format, ...);
extern std::ostream debug;

using namespace std;

fdbValue::fdbValue() : _port(0), _timeout(10)
{  
}

fdbValue::fdbValue(int port) : _port(port), _timeout(10)
{  
}

mapKey::mapKey(char* macStr)
{
  int tempMac[6];
  std::sscanf(macStr, "%02x:%02x:%02x:%02x:%02x:%02x",
              &tempMac[0], &tempMac[1], &tempMac[2], &tempMac[3], &tempMac[4], &tempMac[5]);

  for(int i = 0; i < 6; i++)
  {
    mac[i] = tempMac[i];
  }
}

mapKey::mapKey()
{
}

bool mapKey::operator<(const mapKey& other) const
{
  bool res = false;
  int rs = 0;

  rs = memcmp(mac, other.mac, sizeof(mac));

  res = rs < 0 ? true : false;

  return res;
}

mapKey& mapKey::operator=(const mapKey& other)
{
  memcpy(mac, other.mac, sizeof(mac));
  return *this;
}

std::string mapKey::printKey() const
{
  char buf[50] = {'\0'};
  
  sprintf(buf, "MAC Address: %02x-%02x-%02x-%02x-%02x-%02x", 
          mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

  return buf;
}

TFdb::TFdb()
{
  _timerThread = std::thread(&TFdb::timerFDB, this);
}

void TFdb::timerFDB()
{
  TFdbMap::iterator iter;

  while (true)
  {
    sleep(1);

//  _mutexFDB.lock();

  for(iter = _FDB.begin(); 
      iter != _FDB.end();
      iter++)
  {
    if (iter->second._timeout > 0)
    {
      iter->second._timeout--;  
      debug << "port " << iter->second._port << " timeout " << iter->second._timeout << endl;
    }
    else
    {
      debug << "Erasing port " << iter->second._port << " timeout " << iter->second._timeout << endl;
      _FDB.erase(iter++);
    }
  }

//  _mutexFDB.unlock();

  }
}

void TFdb::printFDB()
{
  TFdbMap::iterator iter;

  cout << "------------FDB-Start-----------------------------" << endl;

  std::lock_guard<std::mutex> lock (_mutexFDB);

  cout << "FDB size = " << _FDB.size() << endl;  

  for(iter = _FDB.begin(); 
      iter != _FDB.end();
      iter++)
  {
    cout << iter->first.printKey();
    cout << ", Port:";
    cout << iter->second._port;
    cout << endl;
  }

  cout << "------------FDB-End-------------------------------" << endl;
}

void TFdb::insertEntry(mapKey& srcKey, int port)
{
  TFdbMap::iterator iter;
  std::lock_guard<std::mutex> lock(_mutexFDB);
  fdbValue value(port);

  debug << __func__ << "(" << __LINE__ << ")" << endl;
  
  iter = _FDB.find(srcKey);

  if(iter != _FDB.end())
  {
    _FDB.erase(iter);  
  }

  _FDB.insert(TFdbMapPair(srcKey, value));
}

void TFdb::deleteEntry(mapKey& srcKey)
{
  TFdbMap::iterator iter;
  std::lock_guard<std::mutex> lock(_mutexFDB);

  debug << __func__ << "(" << __LINE__ << ")" << endl;
  
  iter = _FDB.find(srcKey);

  if(iter != _FDB.end())
  {
    _FDB.erase(iter);  
  }
}

void TFdb::forwardPacket(mapKey& dstKey, int port, const struct pcap_pkthdr* pkthdr, const u_char*packet)
{
  int i = 0;
  TFdbMap::iterator iter;

  debug << __func__ << "(" << __LINE__ << ")" << endl;

   if((iter = _FDB.find(dstKey)) != _FDB.end())
   {
     i = iter->second._port;

     if (i != port)
     { 
       myPrintf("Injected a packet of length [%d] to port %d received on port %d\n", pkthdr->len, i, port);
       pcap_inject(tapHandles[i], packet, pkthdr->len);
     }
     else
    {
       myPrintf("Dropped a packet of length [%d] received on port %d\n", pkthdr->len, port);
    }

     return;
   }
  
   for(i = 0; i < tapHandles.size(); i++)   
   {
     debug << "i = " << i << " port = " << port << endl;
     if (i != port)
     {
       myPrintf("Injected a packet of length [%d] to port %d received on port %d\n", pkthdr->len, i, port);
       pcap_inject(tapHandles[i], packet, pkthdr->len);
     }
   }  
}

/*virtual*/void PortChange::getEventType()
{
  cout << "link up" << '\n';
}

/*virtual*/void PacketObserver::getEventType()
{
  cout << "packet received" << '\n';
}

void PacketListener::update(Observer *ob)
{
  cout << "packet event" << '\n';
  ob->getEventType();
}



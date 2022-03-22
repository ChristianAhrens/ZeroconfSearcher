/*
  ==============================================================================

    ZeroconfSearcher.cpp
    Created: 04 March 2022 22:10:00pm
    Author:  Christian Ahrens

  ==============================================================================
*/

#pragma once

#include <chrono>
#include <future>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "../submodules/mdns/mdns.h"

#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#define sleep(x) Sleep(x * 1000)
#else
#include <netdb.h>
#include <ifaddrs.h>
#include <net/if.h>
#endif

namespace ZeroconfSearcher
{

class ZeroconfSearcher
{
public:
    struct ServiceInfo
    {
        std::string name;
        std::string host;
        std::string ip;
        int port;
        std::map<std::string, std::string> txtRecords;
        std::chrono::time_point<std::chrono::high_resolution_clock> lastSeen;
    };

    class ZeroconfSearcherListener
    {
    public:
        virtual ~ZeroconfSearcherListener() {};
        
        //virtual void handleServiceUpdated() = 0;
        //virtual void handleServiceAdded() = 0;
        virtual void handleServicesChanged() = 0;
    };

public:
	ZeroconfSearcher(std::string name, std::string serviceName);
	~ZeroconfSearcher();

    void AddListener(ZeroconfSearcherListener* listener);
    void RemoveListener(ZeroconfSearcherListener* listener);

    static int RecvCallback(int /*sock*/, const struct sockaddr* from, size_t addrlen, mdns_entry_type_t entry,
            uint16_t /*query_id*/, uint16_t rtype, uint16_t /*rclass*/, uint32_t /*ttl*/, const void* data,
            size_t size, size_t name_offset, size_t /*name_length*/, size_t record_offset,
        size_t record_length, void* /*user_data*/)
    {
        char buffer[256];

        char host[NI_MAXHOST] = { 0 };
        char service[NI_MAXSERV] = { 0 };
        int ret = getnameinfo(from, (socklen_t)addrlen, host, NI_MAXHOST, service, NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);
        std::string fromServiceStr(service);
        std::string fromHostStr(std::string(host) + std::string(fromServiceStr.size() > 0 ? (std::string(":") + std::string(fromServiceStr)) : ""));

        std::string entrytype = (entry == MDNS_ENTRYTYPE_ANSWER) ? "answer" : ((entry == MDNS_ENTRYTYPE_AUTHORITY) ? "authority" : "additional");

        mdns_string_t entrystr =  mdns_string_extract(data, size, &name_offset, buffer, sizeof(buffer));

        if (rtype == MDNS_RECORDTYPE_PTR) 
        {
            std::lock_guard<std::mutex> mdnsEntryLockGuard(ZeroconfSearcher::s_mdnsEntryLock);
            ZeroconfSearcher::s_mdnsEntry = std::string(entrystr.str, entrystr.length);

            mdns_string_t namestr = mdns_record_parse_ptr(data, size, record_offset, record_length, buffer, sizeof(buffer));

            ZeroconfSearcher::s_mdnsEntryPTR = std::string(namestr.str, namestr.length);
        }
        else if (rtype == MDNS_RECORDTYPE_SRV) 
        {
            mdns_record_srv_t srv = mdns_record_parse_srv(data, size, record_offset, record_length, buffer, sizeof(buffer));

            std::lock_guard<std::mutex> mdnsEntryLockGuard(ZeroconfSearcher::s_mdnsEntryLock);
            ZeroconfSearcher::s_mdnsEntrySRVName      = std::string(srv.name.str, srv.name.length);
            ZeroconfSearcher::s_mdnsEntrySRVPort      = srv.port;
            ZeroconfSearcher::s_mdnsEntrySRVPriority  = srv.priority;
            ZeroconfSearcher::s_mdnsEntrySRVWeight    = srv.weight;
        }
        else if (rtype == MDNS_RECORDTYPE_A) 
        {
            struct sockaddr_in addr;
            mdns_record_parse_a(data, size, record_offset, record_length, &addr);

            ret = getnameinfo((const struct sockaddr*)&addr, (socklen_t)sizeof(addr), host, NI_MAXHOST, service, NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);

            std::lock_guard<std::mutex> mdnsEntryLockGuard(ZeroconfSearcher::s_mdnsEntryLock);
            ZeroconfSearcher::s_mdnsEntryAHost = std::string(host);
            ZeroconfSearcher::s_mdnsEntryAService = std::string(service);
        }
        else if (rtype == MDNS_RECORDTYPE_AAAA) 
        {
            struct sockaddr_in6 addr;
            mdns_record_parse_aaaa(data, size, record_offset, record_length, &addr);

            ret = getnameinfo((const struct sockaddr*)&addr, (socklen_t)sizeof(addr), host, NI_MAXHOST, service, NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);

            std::lock_guard<std::mutex> mdnsEntryLockGuard(ZeroconfSearcher::s_mdnsEntryLock);
            ZeroconfSearcher::s_mdnsEntryAAAAHost = std::string(host);
            ZeroconfSearcher::s_mdnsEntryAAAAService = std::string(service);

        }
        else if (rtype == MDNS_RECORDTYPE_TXT) 
        {
            static mdns_record_txt_t txtbuffer[128];
            size_t parsed = mdns_record_parse_txt(data, size, record_offset, record_length, txtbuffer, sizeof(txtbuffer) / sizeof(mdns_record_txt_t));

            for (size_t itxt = 0; itxt < parsed; ++itxt)
            {
                if (txtbuffer[itxt].value.length)
                {
                    std::lock_guard<std::mutex> mdnsEntryLockGuard(ZeroconfSearcher::s_mdnsEntryLock);
                    ZeroconfSearcher::s_mdnsEntryTXT.insert(std::make_pair(std::string(txtbuffer[itxt].key.str, txtbuffer[itxt].key.length), std::string(txtbuffer[itxt].value.str, txtbuffer[itxt].value.length)));
                }
                else 
                {
                    std::lock_guard<std::mutex> mdnsEntryLockGuard(ZeroconfSearcher::s_mdnsEntryLock);
                    ZeroconfSearcher::s_mdnsEntryTXT.insert(std::make_pair(std::string(txtbuffer[itxt].key.str, txtbuffer[itxt].key.length), std::string()));
                }
            }
        }
        else 
        {
            //DBG(String(__FUNCTION__) + String(" received answer from ") + String(fromHostStr) + String("(") + "" + String(")"));

            //printf("%.*s : %s %.*s type %u rclass 0x%x ttl %u length %d\n",
            //    fromHostStr, entrytype, MDNS_STRING_FORMAT(entrystr), rtype,
            //    rclass, ttl, (int)record_length);
        }

        return ret;
    };

    std::string GetIPForHostAndPort(std::string host, int port);

	ServiceInfo * GetService(const std::string& name, const std::string& host, int port);
	void AddService(const std::string& name, const std::string& host, const std::string& ip, int port, const std::map<std::string, std::string>& txtRecords);
	void RemoveService(std::unique_ptr<ServiceInfo>& service);
	void UpdateService(std::unique_ptr<ServiceInfo>& service, const std::string& ip, const std::map<std::string, std::string>& txtRecords);

    const std::string&                 GetName();
    const std::string&                 GetServiceName();
    const std::vector<ServiceInfo*>    GetServices();
    int                                GetSocketIdx();

    bool Search();
    bool CleanupStaleServices();
    void BroadcastChanges();

private:
    static void run(std::future<void> future, ZeroconfSearcher* searcherInstance);

    static std::mutex                           s_mdnsEntryLock;
    static std::string                          s_mdnsEntry;
    static std::string                          s_mdnsEntryPTR;
    static std::string                          s_mdnsEntrySRVName;
    static std::uint16_t                        s_mdnsEntrySRVPort;
    static std::uint16_t                        s_mdnsEntrySRVPriority;
    static std::uint16_t                        s_mdnsEntrySRVWeight;
    static std::string                          s_mdnsEntryAHost;
    static std::string                          s_mdnsEntryAService;
    static std::string                          s_mdnsEntryAAAAHost;
    static std::string                          s_mdnsEntryAAAAService;
    static std::map<std::string, std::string>   s_mdnsEntryTXT;

    std::string                                 m_name;
    std::string                                 m_serviceName;
    std::vector<std::unique_ptr<ServiceInfo>>   m_services;
    int                                         m_socketIdx;

    std::promise<void>              m_threadExitSignal;
    std::unique_ptr<std::thread>    m_searcherThread;

    std::vector<ZeroconfSearcherListener*> m_listeners;
};

};

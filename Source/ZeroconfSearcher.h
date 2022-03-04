/*
  ==============================================================================

    ZeroconfSearcher.cpp
    Created: 04 March 2022 22:10:00pm
    Author:  Christian Ahrens

  ==============================================================================
*/

#pragma once

#include <map>
#include <string>
#include <vector>

#include "../submodules/mdns/mdns.h"

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
    };

public:
	ZeroconfSearcher(std::string name, std::string serviceName, unsigned short announcementPort = 0);
	~ZeroconfSearcher();

    static int recvCallback(int /*sock*/, const struct sockaddr* from, size_t addrlen, mdns_entry_type_t entry,
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
            ZeroconfSearcher::s_mdnsEntry = std::string(entrystr.str, entrystr.length);

            mdns_string_t namestr = mdns_record_parse_ptr(data, size, record_offset, record_length, buffer, sizeof(buffer));

            ZeroconfSearcher::s_mdnsEntryPTR = std::string(namestr.str, namestr.length);
        }
        else if (rtype == MDNS_RECORDTYPE_SRV) 
        {
            mdns_record_srv_t srv = mdns_record_parse_srv(data, size, record_offset, record_length, buffer, sizeof(buffer));

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

            ZeroconfSearcher::s_mdnsEntryAHost = std::string(host);
            ZeroconfSearcher::s_mdnsEntryAService = std::string(service);
        }
        else if (rtype == MDNS_RECORDTYPE_AAAA) 
        {
            struct sockaddr_in6 addr;
            mdns_record_parse_aaaa(data, size, record_offset, record_length, &addr);

            ret = getnameinfo((const struct sockaddr*)&addr, (socklen_t)sizeof(addr), host, NI_MAXHOST, service, NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);

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
                    ZeroconfSearcher::s_mdnsEntryTXT.insert(std::make_pair(std::string(txtbuffer[itxt].key.str, txtbuffer[itxt].key.length), std::string(txtbuffer[itxt].value.str, txtbuffer[itxt].value.length)));
                }
                else 
                {
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

	bool search();
    std::string getIPForHostAndPort(std::string host, int port);

	ServiceInfo * GetService(std::string& name, std::string& host, int port);
	void AddService(std::string& name, std::string& host, std::string& ip, int port);
	void RemoveService(ServiceInfo * service);
	void UpdateService(ServiceInfo * service, std::string& host, std::string& ip, int port);

    const std::string&                  GetName();
    const std::string&                  GetServiceName();
    const std::vector<ServiceInfo*>&    GetServices();
    int                                 GetSocketIdx();

private:
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

    std::string                 m_name;
    std::string                 m_serviceName;
    std::vector<ServiceInfo*>   m_services;
    int                         m_socketIdx;
};

};

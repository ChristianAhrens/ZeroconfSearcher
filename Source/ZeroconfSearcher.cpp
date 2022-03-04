/*
  ==============================================================================

    ZeroconfSearcher.cpp
    Created: 04 March 2022 22:10:00pm
    Author:  Christian Ahrens

  ==============================================================================
*/

#include "ZeroconfSearcher.h"


namespace ZeroconfSearcher
{


std::string                          ZeroconfSearcher::s_mdnsEntry = std::string();
std::string                          ZeroconfSearcher::s_mdnsEntryPTR = std::string();
std::string                          ZeroconfSearcher::s_mdnsEntrySRVName = std::string();
std::uint16_t                        ZeroconfSearcher::s_mdnsEntrySRVPort = std::uint16_t(0);
std::uint16_t                        ZeroconfSearcher::s_mdnsEntrySRVPriority = std::uint16_t(0);
std::uint16_t                        ZeroconfSearcher::s_mdnsEntrySRVWeight = std::uint16_t(0);
std::string                          ZeroconfSearcher::s_mdnsEntryAHost = std::string();
std::string                          ZeroconfSearcher::s_mdnsEntryAService = std::string();
std::string                          ZeroconfSearcher::s_mdnsEntryAAAAHost = std::string();
std::string                          ZeroconfSearcher::s_mdnsEntryAAAAService = std::string();
std::map<std::string, std::string>   ZeroconfSearcher::s_mdnsEntryTXT = std::map<std::string, std::string>();


//==============================================================================
ZeroconfSearcher::ZeroconfSearcher(std::string name, std::string serviceName, unsigned short announcementPort) :
	m_name(name),
	m_serviceName(serviceName)
{
#ifdef _WIN32
	WORD versionWanted = MAKEWORD(1, 1);
	WSADATA wsaData;
	if (WSAStartup(versionWanted, &wsaData))
	{
		//DBG(String("Failed to initialize WinSock"));
	}
#endif
		
	m_socketIdx = mdns_socket_open_ipv4(nullptr);
	if (m_socketIdx < 0)
	{
		int error = WSAGetLastError();
		//DBG(String("mdns_socket_open_ipv4 returned error (LastError:") + String(error) + String(")"));
	}
}

ZeroconfSearcher::~ZeroconfSearcher()
{
	mdns_socket_close(m_socketIdx);

	for (auto& i : m_services)
		delete i;
	m_services.clear();

#ifdef _WIN32
	WSACleanup();
#endif
}

bool ZeroconfSearcher::search()
{
	if (Thread::getCurrentThread()->threadShouldExit())
		return false;

	//servus::Strings instances = m_servus.discover(servus::Servus::Interface::IF_ALL, 200);
	
	bool changed = false;

	std::string queryName = m_serviceName + ".local";

	char buffer[512];
	int queryId = mdns_query_send(m_socketIdx, mdns_record_type_t::MDNS_RECORDTYPE_ANY, queryName.c_str(), queryName.length(), buffer, sizeof(buffer), 0);
	if (queryId < 0)
	{
		//DBG(String("mdns query failed"));
	}

	char userData[512];
	size_t responseCnt = mdns_query_recv(m_socketIdx, buffer, sizeof(buffer), reinterpret_cast<mdns_record_callback_fn>(&recvCallback), userData, queryId);

	if (responseCnt > 0)
	{
		//DBG(String("mdns got ") + String(responseCnt) + String(" responses for ") + String(ZeroconfSearcher::s_mdnsEntry) + String(" from ") + String(ZeroconfSearcher::s_mdnsEntrySRVName));

		ServiceInfo info;
		
		info.ip = ZeroconfSearcher::s_mdnsEntryAHost;
		info.port = ZeroconfSearcher::s_mdnsEntrySRVPort;
		info.host = ZeroconfSearcher::s_mdnsEntrySRVName;
		info.name = ZeroconfSearcher::s_mdnsEntryPTR;

		auto it = std::find_if(m_services.begin(), m_services.end(), [info](ServiceInfo* i_ptr) { return (info.name == i_ptr->name && info.host == i_ptr->host && info.ip == i_ptr->ip && info.port == i_ptr->port); });
		if (it != m_services.end())
			UpdateService(*it, info.host, info.ip, info.port);
		else
			AddService(info.name, info.host, info.ip, info.port);
	}

	ZeroconfSearcher::s_mdnsEntry				= std::string();
	ZeroconfSearcher::s_mdnsEntryPTR			= std::string();
	ZeroconfSearcher::s_mdnsEntrySRVName		= std::string();
	ZeroconfSearcher::s_mdnsEntrySRVPort		= std::uint16_t(0);
	ZeroconfSearcher::s_mdnsEntrySRVPriority	= std::uint16_t(0);
	ZeroconfSearcher::s_mdnsEntrySRVWeight		= std::uint16_t(0);
	ZeroconfSearcher::s_mdnsEntryAHost			= std::string();
	ZeroconfSearcher::s_mdnsEntryAService		= std::string();
	ZeroconfSearcher::s_mdnsEntryAAAAHost		= std::string();
	ZeroconfSearcher::s_mdnsEntryAAAAService	= std::string();
	ZeroconfSearcher::s_mdnsEntryTXT			= std::map<std::string, std::string>();
	
	//StringArray servicesArray;
	//for (auto &s : instances)
	//	servicesArray.add(s);
	//
	//Array<ServiceInfo *> servicesToRemove;
	//
	//for (auto &ss : m_services)
	//{
	//	if (servicesArray.contains(ss->name))
	//	{
	//		String host = m_servus.get(ss->name.toStdString(), "servus_host");
	//		if (host.endsWithChar('.'))
	//			host = host.substring(0, host.length() - 1);
	//		int port = String(m_servus.get(ss->name.toStdString(), "servus_port")).getIntValue();
	//
	//		if (ss->host != host || ss->port != port)
	//			servicesToRemove.add(ss);
	//	}
	//	else
	//	{
	//		servicesToRemove.add(ss);
	//	}
	//}
	//
	//for (auto &ss : servicesToRemove)
	//	removeService(ss);
	//
	//for (auto &s : servicesArray)
	//{
    //    if (Thread::getCurrentThread()->threadShouldExit())
	//		return false;
    //    
    //    String host = m_servus.get(s.toStdString(), "servus_host");
	//	if (host.endsWithChar('.'))
	//		host = host.substring(0, host.length() - 1);
	//
	//	int port = String(m_servus.get(s.toStdString(), "servus_port")).getIntValue();
	//	String ip = getIPForHostAndPort(host, port);
	//
	//	bool isLocal = false;
	//	if (ip.isNotEmpty())
	//	{
	//		Array<IPAddress> localIps;
	//		IPAddress::findAllAddresses(localIps);
	//		for (auto &lip : localIps)
	//		{
	//			if (ip == lip.toString())
	//			{
	//				isLocal = true;
	//				break;
	//			}
	//		}
	//	}
	//
	//	if (isLocal)
	//		ip = IPAddress::local().toString();
	//
	//	ServiceInfo * info = getService(s, host, port);
	//	if (info == nullptr)
	//	{
	//		changed = true;
	//		addService(s, host, ip, port);
	//	}
	//	else if (info->host != host || info->port != port || info->ip != ip)
	//	{
	//		changed = true;
	//		updateService(info, host, ip, port);
	//	}
	//}

	return changed;
}

std::string ZeroconfSearcher::getIPForHostAndPort(std::string host, int port)
{
	std::string ip;

	struct addrinfo hints = { 0 };
	hints.ai_family = AF_INET;

	struct addrinfo* info = nullptr;
	getaddrinfo(host.c_str(), std::string(port).c_str(), &hints, &info);
	if (info == nullptr)
	{
		//DBG("Should not be null !");
		return "";
	}

	char * ipData = info->ai_addr->sa_data;
	if (info != nullptr)
		ip = std::string((uint8)ipData[2]) + "." + std::string((uint8)ipData[3]) + "." + std::string((uint8)ipData[4]) + "." + std::string((uint8)ipData[5]);
	
	freeaddrinfo(info);

	return ip;
}

ZeroconfSearcher::ServiceInfo * ZeroconfSearcher::GetService(std::string& sName, std::string& host, int port)
{
	for (auto &i : m_services)
	{
		if (Thread::getCurrentThread()->threadShouldExit())
			return nullptr;
		if (i->name == sName && i->host == host && i->port == port)
			return i;
	}
	return nullptr;
}

void ZeroconfSearcher::AddService(std::string& sName, std::string& host, std::string& ip, int port)
{
	if (Thread::getCurrentThread()->threadShouldExit())
		return;
	//NLOG("Zeroconf", "New " << name << " service discovered : " << sName << " on " << host << ", " << ip << ":" << port);
	//jassert(GetService(sName, host, port) == nullptr);
	m_services.push_back(new ServiceInfo{ sName, host, ip, port });

}

void ZeroconfSearcher::RemoveService(ServiceInfo * s)
{
	//jassert(s != nullptr);
	//NLOG("Zeroconf", name << " service removed : " << s->name);
	auto sit = std::find(m_services.begin(), m_services.end(), s);
	if (sit != m_services.end())
	{
		delete* sit;
		m_services.erase(sit);
	}
}

void ZeroconfSearcher::UpdateService(ServiceInfo * service, std::string& host, std::string& ip, int port)
{
	jassert(service != nullptr);
	//NLOG("Zeroconf", name << "service updated changed : " << name << " : " << host << ", " << ip << ":" << port);
	service->host = host;
	service->ip = ip;
	service->port = port;
}


const std::string& ZeroconfSearcher::GetName()
{
	return m_name;
}

const std::string& ZeroconfSearcher::GetServiceName()
{
	return m_serviceName;
}

const std::vector<ZeroconfSearcher::ServiceInfo*>& ZeroconfSearcher::GetServices()
{
	return m_services;
}

int ZeroconfSearcher::GetSocketIdx()
{
	return m_socketIdx;
}

}

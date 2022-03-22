/*
  ==============================================================================

    ZeroconfSearcher.cpp
    Created: 04 March 2022 22:10:00pm
    Author:  Christian Ahrens

  ==============================================================================
*/

#include "ZeroconfSearcher.h"

#include <iostream>


namespace ZeroconfSearcher
{


std::mutex							ZeroconfSearcher::s_mdnsEntryLock;
std::string                         ZeroconfSearcher::s_mdnsEntry = std::string();
std::string                         ZeroconfSearcher::s_mdnsEntryPTR = std::string();
std::string                         ZeroconfSearcher::s_mdnsEntrySRVName = std::string();
std::uint16_t                       ZeroconfSearcher::s_mdnsEntrySRVPort = std::uint16_t(0);
std::uint16_t                       ZeroconfSearcher::s_mdnsEntrySRVPriority = std::uint16_t(0);
std::uint16_t                       ZeroconfSearcher::s_mdnsEntrySRVWeight = std::uint16_t(0);
std::string                         ZeroconfSearcher::s_mdnsEntryAHost = std::string();
std::string                         ZeroconfSearcher::s_mdnsEntryAService = std::string();
std::string                         ZeroconfSearcher::s_mdnsEntryAAAAHost = std::string();
std::string                         ZeroconfSearcher::s_mdnsEntryAAAAService = std::string();
std::map<std::string, std::string>  ZeroconfSearcher::s_mdnsEntryTXT = std::map<std::string, std::string>();


//==============================================================================
ZeroconfSearcher::ZeroconfSearcher(std::string name, std::string serviceName) :
	m_name(name),
	m_serviceName(serviceName)
{
#ifdef _WIN32
	WORD versionWanted = MAKEWORD(1, 1);
	WSADATA wsaData;
	if (WSAStartup(versionWanted, &wsaData))
	{
		std::printf("Failed to initialize WinSock");
	}
#endif
		
	m_socketIdx = mdns_socket_open_ipv4(nullptr);
	if (m_socketIdx < 0)
	{
#ifdef _WIN32
		int error = WSAGetLastError();
		std::printf("mdns_socket_open_ipv4 returned error (LastError: %d)", error);
#endif
	}
	else
	{
		std::future<void> future = m_threadExitSignal.get_future();
		m_searcherThread = std::make_unique<std::thread>(&run, std::move(future), this);
	}
}

ZeroconfSearcher::~ZeroconfSearcher()
{
	m_threadExitSignal.set_value();
	m_searcherThread->join();

	mdns_socket_close(m_socketIdx);

	m_services.clear();

#ifdef _WIN32
	WSACleanup();
#endif
}

void ZeroconfSearcher::AddListener(ZeroconfSearcherListener* listener)
{
	m_listeners.push_back(listener);
}

void ZeroconfSearcher::RemoveListener(ZeroconfSearcherListener* listener)
{
	auto knownListener = std::find(m_listeners.begin(), m_listeners.end(), listener);
	if (knownListener != m_listeners.end())
		m_listeners.erase(knownListener);
}

bool ZeroconfSearcher::Search()
{
	bool changed = false;

	std::string queryName = m_serviceName + ".local";

	char buffer[512];
	int queryId = mdns_query_send(m_socketIdx, mdns_record_type_t::MDNS_RECORDTYPE_ANY, queryName.c_str(), queryName.length(), buffer, sizeof(buffer), 0);
	if (queryId < 0)
	{
		return false;
	}

	char userData[512];
	size_t responseCnt = mdns_query_recv(m_socketIdx, buffer, sizeof(buffer), reinterpret_cast<mdns_record_callback_fn>(&RecvCallback), userData, queryId);

	if (responseCnt > 0)
	{
		if (ZeroconfSearcher::s_mdnsEntryLock.try_lock())
		{
			ServiceInfo info;
			info.ip = ZeroconfSearcher::s_mdnsEntryAHost;
			info.port = ZeroconfSearcher::s_mdnsEntrySRVPort;
			info.host = ZeroconfSearcher::s_mdnsEntrySRVName;
			info.name = ZeroconfSearcher::s_mdnsEntryPTR;
			info.txtRecords = ZeroconfSearcher::s_mdnsEntryTXT;

			ZeroconfSearcher::s_mdnsEntryLock.unlock();

			if (!info.name.empty())
			{
				auto it = std::find_if(m_services.begin(), m_services.end(), [info](std::unique_ptr<ServiceInfo>& i_ref) { return (info.name == i_ref->name && info.host == i_ref->host && info.port == i_ref->port); });
				if (it != m_services.end())
					UpdateService(*it, info.ip, info.txtRecords);
				else
					AddService(info.name, info.host, info.ip, info.port, info.txtRecords);

				changed = true;
			}
		}
		else
			std::cout << __FUNCTION__ << " unlock for write access failed";
	}
	
	auto retryCount = 3;
	do
	{
		if (ZeroconfSearcher::s_mdnsEntryLock.try_lock())
		{
			ZeroconfSearcher::s_mdnsEntry.clear();
			ZeroconfSearcher::s_mdnsEntryPTR.clear();
			ZeroconfSearcher::s_mdnsEntrySRVName.clear();
			ZeroconfSearcher::s_mdnsEntrySRVPort = 0;
			ZeroconfSearcher::s_mdnsEntrySRVPriority = 0;
			ZeroconfSearcher::s_mdnsEntrySRVWeight = 0;
			ZeroconfSearcher::s_mdnsEntryAHost.clear();
			ZeroconfSearcher::s_mdnsEntryAService.clear();
			ZeroconfSearcher::s_mdnsEntryAAAAHost.clear();
			ZeroconfSearcher::s_mdnsEntryAAAAService.clear();
			ZeroconfSearcher::s_mdnsEntryTXT.clear();

			ZeroconfSearcher::s_mdnsEntryLock.unlock();

			break;
		}
		retryCount--;
	} while (retryCount > 0);
	
	if (retryCount == 0)
        std::cout << __FUNCTION__ << " max unlock retry count for clearing reached";
	
	return changed;
}

bool ZeroconfSearcher::CleanupStaleServices()
{
	auto staleServices = std::vector<ServiceInfo*>();
	for (auto& service : m_services)
	{
		auto staleTime = std::chrono::high_resolution_clock::now() - service->lastSeen;

		using namespace std::literals;
		if (staleTime > 5s)
			staleServices.push_back(service.get());
	}

	for (auto staleService : staleServices)
	{
		auto ssit = std::find_if(m_services.begin(), m_services.end(), [&](const auto& val) { return val.get() == staleService; });
		if (ssit != m_services.end())
			m_services.erase(ssit);
	}

	return !staleServices.empty();
}

void ZeroconfSearcher::BroadcastChanges()
{
	for (auto const& listener : m_listeners)
		listener->handleServicesChanged();
}

void ZeroconfSearcher::run(std::future<void> future, ZeroconfSearcher* searcherInstance)
{
	while (future.wait_for(std::chrono::milliseconds(1)) == std::future_status::timeout)
	{
		auto newServicesFound = searcherInstance->Search();
		auto existingServicesLost = searcherInstance->CleanupStaleServices();
		if (newServicesFound || existingServicesLost)
		{
			searcherInstance->BroadcastChanges();
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
	}
}

std::string ZeroconfSearcher::GetIPForHostAndPort(std::string host, int port)
{
	std::string ip;

	struct addrinfo hints = { 0 };
	hints.ai_family = AF_INET;

	struct addrinfo* info = nullptr;
	getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &info);
	if (info == nullptr)
	{
		return "";
	}

	char * ipData = info->ai_addr->sa_data;
	if (info != nullptr)
		ip = std::to_string((std::uint8_t)ipData[2]) + "." + std::to_string((std::uint8_t)ipData[3]) + "." + std::to_string((std::uint8_t)ipData[4]) + "." + std::to_string((std::uint8_t)ipData[5]);
	
	freeaddrinfo(info);

	return ip;
}

ZeroconfSearcher::ServiceInfo * ZeroconfSearcher::GetService(const std::string& name, const std::string& host, int port)
{
	for (auto &service : m_services)
	{
		//if (Thread::getCurrentThread()->threadShouldExit())
		//	return nullptr;

		if (service->name == name && service->host == host && service->port == port)
			return service.get();
	}
	return nullptr;
}

void ZeroconfSearcher::AddService(const std::string& name, const std::string& host, const std::string& ip, int port, const std::map<std::string, std::string>& txtRecords)
{
	//if (Thread::getCurrentThread()->threadShouldExit())
	//	return;

	m_services.push_back(std::make_unique<ServiceInfo>(ServiceInfo { name, host, ip, port, txtRecords, std::chrono::high_resolution_clock::now() }));

}

void ZeroconfSearcher::RemoveService(std::unique_ptr<ServiceInfo>& service)
{
	auto sit = std::find(m_services.begin(), m_services.end(), service);
	if (sit != m_services.end())
	{
		m_services.erase(sit);
	}
}

void ZeroconfSearcher::UpdateService(std::unique_ptr<ServiceInfo>& service, const std::string& ip, const std::map<std::string, std::string>& txtRecords)
{
	if (service == nullptr)
		return;

	service->ip = ip;
	for (auto const& record : txtRecords)
		service->txtRecords[record.first] = record.second;

	service->lastSeen = std::chrono::high_resolution_clock::now();
}

const std::string& ZeroconfSearcher::GetName()
{
	return m_name;
}

const std::string& ZeroconfSearcher::GetServiceName()
{
	return m_serviceName;
}

const std::vector<ZeroconfSearcher::ServiceInfo*> ZeroconfSearcher::GetServices()
{
	auto servicesPtrs = std::vector<ZeroconfSearcher::ServiceInfo*>();
	for (auto const& service : m_services)
		servicesPtrs.push_back(service.get());

	return servicesPtrs;
}

int ZeroconfSearcher::GetSocketIdx()
{
	return m_socketIdx;
}

}

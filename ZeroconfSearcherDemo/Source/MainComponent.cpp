/*
  ==============================================================================

    MainComponent.cpp
    Created: 28 Jul 2020 11:21:42am
    Author:  Christian Ahrens

  ==============================================================================
*/

#include "MainComponent.h"


namespace ZeroconfSearcherDemo
{

//==============================================================================
MainComponent::MainComponent()
{
    m_mDNSTree = std::make_unique<TreeView>();
	addAndMakeVisible(m_mDNSTree.get());

    m_mDNSTreeRootItem = std::make_unique<ParentTreeViewItem>();
    m_mDNSTreeRootItem->name = "mDNS services";
    m_mDNSTreeRootItem->setOpen(true);
    m_mDNSTree->setRootItem(m_mDNSTreeRootItem.get());
    
    m_OSCsearcher = std::make_unique<ZeroconfSearcher::ZeroconfSearcher>("Testsearcher", "_osc._udp");
    m_OSCsearcher->AddListener(this);

    m_OCAsearcher = std::make_unique<ZeroconfSearcher::ZeroconfSearcher>("Testsearcher", "_oca._tcp");
    m_OCAsearcher->AddListener(this);

	setSize(300, 440);
}

MainComponent::~MainComponent()
{
}

void MainComponent::paint (Graphics& g)
{
	g.fillAll(Colours::white);
}

void MainComponent::resized()
{
	auto panelDefaultSize = 45.0f;

        FlexBox fb;
        fb.flexDirection = FlexBox::Direction::column;
        fb.items.addArray({
            FlexItem(*m_mDNSTree.get()).withFlex(5) });

        fb.performLayout(getLocalBounds().toFloat());

}

void MainComponent::handleMessage(const Message& message)
{
    auto servicesUpdatedMessage = dynamic_cast<const ServicesUpdatedMessage *>(&message);
    if (servicesUpdatedMessage)
    {
        m_mDNSTreeRootItem->clearSubItems();

        for (auto const& service : servicesUpdatedMessage->serviceToHostIpMapping)
        {
            auto serviceSubItem = std::make_unique<ParentTreeViewItem>();
            serviceSubItem->name = service.first;

            auto host = std::get<0>(service.second);
            auto hostChildSubItem = std::make_unique<ChildTreeViewItem>();
            hostChildSubItem->name = "Host";
            hostChildSubItem->value = host;
            hostChildSubItem->setOpen(true);
            serviceSubItem->addSubItem(hostChildSubItem.release());

            auto ip = std::get<1>(service.second);
            auto ipChildSubItem = std::make_unique<ChildTreeViewItem>();
            ipChildSubItem->name = "IP";
            ipChildSubItem->value = ip;
            ipChildSubItem->setOpen(true);
            serviceSubItem->addSubItem(ipChildSubItem.release());

            serviceSubItem->setOpen(true);

            m_mDNSTreeRootItem->addSubItem(serviceSubItem.release());

        }
    }
}

void MainComponent::handleServicesChanged()
{
    auto message = new ServicesUpdatedMessage;

    for (auto const& service : m_OSCsearcher->GetServices())
        message->serviceToHostIpMapping.insert(std::make_pair(std::string(service->name), std::tuple<std::string, std::string>(service->host, service->ip)));

    for (auto const& service : m_OCAsearcher->GetServices())
        message->serviceToHostIpMapping.insert(std::make_pair(std::string(service->name), std::tuple<std::string, std::string>(service->host, service->ip)));

    postMessage(message);
}

}

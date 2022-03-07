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
    m_mDNSSearchServiceNamesEdit = std::make_unique<TextEditor>();
    m_mDNSSearchServiceNamesEdit->setText("_osc._udp;_oca._tcp;");
    m_mDNSSearchServiceNamesEdit->setColour(TextEditor::ColourIds::backgroundColourId, Colours::white);
    m_mDNSSearchServiceNamesEdit->setColour(TextEditor::ColourIds::outlineColourId, Colours::darkgrey);
    m_mDNSSearchServiceNamesEdit->setColour(TextEditor::ColourIds::focusedOutlineColourId, Colours::black);
    m_mDNSSearchServiceNamesEdit->setColour(TextEditor::ColourIds::textColourId, Colours::black);
    m_mDNSSearchServiceNamesEdit->applyColourToAllText(Colours::black);
    addAndMakeVisible(m_mDNSSearchServiceNamesEdit.get());

    m_mDNSSearchTriggerButton = std::make_unique<TextButton>("Search");
    m_mDNSSearchTriggerButton->setColour(TextButton::ColourIds::textColourOnId, Colours::darkgrey);
    m_mDNSSearchTriggerButton->setColour(TextButton::ColourIds::textColourOffId, Colours::black);
    m_mDNSSearchTriggerButton->setColour(TextButton::ColourIds::buttonOnColourId, Colours::lightgrey);
    m_mDNSSearchTriggerButton->setColour(TextButton::ColourIds::buttonColourId, Colours::white);
    m_mDNSSearchTriggerButton->addListener(this);
    addAndMakeVisible(m_mDNSSearchTriggerButton.get());

    m_mDNSTree = std::make_unique<TreeView>();
	addAndMakeVisible(m_mDNSTree.get());

    m_mDNSTreeRootItem = std::make_unique<ParentTreeViewItem>();
    m_mDNSTreeRootItem->name = "Discovered mDNS services";
    m_mDNSTreeRootItem->setOpen(true);
    m_mDNSTree->setRootItem(m_mDNSTreeRootItem.get());

	setSize(512, 512);
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
    auto bounds = getLocalBounds();

    auto headerControlElmBounds = bounds.removeFromTop(30).reduced(4);
    m_mDNSSearchTriggerButton->setBounds(headerControlElmBounds.removeFromRight(55));
    headerControlElmBounds.removeFromRight(4);
    m_mDNSSearchServiceNamesEdit->setBounds(headerControlElmBounds);

    m_mDNSTree->setBounds(bounds);

}

void MainComponent::handleMessage(const Message& message)
{
    auto servicesUpdatedMessage = dynamic_cast<const ServicesUpdatedMessage *>(&message);
    if (servicesUpdatedMessage)
    {
        m_mDNSTreeRootItem->clearSubItems();

        for (auto const& service : servicesUpdatedMessage->serviceToHostIpTxtMapping)
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

            auto txtRecParentSubItem = std::make_unique<ChildTreeViewItem>();
            txtRecParentSubItem->name = "TXT records";
            txtRecParentSubItem->setOpen(true);
            for (auto const& txtRecKV : std::get<2>(service.second))
            {
                auto txtRecChildSubItem = std::make_unique<ChildTreeViewItem>();
                txtRecChildSubItem->name = txtRecKV.first;
                txtRecChildSubItem->value = txtRecKV.second;
                txtRecChildSubItem->setOpen(true);
                txtRecParentSubItem->addSubItem(txtRecChildSubItem.release());
            }
            serviceSubItem->addSubItem(txtRecParentSubItem.release());

            serviceSubItem->setOpen(true);

            m_mDNSTreeRootItem->addSubItem(serviceSubItem.release());

        }
    }
}

void MainComponent::handleServicesChanged()
{
    auto message = new ServicesUpdatedMessage;

    for (auto const& searcher : m_zeroconfSearchers)
    {
        for (auto const& service : searcher->GetServices())
            if (service)
                message->serviceToHostIpTxtMapping.insert(std::make_pair(std::string(service->name), std::tuple<std::string, std::string, std::map<std::string, std::string>>(service->host, service->ip, service->txtRecords)));
    }

    postMessage(message);
}

void MainComponent::buttonClicked(Button* button)
{
    if (button == m_mDNSSearchTriggerButton.get())
    {
        m_zeroconfSearchers.clear();

        auto newServiceSearchNames = StringArray();
        newServiceSearchNames.addTokens(m_mDNSSearchServiceNamesEdit->getText(), ";,", ";,");
        auto i = 1;
        for (auto const& serviceSearchName : newServiceSearchNames)
        {
            if (serviceSearchName.isNotEmpty())
            {
                auto name = String("(") + String(i) + String(") ") + serviceSearchName;
                m_zeroconfSearchers.push_back(std::make_unique<ZeroconfSearcher::ZeroconfSearcher>(name.toStdString(), serviceSearchName.toStdString()));
                m_zeroconfSearchers.back()->AddListener(this);
                i++;
            }
        }
    }
}

}

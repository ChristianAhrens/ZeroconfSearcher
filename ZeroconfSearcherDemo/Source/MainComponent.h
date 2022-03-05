/*
  ==============================================================================

    MainComponent.h
    Created: 28 Jul 2020 11:21:42am
    Author:  Christian Ahrens

  ==============================================================================
*/

#pragma once

#include <JuceHeader.h>

#include "../../Source/ZeroconfSearcher.h"


namespace ZeroconfSearcherDemo
{

//==============================================================================
/*
    This component lives inside our window, and this is where you should put all
    your controls and content.
*/
class MainComponent   : public Component, public ZeroconfSearcher::ZeroconfSearcher::ZeroconfSearcherListener, public MessageListener
{
public:
    class ParentTreeViewItem : public TreeViewItem
    {
    public:
        bool mightContainSubItems() override
        {
            return true;
        }

        void paintItem(Graphics& g, int width, int height) override
        {
            auto area = juce::Rectangle<int>(0, 0, width, height);
            g.drawText(name, area.reduced(2), juce::Justification::left);
        }

        String name;
    };
    class ChildTreeViewItem : public TreeViewItem
    {
    public:
        bool mightContainSubItems() override
        {
            return false;
        }

        void paintItem(Graphics& g, int width, int height) override
        {
            auto area = juce::Rectangle<int>(0, 0, width, height);
            auto nameArea = area.removeFromLeft(50);
            auto valueArea = area;
            g.drawText(name, nameArea.reduced(2), juce::Justification::left);
            g.drawText(value, valueArea.reduced(2), juce::Justification::left);
        }

        String name;
        String value;
    };
    class ServicesUpdatedMessage : public Message
    {
    public:
        std::map< std::string, std::tuple<std::string, std::string>> serviceToHostIpMapping;
    };

public:
    //==============================================================================
    MainComponent();
    ~MainComponent();

    //==============================================================================
    void paint (Graphics&) override;
    void resized() override;

    //==============================================================================
    void handleMessage(const Message& message) override;

    //==============================================================================
    void handleServicesChanged() override;
    
private:
    
    //==============================================================================
    std::unique_ptr<ParentTreeViewItem>                 m_mDNSTreeRootItem;
    std::unique_ptr<TreeView>                           m_mDNSTree;
    std::unique_ptr<ZeroconfSearcher::ZeroconfSearcher> m_OSCsearcher;
    std::unique_ptr<ZeroconfSearcher::ZeroconfSearcher> m_OCAsearcher;


    JUCE_DECLARE_NON_COPYABLE_WITH_LEAK_DETECTOR (MainComponent)
};

}

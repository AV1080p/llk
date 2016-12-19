# -*- coding: utf-8 -*-

from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_ipaddress(SpiderFootPlugin):
    """IpAddress:Investigate,Passive:information:errorprone:ip address list"""

    # Default options
    opts = {
    }

    # Option descriptions
    optdescs = {
    }

    # Target
    results = list()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = list()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DNSINFO_IP"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["IP_ADDRESS", "IP_ADDRESS_LAN"]

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            self.sf.debug("Already exist " + eventData + ", skipping.")
            return None
        else:
            self.results.append(eventData)

        if eventData.split('.')[0] = '10':
            evt = SpiderFootEvent("IP_ADDRESS_LAN", eventData, self.__name__, event)
            self.notifyListeners(evt)
        elif eventData.split('.')[0] = '172':
            evt = SpiderFootEvent("IP_ADDRESS_LAN", eventData, self.__name__, event)
            self.notifyListeners(evt)
        elif eventData.split('.')[0] = '192' and eventData.split('.')[1] = '168' :
            evt = SpiderFootEvent("IP_ADDRESS_LAN", eventData, self.__name__, event)
            self.notifyListeners(evt)
        else:
            evt = SpiderFootEvent("IP_ADDRESS", eventData, self.__name__, event)
            self.notifyListeners(evt)
'''
        # Sites hosted on the domain
        pages = self.sf.googleIterate("site:" + eventData,
                                      dict(limit=self.opts['pages'], useragent=self.opts['_useragent'],
                                           timeout=self.opts['_fetchtimeout']))
        if pages is None:
            self.sf.info("No results returned from Google.")
            return None

        for page in pages.keys():
            found = False
            if page in self.results:
                continue
            else:
                self.results.append(page)

            links = self.sf.parseLinks(page, pages[page], eventData)
            if len(links) == 0:
                continue

            for link in links:
                if self.checkForStop():
                    return None

                if link in self.results:
                    continue
                else:
                    link = self.sf.urlFQDN(link)
                    self.results.append(link)
                #iself.sf.debug("Found a link: " + link)
                if self.sf.urlFQDN(link).endswith(eventData):
                    #found = True
                    #self.sf.debug("Found a link: " + eventData)
                    evt = SpiderFootEvent("SUBDOMAIN", link,
                                          self.__name__, event)
                    self.notifyListeners(evt)

                if found:
                # Submit the google results for analysis
                evt = SpiderFootEvent("SEARCH_ENGINE_WEB_CONTENT", pages[page],
                                      self.__name__, event)
                self.notifyListeners(evt)
'''

# End of sfp_googlesearch class

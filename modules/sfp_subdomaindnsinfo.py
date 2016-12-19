# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_googlesearch
# Purpose:      Searches Google for content related to the domain in question.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     07/05/2012
# Copyright:   (c) Steve Micallef 2012
# Licence:     GPL
# -------------------------------------------------------------------------------

from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent
from ext.dnsinfo.flint import FlintClient
import urllib
import re
import sys

class sfp_subdomaindnsinfo(SpiderFootPlugin):
    """SubDomainDnsInfo:Footprint,Investigate,Passive:Web Interface:errorprone:DNSinfo web interface scraping to identify sub-domains."""

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
        self.config = {}
        for line in open('/root/flint.conf'):
            line = line.strip()
            if not line:
                continue
            if line.startswith("#"):
                continue
            key, eq, val = line.partition('=')
            key = key.strip()
            val = val.strip().strip('"')
            self.config[key] = val
        API = self.config.get("API", "")
        API_ID = self.config.get("API_ID","")
        API_KEY = self.config.get("API_KEY", "")
        self.flint = FlintClient(API, API_ID, API_KEY, False)

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DOMAIN_NAME"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["DNSINFO_SUBDOMAIN", "DNSINFO_IP"]

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        domain = event.data

        if domain in self.results:
            self.sf.debug("Already did a search for " + domain + ", skipping.")
            return None
        else:
            self.results.append(domain)

        f_keyword = '*.' + domain
        self.flint("rrset", f_keyword, "A")
        resultsDomainIp = self.flint.getresultsData()
        if not resultsDomainIp:
            self.sf.debug("resultsDomainIp empty!")
            return None

        for domainip in resultsDomainIp:
            domainTemp = domainip.split("|A|")[0]
            if not fliterDomain(domainTemp):
                continue
            ipTemp = domainip.split("|A|")[1]
            if domainTemp not in self.results:
                self.results.append(domainTemp)
                self.sf.debug("Found a subdomain: " + domainTemp)
                evt = SpiderFootEvent("DNSINFO_SUBDOMAIN", domainTemp, self.__name__, event)
                self.notifyListeners(evt)
            if ipTemp not in self.results:
                self.results.append(ipTemp)
                self.sf.debug("Found a ip: " + ipTemp)
                evt = SpiderFootEvent("DNSINFO_IP", ipTemp, self.__name__, event)
                self.notifyListeners(evt)
    def fliterDomain(subdomain):
        az19 = "abcdefghijklmnopqrstuvwxyz1234567890"
        if az19.find(subdomain[0]) == -1:
            return False
        return True

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
                    evt = SpiderFootEvent("GOOGLE_SUBDOMAIN", link,
                                          self.__name__, event)
                    self.notifyListeners(evt)
'''
'''
                if found:
                # Submit the google results for analysis
                evt = SpiderFootEvent("SEARCH_ENGINE_WEB_CONTENT", pages[page],
                                      self.__name__, event)
                self.notifyListeners(evt)
'''

# End of sfp_googlesearch class

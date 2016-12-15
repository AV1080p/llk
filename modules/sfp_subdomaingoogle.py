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
from mixins.search import GoogleWebMixin


class sfp_subdomaingoogle(SpiderFootPlugin):
    """SubDomainGoogle:Footprint,Investigate,Passive:Search Engines:errorprone:Some light Google scraping to identify sub-domains."""

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
        return ["DOMAIN_NAME"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["GOOGLE_SUBDOMAIN" ,"GOOGLE_URL"]

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        domain = event.data
        regmatch = re.compile('//([^/]*\.%s)' % (domain))

        if domain in self.results:
            self.sf.debug("Already did a search for " + domain + ", skipping.")
            return None
        else:
            self.results.append(domain)

        base_query = 'site:' + domain
        # control variables
        page = 1
        # execute search engine queries and scrape results storing subdomains in a list
        # loop until no new subdomains are found
        # build query based on results of previous results
        query = ''
        # send query to search engine
        results = self.search_google_web(base_query + query, limit=0, start_page=page)
        # extract hosts from search results
        sites = []
        for link in results:
            site = regmatch.search(link)
            if site is not None:
                sites.append(site.group(1))
            # create a unique list
        sites = list(set(sites))
        # add subdomain to list if not already exists
        for site in sites:
            if site not in self.results:
                self.results.append(site)
                self.sf.debug("Found a link: " + site)
                evt = SpiderFootEvent("GOOGLE_SUBDOMAIN", site, self.__name__, event)
                elf.notifyListeners(evt)
       


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

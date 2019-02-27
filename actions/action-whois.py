#!/usr/bin/env pythonx

import re

from st2common.content import utils
from st2common.runners.base_action import Action

from whois import whois


from urlparse import urlparse

class Whois(Action):
    def run(self, query, cmd, *args):

        # rip out newlines and gibberish
        query = query.strip()
        # replace the misp-style de-fanging
        query = query.replace("[", "")
        query = query.replace("]", "")

        parsed_uri = urlparse(query)
        # if it's an IP address
        if parsed_uri.netloc == '' and re.match('^\d{,3}\.\d{,3}\.\d{,3}\.\d{,3}$', query):
            self.logger.debug("whois on ip '{}'".format(query))
            w = whois(query)
        elif parsed_uri.netloc == '' and parsed_uri.path != '':
            self.logger.debug("whois on domain '{}'".format(parsed_uri.path))    
            w = whois(parsed_uri.path)
        else:
            self.logger.debug("whois on domain '{}'".format(parsed_uri.netloc))
            w = whois(parsed_uri.netloc)
        result = {}
        for key in w.keys():
            if w[key]:
                result[key] = w[key]
        result['text'] = "I'm a little teapot" # w.text
        return (True, result)

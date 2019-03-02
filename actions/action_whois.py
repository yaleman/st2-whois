#!/usr/bin/env python

import re
from datetime import datetime

if __name__ != '__main__':
    from st2common.content import utils
    from st2common.runners.base_action import Action

import whois

from urlparse import urlparse

from whois_lib import *

class Whois(Action):
    def run(self, query, cmd, *args):

        # rip out newlines and gibberish
        query = query.strip()
        # replace the misp-style de-fanging
        query = query.replace("[", "")
        query = query.replace("]", "")

        parsed_uri = urlparse(query)
        # if it's an IP address
        try:
            if parsed_uri.netloc == '' and re.match('^\d{,3}\.\d{,3}\.\d{,3}\.\d{,3}$', query):
                self.logger.debug("whois on ip '{}'".format(query))
                w = whois.whois(query)
            elif parsed_uri.netloc == '' and parsed_uri.path != '':
                self.logger.debug("whois on domain '{}'".format(parsed_uri.path))    
                w = whois.whois(parsed_uri.path)
            else:
                self.logger.debug("whois on domain '{}'".format(parsed_uri.netloc))
                w = whois.whois(parsed_uri.netloc)
        except whois.parser.PywhoisError as e:
            return (False, {'error' : e})

        if w.get('status', False) == False:
            return (False, {'error' : "No result returned"})

        result = clean_dict(w)
        result['text'] = w.text.replace(">>> ", "--- ").replace(" <<<", " ---")
        return (True, result)

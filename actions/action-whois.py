#!/usr/bin/env pythonx

import re

from st2common.content import utils
from st2common.runners.base_action import Action

from whois import whois


from urlparse import urlparse

class Whois(Action):
    def run(self, query, cmd, *args):

        query = query.replace("[", "")
        query = query.replace("]", "")

        parsed_uri = urlparse(query)
        # if it's an IP address
        if parsed_uri.netloc == '' and re.match('^\d{,3}\.\d{,3}\.\d{,3}\.\d{,3}$', query):
            print("whois on ip {}".format(query))
            w = whois(query)
        else:
            print('whois on domain {}'.format(parsed_uri.netloc))
            w = whois(parsed_uri.netloc)

        return w

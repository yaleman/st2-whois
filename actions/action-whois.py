#!/usr/bin/env python


from st2common.content import utils
from st2common.runners.base_action import Action

from whois import whois

from urllib.parse import urlparse
class Whois(Action):
    def run(self, query, cmd, *args):

        query = query.replace("[", "")
        query = query.replace("]", "")

        parsed_uri = urlparse(query)

        w = whois(parsed_uri.netloc)

        return w

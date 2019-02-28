#!/usr/bin/env pythonx

import re
from datetime import datetime

from st2common.content import utils
from st2common.runners.base_action import Action

import whois


from urlparse import urlparse

def clean_list(data):
    """ takes any dict, but typically the return value of an Action, and cleans up any data that'll make
        stackstorm have a hissy fit """
    result = {}
    # go through the results and put it in a form that stackstorm can take
    for key in data.keys():
        if isinstance(data[key], datetime): # datetime is bad, m'kay
            result[key] = str(data[key])
        # because sometimes, people make lists of problematic elements!
        elif isinstance(data[key], list):
            result[key] = clean_list(data[key])
        elif isinstance(w[key], unicode): # something can't handle the unicode conversion...
            result[key] = str(w[key])
        # everything else I got was OK... 
        else:
            result[key] = w[key]
    return result

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

        result = clean_list(w)
        result['text'] = w.text
        return (True, result)

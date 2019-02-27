#!/usr/bin/env python


from st2common.content import utils
from st2common.runners.base_action import Action


class Whois(Action):
    def run(self, query):
        #result = {
        #    'pack_group': utils.get_pack_group(),
        #    'pack_path': utils.get_system_packs_base_path()
        #}

        return "This should be a result, whois for {}".format(query)

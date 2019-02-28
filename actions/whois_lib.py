
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
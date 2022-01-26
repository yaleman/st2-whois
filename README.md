# ⚠️ THIS IS ARCHIVED AND WILL NOT BE UPDATED ⚠️

Whois pack for stackstorm
===

This is a pretty simple implementation of whois for stackstorm. Works in `python2` for now - I will test in `python3` soon.

Tweet @yaleman43381258 if you want to yell at me, or file a bug.

## Actions

`whois.whois` - returns a lot of different things, the easiest visual version is `result.text` but there's many others depending on your `query` value.

## Aliases

`whois {{query}}` will do a whois lookup and return the full string result as if you were on the command line.

## Changelog

* 2019-02-27 - v1.0.5 - Initial writeup of the code, thought I had it right but oh how wrong I was.
* 2019-02-28 - v1.0.6 - Moved bad-data-cleaning code out of the Action into a separate function/lib, can handle arbitrary-layout data.
* 2019-03-02 - v1.0.7 - Changed whois_lib to change datetime objects to isoformat instead of str()'ing them.

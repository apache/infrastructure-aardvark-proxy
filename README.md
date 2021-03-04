# Aardvark - An anti-spam proxy server

Aardvark acts as a middleman between frontend web servers and (typically) ticket submission services such as JIRA or BugZilla, and intercepts all data sent.
POST Data is scanned for known offending words that are common in spam, and if found to be spam, the request is blocked.
Aardvark keeps an internal list of offending IPs, and will block any subsequent POST requests from those IPs (until restarted).

Aardvark is written in Python3 and uses [aiohttp](https://github.com/aio-libs/aiohttp) for its server/client capabilities.

![diagram](aardvark.png)

## Settings:

- **General settings**:
- - `port`: Which port to listen on for scans. For security reasons, Aardvark will bind to localhost. Default is [1729](https://en.wikipedia.org/wiki/1729_(number))
- - `proxy_url`: The backend service to proxy to if request is sane
- - `ipheader`: The header to look for the client's IP in. Typically X-Forwarded-For.
- - `debug`: If set to `true`, will spit out some extra lines for reach request handled. Can get very spammy.
- **Scan settings**:
- - `naive_spam_threshold`: This is the spam score threshold for the naïve scanner, `spamfilter.py`. It uses a pre-generated English corpus for detecting spam.
- - `spamurls`: Specific honey-pot URLs that trigger a block regardless of the action
- - `ignoreurls`: Specific URLs that are exempt from spam detection
- - `postmatches`: A list of keywords and/or regexes that, if matched, will block the request
- - `multimatch`: A combination blocker. If a `required` keyword or regex is matched, the request will be blocked only if one or more `auxiliary` keywords/regexes are also matched
- **Scoreboard settings**:
- - `persistence`: Enables persistent storage of offending IPs in `blocklist.txt`. Enabling this also enables you to use unblock.py (to be enhanced further at a later point).
- - `savedata`: A path which, if set, is where debug data from offending requests will be saved. This is typically the full first request an IP makes.
- - `suppress_repeats`: Suppresses repeat syslog entries for known offenders. `debug: true` will override this.

## Naïve Spam Scan
Aardvark contains a very naïve spam scanner in `spamfilter.py` that uses a very simplified Bayes-esque formula for
determining whether something is spam. It is enabled for form data only, and can be disabled entirely by 
setting `enable_naive_scan` to `false`. It has a built-in corpus with ham and spam in English, and works...sometimes :)

It is very much a work in progress, but should be safe to have enabled.


## Pipservicing

To enable as a pipservice, add the following minimal hiera yaml to your node config:

~~~yaml
pipservice:
  aardvark-proxy:
    tag: main
~~~

## Running manually
Follow these steps to run manually (assuming you have [pipenv](https://pypi.org/project/pipenv/) installed):

- `git clone https://github.com/apache/infrastructure-aardvark-proxy.git aardvark-proxy`
- `cd aardvark-proxy`
- `pipenv install -r requirements.txt`
- `pipenv run python3 aardvark.py`

## HTTPd configuration example
As Aardvark is a proxy middleman for specific purposes, you will preferably need a web server in front.
The example below relays all POST requests for /foo/bar through Aardvark, while letting all GETs etc 
go directly to the backend service.

Assuming Aardvark is listening on port `1729` and the real backend service is on port `8080`:

~~~apache
# Send all POST requests through Aardvark
RewriteEngine On
RewriteCond %{REQUEST_METHOD} POST
RewriteRule ^/(.*)$ http://localhost:1729/$1 [P]
# Rest goes to backend directly
ProxyPass / http://localhost:8080/foo/bar/
~~~


## Unblocking an IP
IPs can be unblocked in a couple of ways:

- bouncing Aardvark without persistence, this resets the block list
- manually editing the block list file (if persistence is turned on) and bouncing Aardvark
- using unblock.py: `python3 unblock.py ip.goes.here`
- Using cURL: `curl 'http://localhost:1729/aardvark-unblock?ip.goes.here' -H 'X-Aardvark-Key: uuid-from-blocklist.txt'`

# Aardvark - An anti-spam proxy server

Aardvark acts as a middleman between frontend web servers and (typically) ticket submission services such as JIRA or BugZilla, and intercepts all data sent.
POST Data is scanned for known offending words that are common in spam, and if found to be spam, the request is blocked.
Aardvark keeps an internal list of offending IPs, and will block any subsequent POST requests from those IPs (until restarted).

Aardvark is written in Python3 and uses [aiohttp](https://github.com/aio-libs/aiohttp) for its server/client capabilities.

![diagram](aardvark.png)

## Settings:

- `port`: Which port to listen on for scans. For security reasons, Aardvark will bind to localhost. Default is [1729](https://en.wikipedia.org/wiki/1729_(number))
- `proxy_url`: The backend service to proxy to if request is sane
- `ipheader`: The header to look for the client's IP in. Typically X-Forwarded-For.
- `naive_spam_threshold`: This is the spam score threshold for the naïve scanner, `spamfilter.py`. It uses a pre-generated English corpus for detecting spam.
- `spamurls`: Specific honey-pot URLs that trigger a block regardless of the action
- `ignoreurls`: Specific URLs that are exempt from spam detection
- `postmatches`: A list of keywords and/or regexes that, if matched, will block the request
- `multimatch`: A combination blocker. If a `required` keyword or regex is matched, the request will be blocked only if one or more `auxiliary` keywords/regexes are also matched

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

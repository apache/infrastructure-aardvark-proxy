#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import asyncio
import aiohttp
import aiohttp.web
import aiohttp.client_exceptions
import urllib.parse
import yaml
import time
import re
import asfpy.syslog
import typing
import multidict
import spamfilter

# Shadow print with our syslog wrapper
print = asfpy.syslog.Printer(stdout=True, identity="aardvark")


# Some defaults to keep this running without a yaml
DEFAULT_PORT = 4321
DEFAULT_BACKEND = "http://localhost:8080"
DEFAULT_IPHEADER = "x-forwarded-for"
DEFAULT_BLOCK_MSG = "No Cookie!"
DEFAULT_DEBUG = False
DEFAULT_NAIVE = True
DEFAULT_SPAM_NAIVE_THRESHOLD = 60
MINIMUM_SCAN_LENGTH = 16  # We don't normally scan form data elements with fewer than 16 chars


class Aardvark:
    def __init__(self, config_file: str = "aardvark.yaml"):
        """ Load and parse the config """

        # Type checking hints for mypy
        self.scan_times: typing.List[float]
        self.last_batches: typing.List[float]
        self.processing_times: typing.List[float]
        self.offenders: typing.Set[str]
        self.spamurls: typing.Set[re.Pattern]
        self.postmatches: typing.Set[re.Pattern]
        self.multispam_auxiliary: typing.Set[re.Pattern]
        self.multispam_required: typing.Set[re.Pattern]

        # Init vars with defaults
        self.config = {}  # Our config, unless otherwise specified in init
        self.debug = False  # Debug prints, spammy!
        self.block_msg = DEFAULT_BLOCK_MSG
        self.proxy_url = DEFAULT_BACKEND  # Backend URL to proxy to
        self.port = DEFAULT_PORT  # Port we listen on
        self.ipheader = DEFAULT_IPHEADER  # Standard IP forward header
        self.last_batches = []  # Last batches of requests for stats
        self.scan_times = []  # Scan times for stats
        self.processing_times = []  # Request proxy processing times for stats
        self.postmatches = set()  # SPAM POST data simple matches
        self.spamurls = set()  # Honey pot URLs
        self.ignoreurls = set()  # URLs we should not scan
        self.multispam_required = set()  # Multi-Match required matches
        self.multispam_auxiliary = set()  # Auxiliary Multi-Match strings
        self.offenders = set()  # List of already known offenders (block right out!)
        self.naive_threshold = DEFAULT_SPAM_NAIVE_THRESHOLD
        self.enable_naive = DEFAULT_NAIVE

        # If config file, load that into the vars
        if config_file:
            self.config = yaml.safe_load(open(config_file, "r"))
            self.debug = self.config.get("debug", self.debug)
            self.proxy_url = self.config.get("proxy_url", self.proxy_url)
            self.port = int(self.config.get("port", self.port))
            self.ipheader = self.config.get("ipheader", self.ipheader)
            self.block_msg = self.config.get("spam_response", self.block_msg)
            self.enable_naive = self.config.get("enable_naive_scan", self.enable_naive)
            self.naive_threshold = self.config.get("naive_spam_threshold", self.naive_threshold)
            for pm in self.config.get("postmatches", []):
                r = re.compile(bytes(pm, encoding="utf-8"), flags=re.IGNORECASE)
                self.postmatches.add(r)
            for su in self.config.get("spamurls", []):
                r = re.compile(su, flags=re.IGNORECASE)
                self.spamurls.add(r)
            self.ignoreurls = self.config.get("ignoreurls", [])
            multimatch = self.config.get("multimatch", {})
            if multimatch:
                for req in multimatch.get("required", []):
                    r = re.compile(bytes(req, encoding="utf-8"), flags=re.IGNORECASE)
                    self.multispam_required.add(r)
                for req in multimatch.get("auxiliary", []):
                    r = re.compile(bytes(req, encoding="utf-8"), flags=re.IGNORECASE)
                    self.multispam_auxiliary.add(r)
        if self.enable_naive:
            print("Loading Naïve Bayesian spam filter...")
            self.spamfilter = spamfilter.BayesScanner()

    def scan_simple(self, request_url: str, post_data: bytes = None):
        """Scans post data for spam"""
        bad_items = []

        # Check for honey pot URLs
        for su in self.spamurls:
            if su.match(request_url):
                bad_items.append(f"Request URL '{request_url}' matches honey pot URL '{su.pattern}'")

        # Standard POST data simple matches
        for pm in self.postmatches:
            if pm.search(post_data):
                bad_items.append("Found offending match in POST data: " + str(pm.pattern, encoding="utf-8"))

        # Multimatch check where one _required_ match is needed, PLUS one or more _auxiliary_ matches.
        # Thus, "phone support" does not match, but "for phone support, call 1-234-453-2383" will.
        for req in self.multispam_required:
            if req.search(post_data):
                for aux in self.multispam_auxiliary:
                    if aux.search(post_data):
                        bad_items.append(
                            f"Found multi-match in POST data: '%s' + '%s'"
                            % (str(req.pattern, encoding="utf-8"), str(aux.pattern, encoding="utf-8"))
                        )

        return bad_items

    def scan_dict(self, post_dict: multidict.MultiDictProxy):
        """Scans form data dicts for spam"""
        bad_items = []
        for k, v in post_dict.items():
            if v and isinstance(v, str) and len(v) >= MINIMUM_SCAN_LENGTH:
                b = bytes(v, encoding="utf-8")
                bad_items.extend(self.scan_simple(f"formdata::{k}", b))
                # Use the naïve scanner as well?
                if self.enable_naive:
                    res = self.spamfilter.scan_text(v)
                    if res >= self.naive_threshold:
                        bad_items.append(f"Form element {k} has spam score of {res}, crosses threshold of {self.naive_threshold}!")
        return bad_items

    async def proxy(self, request: aiohttp.web.Request):
        """Handles each proxy request"""
        request_url = "/" + request.match_info["path"]
        now = time.time()
        target_url = urllib.parse.urljoin(self.proxy_url, request_url)
        if self.ipheader:
            remote_ip = request.headers.get(self.ipheader, request.remote)
        else:
            remote_ip = request.remote
        if self.debug:
            print(f"Proxying request to {target_url}...")  # This can get spammy, default is to not show it.

        # Debug output for syslog
        self.last_batches.append(time.time())
        if len(self.last_batches) >= 5000:
            diff = self.last_batches[-1] - self.last_batches[0]
            diff += 0.01
            self.last_batches = []
            print("Last 5k anti spam scans done at %.2f req/sec" % (5000 / diff))
            if self.processing_times:
                avg = sum(self.processing_times) / len(self.processing_times)
                self.processing_times = []
                print("Average request proxy response time is %.2f ms" % (avg * 1000.0))
            if self.scan_times:
                avg = sum(self.scan_times) / len(self.scan_times)
                self.scan_times = []
                print("Average request scan time is %.2f ms" % (avg * 1000.0))

        # Read POST data and query string
        post_dict = await request.post()  # Request data as key/value pairs if applicable
        post_data = None
        if not post_dict:
            post_data = await request.read()  # Request data as a blob if not valid form data
        get_data = request.rel_url.query

        # Perform scan!
        bad_items = []

        # Check if offender is in out registry already
        if remote_ip in self.offenders:
            bad_items.append("Client is on the list of bad offenders.")
        else:
            bad_items = []
            if post_data:
                bad_items.extend(self.scan_simple(request_url, post_data))
            elif post_dict:
                bad_items.extend(self.scan_dict(post_dict))
            #  If this URL is actually to be ignored, forget all we just did!
            if bad_items:
                for iu in self.ignoreurls:
                    if iu in request_url:
                        print(f"Spam was detected from {remote_ip} but URL '{request_url} is on ignore list, so...")
                        bad_items = []
                        break

        if bad_items:
            print(f"Request from {remote_ip} to '{request_url}' contains possible spam:")
            for item in bad_items:
                print(f"[{remote_ip}]: {item}")

        # Done with scan, log how long that took
        self.scan_times.append(time.time() - now)

        # If bad items were found, don't proxy, return empty response
        if bad_items:
            self.offenders.add(remote_ip)
            self.processing_times.append(time.time() - now)
            return aiohttp.web.Response(text=self.block_msg, status=403)

        async with aiohttp.ClientSession() as session:
            try:
                req_headers = request.headers.copy()
                if post_dict:
                    del req_headers["content-length"]
                async with session.request(
                    request.method,
                    target_url,
                    headers=req_headers,
                    params=get_data,
                    data=post_dict or post_data,
                    timeout=30,
                ) as resp:
                    result = resp
                    raw = await result.read()
                    headers = result.headers.copy()
                    # We do NOT want chunked T-E! Leave it to aiohttp
                    if "Transfer-Encoding" in headers:
                        del headers["Transfer-Encoding"]
                    self.processing_times.append(time.time() - now)
                    return aiohttp.web.Response(body=raw, status=result.status, headers=headers)
            except aiohttp.client_exceptions.ClientConnectorError as e:
                print("Could not connect to backend: " + str(e))
                self.processing_times.append(time.time() - now)

        self.processing_times.append(time.time() - now)
        return aiohttp.web.Response(text=self.block_msg, status=403)


async def main():
    aar = Aardvark()
    app = aiohttp.web.Application()
    app.router.add_route("*", "/{path:.*?}", aar.proxy)
    runner = aiohttp.web.AppRunner(app)

    await runner.setup()
    site = aiohttp.web.TCPSite(runner, "localhost", aar.port)
    print("Starting Aardvark Anti Spam Proxy")
    await site.start()
    print(f"Started on port {aar.port}")
    while True:
        await asyncio.sleep(60)


if __name__ == "__main__":
    try:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        pass

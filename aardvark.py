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
import urllib.parse
import yaml
import time
import re

class Aardvark:
    config = {}                                 # Our config, unless otherwise specified in init
    proxy_url = "http://localhost:8000"         # Backend URL to proxy to
    port = 8080                                 # Port we listen on
    last_batches = []                           # Last batches of requests for stats
    scan_times = []                             # Scan times for stats
    processing_times = []                       # Request proxy processing times for stats
    postmatches = []                            # SPAM POST data simple matches
    spamurls = []                               # Honey pot URLs
    ignoreurls = []                             # URLs we should not scan
    multispam_required = []                     # Multi-Match required matches
    multispam_auxiliary = []                    # Auxiliary Multi-Match strings
    offenders = []                              # List of already known offenders (block right out!)

    def init(self, config_file="aardvark.yaml"):
        """ Load and parse the config """
        if config_file:
            self.config = yaml.safe_load(open(config_file, "r"))
            self.proxy_url = self.config.get("proxy_url", self.proxy_url)
            self.port = int(self.config.get('port', self.port))
            for pm in self.config.get("postmatches", []):
                r = re.compile(bytes(pm, encoding="utf-8"), flags=re.IGNORECASE)
                self.postmatches.append(r)
            for su in self.config.get("spamurls", []):
                r = re.compile(su, flags=re.IGNORECASE)
                self.spamurls.append(r)
            self.ignoreurls = self.config.get("ignoreurls", [])
            multimatch = self.config.get("multimatch", {})
            if multimatch:
                for req in multimatch.get("required", []):
                    r = re.compile(bytes(req, encoding="utf-8"), flags=re.IGNORECASE)
                    self.multispam_required.append(r)
                for req in multimatch.get("auxiliary", []):
                    r = re.compile(bytes(req, encoding="utf-8"), flags=re.IGNORECASE)
                    self.multispam_auxiliary.append(r)

    async def proxy(self, request):
        """Handles each proxy request"""
        request_url = "/" + request.match_info["path"]
        now = time.time()
        target_url = urllib.parse.urljoin(self.proxy_url, request_url)
        # print(f"Proxying request to {target_url}...")  # Tooooo spammy, keep it clean

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
        post_data = await request.read()
        get_data = request.rel_url.query

        # Perform scan!
        bad_items = []

        # Check if offender is in out registry already
        if request.remote in self.offenders:
            bad_items.append("Client is on the list of bad offenders.")

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

        #  If this URL is actually to be ignored, forget all we just did!
        if bad_items:
            for iu in self.ignoreurls:
                if iu in request_url:
                    print(f"Spam was detected from {request.remote} but URL '{request_url} is on ignore list, so...")
                    bad_items = []
                    break

        if bad_items:
            print(f"Request from {request.remote} to '{request_url}' contains possible spam:")
            for item in bad_items:
                print(f"[{request.remote}]: {item}")

        # Done with scan, log how long that took
        self.scan_times.append(time.time() - now)

        # If bad items were found, don't proxy, return empty response
        if bad_items:
            if request.remote not in self.offenders:
                self.offenders.append(request.remote)
            self.processing_times.append(time.time() - now)
            return None

        async with aiohttp.ClientSession() as session:
            try:
                async with session.request(
                    request.method, target_url, headers=request.headers, params=get_data, data=post_data
                ) as resp:
                    result = resp
                    raw = await result.read()
            except aiohttp.client_exceptions.ClientConnectorError as e:
                print("Could not connect to backend: " + str(e))
                self.processing_times.append(time.time() - now)
                return None

        self.processing_times.append(time.time() - now)
        return aiohttp.web.Response(body=raw, status=result.status, headers=result.headers)


async def main():
    A = Aardvark()
    A.init()
    app = aiohttp.web.Application()
    app.router.add_route("*", "/{path:.*?}", A.proxy)
    runner = aiohttp.web.AppRunner(app)

    await runner.setup()
    site = aiohttp.web.TCPSite(runner, "localhost", 8080)
    print("Starting Aardvark Anti Spam Proxy")
    await site.start()
    print("Started on port 8080")
    while True:
        await asyncio.sleep(60)


if __name__ == "__main__":
    try:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        pass

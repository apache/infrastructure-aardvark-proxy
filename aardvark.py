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
import os
import asfpy.syslog
import typing
import multidict
import uuid
import spamfilter
import aiofile
import platform
import datetime

# Shadow print with our syslog wrapper
print = asfpy.syslog.Printer(stdout=True, identity="aardvark")

# Some defaults to keep this running without a yaml
DEFAULT_PORT = 1729
DEFAULT_BACKEND = "http://localhost:8080"
DEFAULT_MAX_REQUEST_SIZE = 1024 ** 2
DEFAULT_IPHEADER = "x-forwarded-for"
DEFAULT_BLOCK_MSG = "No Cookie!"
DEFAULT_SAVE_PATH = "/tmp/aardvark"
DEFAULT_DEBUG = False
DEFAULT_NAIVE = True
DEBUG_SUPPRESS = False
DEFAULT_SPAM_NAIVE_THRESHOLD = 60
MINIMUM_SCAN_LENGTH = 16  # We don't normally scan form data elements with fewer than 16 chars
BLOCKFILE = "blocklist.txt"


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
        self.myuid = str(uuid.uuid4())
        self.debug = False  # Debug prints, spammy!
        self.persistence = False  # Persistent block list
        self.block_msg = DEFAULT_BLOCK_MSG
        self.proxy_url = DEFAULT_BACKEND  # Backend URL to proxy to
        self.max_request_size = DEFAULT_MAX_REQUEST_SIZE
        self.port = DEFAULT_PORT  # Port we listen on
        self.ipheader = DEFAULT_IPHEADER  # Standard IP forward header
        self.savepath = DEFAULT_SAVE_PATH  # File path for saving offender data
        self.suppress_repeats = DEBUG_SUPPRESS  # Whether to suppress logging of repeat offenders
        self.asyncwrite = False  # Only works on later Linux (>=4.18)
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
        self.lock = asyncio.Lock()

        if platform.system() == 'Linux':
            major, minor, _ = platform.release().split('.', 2)
            if major > "4" or (major >= "4" and minor >= "18"):
                self.asyncwrite = True
        if self.asyncwrite:
            print("Utilizing kernel support for asynchronous writing of files")
        else:
            print("Kernel does not support asynchronous writing of files, falling back to synced writing")

        # If config file, load that into the vars
        if config_file:
            self.config = yaml.safe_load(open(config_file, "r"))
            self.debug = self.config.get("debug", self.debug)
            self.proxy_url = self.config.get("proxy_url", self.proxy_url)
            self.max_request_size = self.config.get("max_request_size", self.max_request_size)
            self.port = int(self.config.get("port", self.port))
            self.ipheader = self.config.get("ipheader", self.ipheader)
            self.savepath = self.config.get("savedata", self.savepath)
            self.persistence = self.config.get("persistence", self.persistence)
            self.suppress_repeats = self.config.get("suppress_repeats", self.suppress_repeats)
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
        if self.persistence:
            if os.path.exists(BLOCKFILE):
                offenders = 0
                with open(BLOCKFILE, "r") as bl:
                    for line in bl:
                        if line.strip() and not line.startswith("#"):
                            offenders += 1
                            self.offenders.add(line.strip())
                    print(f"Loaded {offenders} offenders from persistent storage.")

        if self.enable_naive:
            print("Loading Naïve Bayesian spam filter...")
            self.spamfilter = spamfilter.BayesScanner()

    async def save_block_list_async(self):
        async with aiofile.async_open(BLOCKFILE, "w") as f:
            bl = f"# Block list generated at {datetime.datetime.now().isoformat()}\n# UUID: {self.myuid}\n"
            bl += "\n".join(self.offenders)
            await f.write(bl)

    def save_block_list_sync(self):
        with open(BLOCKFILE, "w") as f:
            bl = f"# Block list generated at {datetime.datetime.now().isoformat()}\n# UUID: {self.myuid}\n"
            bl += "\n".join(self.offenders)
            f.write(bl)


    async def save_request_data(
            self, request: aiohttp.web.Request, remote_ip: str, post: typing.Union[multidict.MultiDictProxy, bytes]
    ):
        if not self.savepath:  # If savepath is None, disable saving
            return
        reqid = "request_data_from_%s-%s.txt" % (
            re.sub(r"[^0-9.]+", "-", remote_ip),
            str(uuid.uuid4()),
        )
        filepath = os.path.join(self.savepath, reqid)
        if not os.path.isdir(self.savepath):
            print("Creating save data dir %s" % self.savepath)
            try:
                os.mkdir(self.savepath)
            except PermissionError as e:
                print("Could not create save data dir, bailing: %s" % e)
                return
        print(f"Saving offender data as {filepath}")
        savedata = f"{request.method} {request.path} HTTP/{request.version.major}.{request.version.minor}\r\n"
        savedata += "\r\n".join(
            [": ".join([str(x, encoding="utf-8") for x in header]) for header in request.raw_headers]
        )
        savedata += "\r\n\r\n"
        if isinstance(post, multidict.MultiDictProxy):
            for k, v in post.items():
                savedata += f"{k}={v}\n"
        elif post and isinstance(post, bytes):
            savedata += str(post, encoding="utf-8")
        if self.asyncwrite:
            async with aiofile.async_open(filepath, "w") as f:
                await f.write(savedata)
        else:
            with open(filepath, "w") as f:
                f.write(savedata)

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
                        bad_items.append(
                            f"Form element {k} has spam score of {res}, crosses threshold of {self.naive_threshold}!")
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

        if request.path == '/aardvark-unblock':
            ip = request.query_string
            theiruid = request.headers.get('X-Aardvark-Key', '')
            if theiruid == self.myuid:
                if ip in self.offenders:
                    self.offenders.remove(ip)
                    print(f"Removed IP {ip} from block list.")
                    return aiohttp.web.Response(text="Block removed", status=200)
            return aiohttp.web.Response(text="No such block", status=404)

        # Debug output for syslog
        self.last_batches.append(time.time())
        if len(self.last_batches) >= 25000:
            diff = self.last_batches[-1] - self.last_batches[0]
            diff += 0.01
            self.last_batches = []
            print("Last 25k anti spam scans done at %.2f req/sec" % (25000 / diff))
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
        known_offender = False
        if remote_ip in self.offenders:
            bad_items.append("Client is on the list of bad offenders.")
            known_offender = True
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
            if self.debug or not (known_offender and self.suppress_repeats):
                print(f"Request from {remote_ip} to '{request_url}' contains possible spam:")
                for item in bad_items:
                    print(f"[{remote_ip}]: {item}")
            if not known_offender:  # Only save request data for new cases
                await self.save_request_data(request, remote_ip, post_dict or post_data)

        # Done with scan, log how long that took
        self.scan_times.append(time.time() - now)

        # If bad items were found, don't proxy, return empty response
        if bad_items:
            self.offenders.add(remote_ip)
            self.processing_times.append(time.time() - now)
            return aiohttp.web.Response(text=self.block_msg, status=403)

        async with aiohttp.ClientSession(auto_decompress=False) as session:
            try:
                req_headers = request.headers.copy()
                # We have to replicate the form data or we mess up file transfers
                form_data = None
                if post_dict:
                    form_data = aiohttp.FormData()
                    if "content-length" in req_headers:
                        del req_headers["content-length"]
                    if "content-type" in req_headers:
                        del req_headers["content-type"]
                    for k, v in post_dict.items():
                        if isinstance(v, aiohttp.web.FileField):  # This sets multipart properly in the request
                            form_data.add_field(name=v.name, filename=v.filename, value=v.file.raw,
                                                content_type=v.content_type)
                        else:
                            form_data.add_field(name=k, value=v)
                async with session.request(
                        request.method,
                        target_url,
                        headers=req_headers,
                        params=get_data,
                        data=form_data or post_data,
                        timeout=30,
                        allow_redirects=False,
                ) as resp:
                    result = resp
                    headers = result.headers.copy()
                    if "server" not in headers:
                        headers["server"] = "JIRA (via Aardvark)"
                    self.processing_times.append(time.time() - now)

                    # Standard response
                    if 'content-length' in headers:
                        raw = await result.read()
                        response = aiohttp.web.Response(body=raw, status=result.status, headers=headers)
                    # Chunked response
                    else:
                        response = aiohttp.web.StreamResponse(status=result.status, headers=headers)
                        response.enable_chunked_encoding()
                        await response.prepare(request)
                        buffer = b""
                        async for data, end_of_http_chunk in result.content.iter_chunks():
                            buffer += data
                            if end_of_http_chunk:
                                async with self.lock:
                                    await asyncio.wait_for(response.write(buffer), timeout=5)
                                    buffer = b""
                        async with self.lock:
                            await asyncio.wait_for(response.write(buffer), timeout=5)
                            await asyncio.wait_for(response.write(b""), timeout=5)
                    return response

            except aiohttp.client_exceptions.ClientConnectorError as e:
                print("Could not connect to backend: " + str(e))
                self.processing_times.append(time.time() - now)

        self.processing_times.append(time.time() - now)
        return aiohttp.web.Response(text=self.block_msg, status=403)

    async def sync_block_list(self):
        while True:
            if self.persistence:
                if self.asyncwrite:
                    await self.save_block_list_async()
                else:
                    self.save_block_list_sync()
            await asyncio.sleep(900)


async def main():
    aar = Aardvark()
    app = aiohttp.web.Application(client_max_size=aar.max_request_size)
    app.router.add_route("*", "/{path:.*?}", aar.proxy)
    runner = aiohttp.web.AppRunner(app)

    await runner.setup()
    site = aiohttp.web.TCPSite(runner, "localhost", aar.port)
    print("Starting Aardvark Anti Spam Proxy")
    await site.start()
    print(f"Started on port {aar.port}")
    print(f"Unblock UUID: {aar.myuid}")
    await aar.sync_block_list()


if __name__ == "__main__":
    try:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        pass

#!/usr/bin/python3
"""
    Copyright (c) 2024 Penterep Security s.r.o.

    ptprssi - Path-Relative Style Sheet Import Testing Tool

    ptprssi is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    ptprssi is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with ptprssi.  If not, see <https://www.gnu.org/licenses/>.
"""

import argparse
import re
import sys; sys.path.append(__file__.rsplit("/", 1)[0])
import time
import threading
import urllib
import warnings

import requests
from bs4 import BeautifulSoup, Comment

from _version import __version__
from ptlibs import ptmisclib, ptjsonlib, ptprinthelper, ptnethelper, tldparser

class PtPRSSI:
    def __init__(self, args):
        self.ptjsonlib = ptjsonlib.PtJsonLib()
        self.headers   = ptnethelper.get_request_headers(args)
        self.proxies   = {"https": args.proxy, "http": args.proxy}
        self.use_json  = args.json
        self.redirects = args.redirects if not args.list else True
        self.cache     = args.cache
        self.timeout   = args.timeout
        self.file_test = args.list

        if args.list and args.json:
            self.ptjsonlib.end_error("Cannot combine --list with --json", args.json)

    def run(self, args: argparse.Namespace) -> None:
        if self.file_test:
            ptprinthelper.ptprint(f"Vulnerable domains:", "TITLE", not self.use_json, colortext=True)
            warnings.filterwarnings("error")
            active_threads = []
            for url in self._url_generator(args.list):
                active_threads = [t for t in active_threads if t.is_alive()]
                while len(active_threads) >= args.threads:
                    time.sleep(0.1)
                    active_threads = [t for t in active_threads if t.is_alive()]
                thread = threading.Thread(target=self._prepare_test, args=(url,))
                thread.daemon = True
                thread.start()
                active_threads.append(thread)
            for thread in active_threads:
                thread.join()
        else:
            self._prepare_test(self._adjust_url(args.url))

        self.ptjsonlib.set_status("finished")
        ptmisclib.ptprint(self.ptjsonlib.get_result_json(), "", self.use_json)

    def _prepare_test(self, url):
        try:
            url = self._get_valid_response(url)
            self._test_for_prssi(url)
        except Exception as e:
            print(e)
            if not self.file_test:
                self.ptjsonlib.end_error(f"Cannot connect to server", self.use_json)
            return

    def _test_for_prssi(self, url: str, payload: str = None) -> None:
        for payload in ["", "/foo/foo/foo/foo/foo"]:
            response, response_dump = self._get_response(url, payload)
            if self.file_test and "text/html" not in response.headers.get('Content-Type', ""):
                return
            ptprinthelper.ptprint(f"Testing: {response.url} [{response.status_code}]", "TITLE", not self.use_json and not payload and not self.file_test, colortext=True)

            soup = BeautifulSoup(response.text, "lxml")
            page_comments = soup.find_all(string=lambda text: isinstance(text, Comment))
            css_in_page_comments = [match.group(1) for comment in page_comments for match in re.finditer(r'<link.*?rel=["\']stylesheet["\'].*?href=["\'](.*?)["\'].*?>', comment)]
            page_css = [css.get("href") for css in soup.find_all("link", rel="stylesheet")]
            all_css = page_css + css_in_page_comments
            vulnerable_css = [css for css in all_css if "foo" in css] if payload else [css for css in all_css if not css.startswith("/") and not css.startswith("http")]

            if self.file_test:
                ptprinthelper.ptprint(f"{url}", "", not self.use_json and self.file_test and vulnerable_css)
            else:
                ptprinthelper.ptprint(f"Vulnerable {'relative' if not payload else 'absolute'} CSS paths:", "TITLE", not self.use_json, newline_above=True)
                if vulnerable_css:
                    self.ptjsonlib.add_vulnerability(vuln_code=f"PTV-WEB-INJECT-PRSSIREL" if not payload else "PTV-WEB-INJECT-PRSSIABS", note=vulnerable_css, vuln_request=response_dump["request"], vuln_response=response_dump["response"])
                    for css in vulnerable_css:
                        ptprinthelper.ptprint(f"      {css}", "", not self.use_json)
                else:
                    ptprinthelper.ptprint(f"      None", "", not self.use_json)

    def _get_valid_response(self, url):
            if not urllib.parse.urlparse(url).path:
                for path in ["index.php", "default.aspx"]:
                    r, _ = self._get_response(f"{url}/{path}", "")
                    if r.status_code == 200:
                        url = r.url
                        break
            return url

    def _url_generator(self, file_path: str = None):
        with open(file_path, "r") as file:
            for line in file:
                line =  self._adjust_url(line.strip())
                if line:
                    yield line

    def _adjust_url(self, url) -> str|None:
        if self.file_test:
            try:
                extract = tldparser.extract(url)
                return "http://" + '.'.join([p for p in [extract.subdomain, extract.domain, extract.suffix] if p])
            except:
                return None
        else:
            parsed_url = urllib.parse.urlparse(url)
            if not parsed_url.scheme or parsed_url.scheme not in ["http", "https"]:
                self.ptjsonlib.end_error(f"Missing or wrong scheme", self.use_json)
            path = parsed_url.path
            while path.endswith("/"):
                path = path[:-1]

            parsed_url = urllib.parse.urlunparse((parsed_url.scheme, parsed_url.netloc, path, "", "", ""))
            return parsed_url

    def _get_response(self, url, payload):
        try:
            response, response_dump = ptmisclib.load_url_from_web_or_temp(url+payload if payload else url, "GET", self.headers, self.proxies, None, self.timeout, self.redirects, False, self.cache, True)
        except requests.RequestException as e:
            if not self.file_test:
                self.ptjsonlib.end_error(f"Cannot connect to server", self.use_json)
            else:
                raise

        if response.is_redirect and not self.redirects:
            error_str = f"Redirects disabled: {response.url} -> {response.headers.get('location')}" if self.use_json else f"Redirects disabled: ({ptprinthelper.get_colored_text(response.url, 'TITLE')} -> {ptprinthelper.get_colored_text(response.headers.get('location'), 'TITLE')})"
            self.ptjsonlib.end_error(error_str, self.use_json)

        return response, response_dump


def get_help():
    return [
        {"description": ["Path-Relative Style Sheet Import Testing Tool"]},
        {"usage": ["ptprssi <options>"]},
        {"usage_example": [
            "ptprssi -u https://www.example.com/",
        ]},
        {"options": [
            ["-u",  "--url",                    "<url>",            "Connect to URL"],
            ["-l",  "--list",                   "<list>",           "Test list of domains"],
            ["-p",  "--proxy",                  "<proxy>",          "Set proxy (e.g. http://127.0.0.1:8080)"],
            ["-T",  "--timeout",                "<timeout>",        "Set timeout (default 10s)"],
            ["-H",  "--headers",                "<header:value>",   "Set Header(s)"],
            ["-a",  "--user-agent",             "<agent>",          "Set User-Agent"],
            ["-c",  "--cookie",                 "<cookie>",         "Set Cookie(s)"],
            ["-t",  "--threads",                "<threads>",        "Set threads count"],
            ["-r",  "--redirects",              "",                 "Follow redirects (default False)"],
            ["-C",  "--cache",                  "",                 "Cache HTTP communication (load from tmp in future)"],
            ["-v",  "--version",                "",                 "Show script version and exit"],
            ["-h",  "--help",                   "",                 "Show this help message and exit"],
            ["-j",  "--json",                   "",                 "Output in JSON format"],
        ]
        }]


def parse_args():
    parser = argparse.ArgumentParser(add_help=False, usage="ptprssi <options>")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument( "-u",  "--url",           type=str)
    group.add_argument( "-l",  "--list",          type=str)
    parser.add_argument("-p",  "--proxy",         type=str)
    parser.add_argument("-c",  "--cookie",        type=str)
    parser.add_argument("-a",  "--user-agent",    type=str, default="Penterep Tools")
    parser.add_argument("-T",  "--timeout",       type=int, default=10)
    parser.add_argument("-t",  "--threads",       type=int, default=100)
    parser.add_argument("-H",  "--headers",       type=ptmisclib.pairs)
    parser.add_argument("-r",  "--redirects",     action="store_true")
    parser.add_argument("-C",  "--cache",         action="store_true")
    parser.add_argument("-j",  "--json",          action="store_true")
    parser.add_argument("-v",  "--version",       action="version", version=f"{SCRIPTNAME} {__version__}")

    parser.add_argument("--socket-address",          type=str, default=None)
    parser.add_argument("--socket-port",             type=str, default=None)
    parser.add_argument("--process-ident",           type=str, default=None)


    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
        sys.exit(0)
    args = parser.parse_args()
    ptprinthelper.print_banner(SCRIPTNAME, __version__, args.json)
    return args


def main():
    global SCRIPTNAME
    SCRIPTNAME = "ptprssi"
    args = parse_args()
    args.threads = 1 if not args.list else args.threads
    requests.packages.urllib3.disable_warnings()
    script = PtPRSSI(args)
    script.run(args)


if __name__ == "__main__":
    main()

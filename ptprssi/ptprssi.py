#!/usr/bin/python3
"""
    Copyright (c) 2023 Penterep Security s.r.o.

    ptprssi - Path-relative style sheet import testing tool

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
import sys; sys.path.append(__file__.rsplit("/", 1)[0])
import urllib

import requests
from bs4 import BeautifulSoup, Comment

from _version import __version__
from ptlibs import ptmisclib, ptjsonlib, ptprinthelper, ptnethelper


class PtPrssi:
    def __init__(self, args):
        self.ptjsonlib     = ptjsonlib.PtJsonLib()
        self.headers       = ptnethelper.get_request_headers(args)
        self.proxies       = {"https": args.proxy, "http": args.proxy}
        self.use_json      = args.json
        self.redirects     = args.redirects
        self.cache         = args.cache
        self.timeout       = args.timeout

    def run(self, args) -> None:
        url = self._adjust_url(args.url)
        response, _ = self._get_response(url, payload="")
        ptprinthelper.ptprint(f"Testing: {response.url} [{response.status_code}]", "TITLE", not self.use_json, colortext=True)

        for payload in [None, "foo/foo/foo/foo/foo"]:
            self._test_url(url, payload)

        self.ptjsonlib.set_status("ok")
        ptmisclib.ptprint(self.ptjsonlib.get_result_json(), "", self.use_json)

    def _test_url(self, url: str, payload: str) -> None:
        """Test url for prssi"""
        response, response_dump = self._get_response(url, payload)
        soup = BeautifulSoup(response.text, "lxml")
        page_css = [css.get('href') for css in soup.find_all('link', type="text/css")]
        page_comments = soup.find(string=lambda text: isinstance(text, Comment))
        css_in_comments = list()

        if page_comments:
            comment_soup = BeautifulSoup(page_comments, 'lxml')
            css_in_comments = [css.get('href') for css in comment_soup.find_all('link', type="text/css")]
        if payload:
            vulnerable_css = [css for css in page_css if "foo" in css]
            vulnerable_css += [css for css in css_in_comments if "foo" in css if css_in_comments]
        else:
            vulnerable_css = [css for css in page_css if not css.startswith("/") and not css.startswith("http")]
            vulnerable_css += [css for css in css_in_comments if not css.startswith("/") if css_in_comments]

        ptprinthelper.ptprint(f"Vulnerable {'relative' if not payload else 'absolute'} CSS paths:", "TITLE", not self.use_json, newline_above=True)
        if vulnerable_css:
            self.ptjsonlib.add_vulnerability(code='relative' if not payload else 'absolute', note=vulnerable_css, request=response_dump["request"], response=response_dump["response"])
            for discovery in vulnerable_css:
                ptprinthelper.ptprint(f"      {discovery}", "", not self.use_json)
        else:
                ptprinthelper.ptprint(f"      None", "", not self.use_json)

    def _adjust_url(self, url):
        parsed_url = urllib.parse.urlparse(url)
        if not parsed_url.scheme or parsed_url.scheme not in ["http", "https"]:
            self.ptjsonlib.end_error(f"Missing or wrong scheme", self.use_json)
        path = parsed_url.path
        while path.endswith("/"):
            path = path[:-1]
        if len(path) == 0:
            path += "/"
        parsed_url = urllib.parse.urlunparse((parsed_url.scheme, parsed_url.netloc, path, "", "", ""))
        return parsed_url

    def _get_response(self, url, payload):
        """Retrieve response"""
        try:
            response, response_dump = ptmisclib.load_url_from_web_or_temp(url+payload if payload else url, "GET", self.headers, self.proxies, None, self.timeout, self.redirects, False, self.cache, True)
            if response.is_redirect and not self.redirects:
                if self.use_json:
                    self.ptjsonlib.end_error(f"Redirects disabled: {response.url} -> {response.headers.get('location')})", self.use_json)
                else:
                    ptprinthelper.ptprint(f"Redirects disabled: ({ptprinthelper.get_colored_text(response.url, 'TITLE')} -> {ptprinthelper.get_colored_text(response.headers.get('location'), 'TITLE')})", "ERROR", not self.use_json)
                    sys.exit(0)
            return response, response_dump
        except requests.RequestException as e:
            self.ptjsonlib.end_error(f"Cannot connect to server", self.use_json)


def get_help():
    return [
        {"description": ["Path-relative style sheet import testing tool"]},
        {"usage": ["ptprssi <options>"]},
        {"usage_example": [
            "ptprssi -u https://www.example.com/",
        ]},
        {"options": [
            ["-u",  "--url",                    "<url>",            "Connect to URL"],
            ["-p",  "--proxy",                  "<proxy>",          "Set proxy (e.g. http://127.0.0.1:8080)"],
            ["-H",  "--headers",                "<header:value>",   "Set custom header(s)"],
            ["-T",  "--timeout",                "<timeout>",        "Set timeout (default 10s)"],
            ["-ua", "--user-agent",             "<ua>",             "Set User-Agent header"],
            ["-c",  "--cookie",                 "<cookie>",         "Set cookie"],
            ["-r",  "--redirects",              "",                 "Follow redirects (default False)"],
            ["-C",   "--cache",                 "",                 "Cache HTTP communication (load from tmp in future)"],
            ["-v",  "--version",                "",                 "Show script version and exit"],
            ["-h",  "--help",                   "",                 "Show this help message and exit"],
            ["-j",  "--json",                   "",                 "Output in JSON format"],
        ]
        }]


def parse_args():
    parser = argparse.ArgumentParser(add_help=False, usage="ptprssi <options>")
    parser.add_argument("-u",  "--url",        type=str, required=True)
    parser.add_argument("-p",  "--proxy",      type=str)
    parser.add_argument("-c",  "--cookie",     type=str)
    parser.add_argument("-ua", "--user-agent", type=str, default="Penterep Tools")
    parser.add_argument("-T",  "--timeout",    type=int, default=10)
    parser.add_argument("-H",  "--headers",    type=ptmisclib.pairs)
    parser.add_argument("-r",  "--redirects",  action="store_true")
    parser.add_argument("-C",  "--cache",      action="store_true")
    parser.add_argument("-j",  "--json",       action="store_true")
    parser.add_argument("-v",  "--version",    action="version", version=f"{SCRIPTNAME} {__version__}")

    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
        sys.exit(0)
    args = parser.parse_args()
    ptprinthelper.print_banner(SCRIPTNAME, __version__, args.json)
    return args


def main():
    global SCRIPTNAME
    SCRIPTNAME = "ptprssi"
    requests.packages.urllib3.disable_warnings()
    args = parse_args()
    script = PtPrssi(args)
    script.run(args)


if __name__ == "__main__":
    main()

# Host-normaliser fixtures: where each file comes from

| file | source | licence | how it was made |
|---|---|---|---|
| `wpt-urltestdata-special.json` | web-platform-tests `url/resources/urltestdata.json` at `c5e80ef1dca982bfab50c54277fdf99bfb8c9a62` | BSD-3-Clause, below | the cases with no base whose scheme is special (http, https, ws, wss, ftp, file), keeping `input`, `failure`, `hostname`, `port`; written with `json.dumps(cases, ensure_ascii=True, indent=1)`, so every non-ASCII character is a JSON `\u` escape (as in the IDNA file below); the values are unchanged |
| `wpt-toascii.json` | web-platform-tests `url/resources/toascii.json`, same commit | BSD-3-Clause, below | verbatim |
| `wpt-IdnaTestV2.json` | web-platform-tests `url/resources/IdnaTestV2.json`, same commit, generated there from Unicode's `IdnaTestV2.txt` | BSD-3-Clause, below; the underlying data is under the Unicode License v3 (https://www.unicode.org/license.txt) | verbatim |
| `ssrf-corpus.json` | `patt`: PayloadsAllTheThings, `Server Side Request Forgery/README.md` at `3ac27901c711bdf3f5b65a7b1d1820a1f65bd09a` (MIT, Copyright (c) 2019 Swissky); `tsai`: Orange Tsai, "A New Era of SSRF - Exploiting URL Parser in Trending Programming Languages", Black Hat USA 2017; `cve-2019-9636`: CPython bpo-36216 (NFKC-normalised netloc); `item`: the forms named in the W2-C4 work item; `review`: forms this PR's adversarial review found curl and glibc read as DNS names | as named | inputs copied from the source; `host`/`port` are the expected canonical results here, `null` meaning refused as unparseable |
| `real-urls.txt` | every http(s)/ws/ftp URL cited in this catalog's `base/` and `.github/` and in the org-plan security research records and plans (2026-10-02) | URLs only | extracted by regex; templates, placeholders and credential-looking URLs dropped |

The URL Standard is https://url.spec.whatwg.org/ (host parsing: #host-parsing, IPv4: #concept-ipv4-parser).

## web-platform-tests licence

The 3-Clause BSD License

Copyright © web-platform-tests contributors

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## PayloadsAllTheThings licence (MIT)

Copyright (c) 2019 Swissky

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

"""
tools_db — full tool catalog.

Each entry:
  check            : cmd that returns 0 if installed
  install          : primary install (any platform)
  install_ubuntu   : optional override for ubuntu/debian
  install_termux   : optional override for termux
  install_macos    : optional override for macos
  category         : one of recon|web|fuzz|secrets|cloud|network|pivot|creds|api|wordlist|mobile|misc|util
  desc             : what it does
  url              : upstream

Anything not listed here can still be installed — installer.py falls back to
pkg/apt/pip/pipx/npm/go/cargo/gem/snap/docker, then github search.
"""

TOOLS = {

    # ═══════════════════════════════════════════════════════════════════
    # RECON — subdomains, DNS, host discovery
    # ═══════════════════════════════════════════════════════════════════
    "subfinder":   {"check": "command -v subfinder",   "install": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "category": "recon", "desc": "passive subdomain enumeration", "url": "https://github.com/projectdiscovery/subfinder"},
    "amass":       {"check": "command -v amass",       "install": "go install -v github.com/owasp-amass/amass/v4/...@master", "category": "recon", "desc": "OWASP subdomain enum", "url": "https://github.com/owasp-amass/amass"},
    "assetfinder": {"check": "command -v assetfinder", "install": "go install -v github.com/tomnomnom/assetfinder@latest", "category": "recon", "desc": "passive subdomain enum", "url": "https://github.com/tomnomnom/assetfinder"},
    "findomain":   {"check": "command -v findomain",   "install": "curl -sL https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip -o /tmp/fd.zip && unzip -o /tmp/fd.zip -d ~/agent/tools && chmod +x ~/agent/tools/findomain", "category": "recon", "desc": "fast subdomain enum", "url": "https://github.com/Findomain/Findomain"},
    "chaos":       {"check": "command -v chaos",       "install": "go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest", "category": "recon", "desc": "ProjectDiscovery chaos DB client", "url": "https://github.com/projectdiscovery/chaos-client"},
    "shosubgo":    {"check": "command -v shosubgo",    "install": "go install -v github.com/incogbyte/shosubgo@latest", "category": "recon", "desc": "subdomain enum via shodan", "url": "https://github.com/incogbyte/shosubgo"},
    "github-subdomains": {"check": "command -v github-subdomains", "install": "go install -v github.com/gwen001/github-subdomains@latest", "category": "recon", "desc": "scrape github for subdomains", "url": "https://github.com/gwen001/github-subdomains"},
    "gotator":     {"check": "command -v gotator",     "install": "go install -v github.com/Josue87/gotator@latest", "category": "recon", "desc": "subdomain permutation", "url": "https://github.com/Josue87/gotator"},
    "dnsgen":      {"check": "command -v dnsgen",      "install": "pipx install dnsgen || pip install --user dnsgen", "category": "recon", "desc": "subdomain permutation from wordlist", "url": "https://github.com/ProjectAnte/dnsgen"},
    "altdns":      {"check": "command -v altdns",      "install": "pipx install altdns || pip install --user altdns", "category": "recon", "desc": "DNS mutation", "url": "https://github.com/infosec-au/altdns"},
    "puredns":     {"check": "command -v puredns",     "install": "go install -v github.com/d3mondev/puredns/v2@latest", "category": "recon", "desc": "mass DNS resolve with wildcard filter", "url": "https://github.com/d3mondev/puredns"},
    "shuffledns":  {"check": "command -v shuffledns",  "install": "go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest", "category": "recon", "desc": "massdns wrapper", "url": "https://github.com/projectdiscovery/shuffledns"},
    "massdns":     {"check": "command -v massdns",     "install": "git clone --depth 1 https://github.com/blechschmidt/massdns ~/agent/tools/massdns && cd ~/agent/tools/massdns && make && ln -sf $(pwd)/bin/massdns ~/agent/tools/massdns-bin", "category": "recon", "desc": "fastest DNS resolver", "url": "https://github.com/blechschmidt/massdns"},
    "dnsx":        {"check": "command -v dnsx",        "install": "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest", "category": "recon", "desc": "DNS toolkit", "url": "https://github.com/projectdiscovery/dnsx"},
    "crobat":      {"check": "command -v crobat",      "install": "go install -v github.com/cgboal/sonarsearch/cmd/crobat@latest", "category": "recon", "desc": "fast subdomain enum", "url": "https://github.com/cgboal/sonarsearch"},
    "cdncheck":    {"check": "command -v cdncheck",    "install": "go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest", "category": "recon", "desc": "detect CDN / WAF per host", "url": "https://github.com/projectdiscovery/cdncheck"},
    "httpx":       {"check": "command -v httpx",       "install": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest", "category": "recon", "desc": "http probe + fingerprint", "url": "https://github.com/projectdiscovery/httpx"},
    "tlsx":        {"check": "command -v tlsx",        "install": "go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest", "category": "recon", "desc": "TLS fingerprint / SANs", "url": "https://github.com/projectdiscovery/tlsx"},
    "naabu":       {"check": "command -v naabu",       "install": "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", "category": "recon", "desc": "fast port scanner", "url": "https://github.com/projectdiscovery/naabu"},
    "gau":         {"check": "command -v gau",         "install": "go install -v github.com/lc/gau/v2/cmd/gau@latest", "category": "recon", "desc": "getallurls from wayback/cc/otx", "url": "https://github.com/lc/gau"},
    "gauplus":     {"check": "command -v gauplus",     "install": "go install -v github.com/bp0lr/gauplus@latest", "category": "recon", "desc": "gau with filters", "url": "https://github.com/bp0lr/gauplus"},
    "waybackurls": {"check": "command -v waybackurls", "install": "go install -v github.com/tomnomnom/waybackurls@latest", "category": "recon", "desc": "wayback machine URLs", "url": "https://github.com/tomnomnom/waybackurls"},
    "katana":      {"check": "command -v katana",      "install": "go install -v github.com/projectdiscovery/katana/cmd/katana@latest", "category": "recon", "desc": "crawler", "url": "https://github.com/projectdiscovery/katana"},
    "hakrawler":   {"check": "command -v hakrawler",   "install": "go install -v github.com/hakluke/hakrawler@latest", "category": "recon", "desc": "fast crawler", "url": "https://github.com/hakluke/hakrawler"},
    "gospider":    {"check": "command -v gospider",    "install": "go install -v github.com/jaeles-project/gospider@latest", "category": "recon", "desc": "crawler with JS grep", "url": "https://github.com/jaeles-project/gospider"},
    "subjs":       {"check": "command -v subjs",       "install": "go install -v github.com/lc/subjs@latest", "category": "recon", "desc": "collect JS files", "url": "https://github.com/lc/subjs"},
    "getJS":       {"check": "command -v getJS",       "install": "go install -v github.com/003random/getJS@latest", "category": "recon", "desc": "extract JS URLs", "url": "https://github.com/003random/getJS"},
    "jsluice":     {"check": "command -v jsluice",     "install": "go install -v github.com/BishopFox/jsluice/cmd/jsluice@latest", "category": "recon", "desc": "extract URLs + secrets from JS", "url": "https://github.com/BishopFox/jsluice"},
    "LinkFinder":  {"check": "command -v linkfinder",  "install": "pipx install linkfinder || pip install --user linkfinder", "category": "recon", "desc": "endpoints from JS", "url": "https://github.com/GerbenJavado/LinkFinder"},
    "SecretFinder": {"check": "command -v secretfinder", "install": "pipx install secretfinder || pip install --user secretfinder", "category": "recon", "desc": "secrets in JS", "url": "https://github.com/m4ll0k/SecretFinder"},
    "xnLinkFinder": {"check": "command -v xnLinkFinder", "install": "pipx install xnLinkFinder || pip install --user xnLinkFinder", "category": "recon", "desc": "link finder for XSS/param", "url": "https://github.com/xnl-h4ck3r/xnLinkFinder"},
    "qsreplace":   {"check": "command -v qsreplace",   "install": "go install -v github.com/tomnomnom/qsreplace@latest", "category": "recon", "desc": "query string replacement", "url": "https://github.com/tomnomnom/qsreplace"},
    "anew":        {"check": "command -v anew",        "install": "go install -v github.com/tomnomnom/anew@latest", "category": "util", "desc": "dedupe append", "url": "https://github.com/tomnomnom/anew"},
    "gf":          {"check": "command -v gf",          "install": "go install -v github.com/tomnomnom/gf@latest", "category": "util", "desc": "grep patterns for URLs", "url": "https://github.com/tomnomnom/gf"},

    # ═══════════════════════════════════════════════════════════════════
    # WEB — exploitation, XSS, SQLi, SSRF, SSTI, CMDi, smuggling
    # ═══════════════════════════════════════════════════════════════════
    "nuclei":      {"check": "command -v nuclei",      "install": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "category": "web", "desc": "template scanner", "url": "https://github.com/projectdiscovery/nuclei"},
    "dalfox":      {"check": "command -v dalfox",      "install": "go install -v github.com/hahwul/dalfox/v2@latest", "category": "web", "desc": "XSS scanner", "url": "https://github.com/hahwul/dalfox"},
    "gxss":        {"check": "command -v gxss",        "install": "go install -v github.com/KathanP19/Gxss@latest", "category": "web", "desc": "reflected XSS detect", "url": "https://github.com/KathanP19/Gxss"},
    "kxss":        {"check": "command -v kxss",        "install": "go install -v github.com/Emoe/kxss@latest", "category": "web", "desc": "reflection detector", "url": "https://github.com/Emoe/kxss"},
    "sqlmap":      {"check": "command -v sqlmap",      "install": "apt install -y sqlmap || pip install --user sqlmap", "category": "web", "desc": "SQL injection", "url": "https://github.com/sqlmapproject/sqlmap"},
    "ghauri":      {"check": "command -v ghauri",      "install": "pipx install ghauri || pip install --user ghauri", "category": "web", "desc": "modern SQLi (WAF-friendly)", "url": "https://github.com/r0oth3x49/ghauri"},
    "nosqlmap":    {"check": "command -v nosqlmap",    "install": "git clone --depth 1 https://github.com/codingo/NoSQLMap ~/agent/tools/nosqlmap && chmod +x ~/agent/tools/nosqlmap/nosqlmap.py", "category": "web", "desc": "NoSQL injection", "url": "https://github.com/codingo/NoSQLMap"},
    "commix":      {"check": "command -v commix",      "install": "apt install -y commix || pipx install commix", "category": "web", "desc": "command injection", "url": "https://github.com/commixproject/commix"},
    "sstimap":     {"check": "command -v sstimap",     "install": "pipx install sstimap || pip install --user sstimap", "category": "web", "desc": "SSTI scanner (Jinja/Twig)", "url": "https://github.com/vladko312/SSTImap"},
    "ppmap":       {"check": "command -v ppmap",       "install": "go install -v github.com/kleiton0x00/ppmap@latest", "category": "web", "desc": "prototype pollution", "url": "https://github.com/kleiton0x00/ppmap"},
    "ssrfmap":     {"check": "command -v ssrfmap",     "install": "git clone --depth 1 https://github.com/swisskyrepo/SSRFmap ~/agent/tools/ssrfmap && pip install --user -r ~/agent/tools/ssrfmap/requirements.txt", "category": "web", "desc": "SSRF exploitation", "url": "https://github.com/swisskyrepo/SSRFmap"},
    "gopherus":    {"check": "command -v gopherus",    "install": "pipx install gopherus || pip install --user gopherus", "category": "web", "desc": "SSRF -> gopher RCE", "url": "https://github.com/tarunkant/Gopherus"},
    "smuggler":    {"check": "command -v smuggler",    "install": "git clone --depth 1 https://github.com/defparam/smuggler ~/agent/tools/smuggler", "category": "web", "desc": "HTTP request smuggling", "url": "https://github.com/defparam/smuggler"},
    "h2csmuggler": {"check": "command -v h2csmuggler", "install": "pipx install h2csmuggler || pip install --user h2csmuggler", "category": "web", "desc": "h2c smuggling", "url": "https://github.com/BishopFox/h2csmuggler"},
    "corsy":       {"check": "command -v corsy",       "install": "git clone --depth 1 https://github.com/s0md3v/Corsy ~/agent/tools/corsy && pip install --user -r ~/agent/tools/corsy/requirements.txt", "category": "web", "desc": "CORS misconfig scanner", "url": "https://github.com/s0md3v/Corsy"},
    "crlfuzz":     {"check": "command -v crlfuzz",     "install": "go install -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest", "category": "web", "desc": "CRLF injection", "url": "https://github.com/dwisiswant0/crlfuzz"},
    "x8":          {"check": "command -v x8",          "install": "cargo install x8", "category": "web", "desc": "hidden param discoverer", "url": "https://github.com/Sh1Yo/x8"},
    "arjun":       {"check": "command -v arjun",       "install": "pipx install arjun || pip install --user arjun", "category": "web", "desc": "param discoverer", "url": "https://github.com/s0md3v/Arjun"},
    "paramspider": {"check": "command -v paramspider", "install": "pipx install paramspider || pip install --user paramspider", "category": "web", "desc": "params from wayback", "url": "https://github.com/devanshbatham/ParamSpider"},
    "jwt_tool":    {"check": "command -v jwt_tool",    "install": "git clone --depth 1 https://github.com/ticarpi/jwt_tool ~/agent/tools/jwt_tool && chmod +x ~/agent/tools/jwt_tool/jwt_tool.py", "category": "web", "desc": "JWT forgery / alg attacks", "url": "https://github.com/ticarpi/jwt_tool"},
    "jwt-cracker": {"check": "command -v jwt-cracker", "install": "npm install -g jwt-cracker", "category": "web", "desc": "HS256 weak secret brute", "url": "https://github.com/lmammino/jwt-cracker"},
    "interactsh-client": {"check": "command -v interactsh-client", "install": "go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest", "category": "web", "desc": "OOB callback (DNS/HTTP/SMTP)", "url": "https://github.com/projectdiscovery/interactsh"},

    # ═══════════════════════════════════════════════════════════════════
    # FUZZ — brute force, dirs, mutation
    # ═══════════════════════════════════════════════════════════════════
    "ffuf":        {"check": "command -v ffuf",        "install": "go install -v github.com/ffuf/ffuf/v2@latest", "category": "fuzz", "desc": "fuzzer", "url": "https://github.com/ffuf/ffuf"},
    "gobuster":    {"check": "command -v gobuster",    "install": "go install -v github.com/OJ/gobuster/v3@latest", "category": "fuzz", "desc": "dir/dns/vhost fuzz", "url": "https://github.com/OJ/gobuster"},
    "feroxbuster": {"check": "command -v feroxbuster", "install": "cargo install feroxbuster --locked", "category": "fuzz", "desc": "recursive dir fuzz", "url": "https://github.com/epi052/feroxbuster"},
    "dirsearch":   {"check": "command -v dirsearch",   "install": "pipx install dirsearch || pip install --user dirsearch", "category": "fuzz", "desc": "python dir fuzz", "url": "https://github.com/maurosoria/dirsearch"},
    "wfuzz":       {"check": "command -v wfuzz",       "install": "pipx install wfuzz || pip install --user wfuzz", "category": "fuzz", "desc": "fuzzer", "url": "https://github.com/xmendez/wfuzz"},
    "kr":          {"check": "command -v kr",          "install": "go install -v github.com/assetnote/kiterunner/cmd/kr@latest", "category": "fuzz", "desc": "API route bruter", "url": "https://github.com/assetnote/kiterunner"},
    "radamsa":     {"check": "command -v radamsa",     "install": "apt install -y radamsa || git clone --depth 1 https://github.com/aoh/radamsa ~/agent/tools/radamsa && cd ~/agent/tools/radamsa && make && make install PREFIX=~/agent/tools", "category": "fuzz", "desc": "mutation fuzzer", "url": "https://github.com/aoh/radamsa"},

    # ═══════════════════════════════════════════════════════════════════
    # SECRETS
    # ═══════════════════════════════════════════════════════════════════
    "gitleaks":    {"check": "command -v gitleaks",    "install": "go install -v github.com/gitleaks/gitleaks/v8@latest", "category": "secrets", "desc": "git secret scan", "url": "https://github.com/gitleaks/gitleaks"},
    "trufflehog":  {"check": "command -v trufflehog",  "install": "go install -v github.com/trufflesecurity/trufflehog/v3@latest", "category": "secrets", "desc": "secret scan with verification", "url": "https://github.com/trufflesecurity/trufflehog"},

    # ═══════════════════════════════════════════════════════════════════
    # CLOUD
    # ═══════════════════════════════════════════════════════════════════
    "cloud_enum":  {"check": "command -v cloud_enum",  "install": "pipx install cloud_enum || pip install --user cloud_enum", "category": "cloud", "desc": "enumerate public cloud buckets", "url": "https://github.com/initstring/cloud_enum"},
    "S3Scanner":   {"check": "command -v s3scanner",   "install": "pipx install s3scanner || pip install --user s3scanner", "category": "cloud", "desc": "S3 bucket scanner", "url": "https://github.com/sa7mon/S3Scanner"},
    "awscli":      {"check": "command -v aws",         "install": "pipx install awscli || pip install --user awscli", "category": "cloud", "desc": "AWS CLI", "url": "https://aws.amazon.com/cli/"},
    "pacu":        {"check": "command -v pacu",        "install": "pipx install pacu || pip install --user pacu", "category": "cloud", "desc": "AWS exploitation framework", "url": "https://github.com/RhinoSecurityLabs/pacu"},
    "ScoutSuite":  {"check": "command -v scout",       "install": "pipx install scoutsuite || pip install --user scoutsuite", "category": "cloud", "desc": "multi-cloud audit", "url": "https://github.com/nccgroup/ScoutSuite"},
    "prowler":     {"check": "command -v prowler",     "install": "pipx install prowler || pip install --user prowler", "category": "cloud", "desc": "AWS security scanner", "url": "https://github.com/prowler-cloud/prowler"},

    # ═══════════════════════════════════════════════════════════════════
    # NETWORK / INFRA
    # ═══════════════════════════════════════════════════════════════════
    "nmap":        {"check": "command -v nmap",        "install": "apt install -y nmap || pkg install -y nmap", "category": "network", "desc": "port scanner", "url": "https://nmap.org/"},
    "masscan":     {"check": "command -v masscan",     "install": "apt install -y masscan || pkg install -y masscan", "category": "network", "desc": "fast port scanner", "url": "https://github.com/robertdavidgraham/masscan"},
    "rustscan":    {"check": "command -v rustscan",    "install": "cargo install rustscan --locked", "category": "network", "desc": "port scanner with nmap integration", "url": "https://github.com/RustScan/RustScan"},
    "nikto":       {"check": "command -v nikto",       "install": "apt install -y nikto || pkg install -y nikto", "category": "network", "desc": "web server scanner", "url": "https://github.com/sullo/nikto"},
    "whatweb":     {"check": "command -v whatweb",     "install": "apt install -y whatweb || pkg install -y whatweb", "category": "network", "desc": "tech fingerprint", "url": "https://github.com/urbanadventurer/WhatWeb"},
    "wafw00f":     {"check": "command -v wafw00f",     "install": "pipx install wafw00f || pip install --user wafw00f", "category": "network", "desc": "WAF fingerprint", "url": "https://github.com/EnableSecurity/wafw00f"},
    "testssl":     {"check": "test -f ~/agent/tools/testssl.sh/testssl.sh", "install": "git clone --depth 1 https://github.com/drwetter/testssl.sh.git ~/agent/tools/testssl.sh", "category": "network", "desc": "TLS deep scan", "url": "https://github.com/drwetter/testssl.sh"},
    "sslyze":      {"check": "command -v sslyze",      "install": "pipx install sslyze || pip install --user sslyze", "category": "network", "desc": "SSL/TLS scanner", "url": "https://github.com/nabla-c0d3/sslyze"},
    "sslscan":     {"check": "command -v sslscan",     "install": "apt install -y sslscan || pkg install -y sslscan", "category": "network", "desc": "SSL scanner", "url": "https://github.com/rbsec/sslscan"},
    "gowitness":   {"check": "command -v gowitness",   "install": "go install -v github.com/sensepost/gowitness@latest", "category": "network", "desc": "headless screenshotter", "url": "https://github.com/sensepost/gowitness"},
    "eyewitness":  {"check": "command -v eyewitness",  "install": "pipx install eyewitness || pip install --user eyewitness", "category": "network", "desc": "screenshot + report", "url": "https://github.com/RedSiege/EyeWitness"},

    # ═══════════════════════════════════════════════════════════════════
    # PIVOT / POST-EXPLOIT
    # ═══════════════════════════════════════════════════════════════════
    "nxc":         {"check": "command -v nxc",         "install": "pipx install netexec || pip install --user netexec", "category": "pivot", "desc": "SMB/WinRM/LDAP/MSSQL/SSH wrapper", "url": "https://github.com/Pennyw0rth/NetExec"},
    "impacket-mssqlclient": {"check": "command -v impacket-mssqlclient", "install": "pipx install impacket || pip install --user impacket", "category": "pivot", "desc": "impacket suite", "url": "https://github.com/fortra/impacket"},
    "bloodhound-python": {"check": "command -v bloodhound-python", "install": "pipx install bloodhound || pip install --user bloodhound", "category": "pivot", "desc": "AD recon", "url": "https://github.com/dirkjanm/BloodHound.py"},
    "chisel":      {"check": "command -v chisel",      "install": "go install -v github.com/jpillora/chisel@latest", "category": "pivot", "desc": "TCP over HTTP tunnel", "url": "https://github.com/jpillora/chisel"},
    "ligolo-ng":   {"check": "command -v ligolo-ng",   "install": "curl -sL https://github.com/nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_proxy_$(uname -s)_$(uname -m).tar.gz -o /tmp/lig.zip && mkdir -p ~/agent/tools/ligolo && tar xzf /tmp/lig.zip -C ~/agent/tools/ligolo", "category": "pivot", "desc": "modern reverse tunnel", "url": "https://github.com/nicocha30/ligolo-ng"},
    "socat":       {"check": "command -v socat",       "install": "apt install -y socat || pkg install -y socat", "category": "pivot", "desc": "universal TCP relay", "url": "http://www.dest-unreach.org/socat/"},
    "proxychains": {"check": "command -v proxychains4", "install": "apt install -y proxychains4 || pkg install -y proxychains-ng", "category": "pivot", "desc": "route traffic through proxy", "url": "https://github.com/rofl0r/proxychains-ng"},
    "sshuttle":    {"check": "command -v sshuttle",    "install": "pipx install sshuttle || pip install --user sshuttle", "category": "pivot", "desc": "VPN over SSH", "url": "https://github.com/sshuttle/sshuttle"},
    "smbmap":      {"check": "command -v smbmap",      "install": "pipx install smbmap || pip install --user smbmap", "category": "pivot", "desc": "SMB share mapper", "url": "https://github.com/ShawnDEvans/smbmap"},
    "enum4linux-ng": {"check": "command -v enum4linux-ng", "install": "pipx install enum4linux-ng || pip install --user enum4linux-ng", "category": "pivot", "desc": "SMB/LDAP enum", "url": "https://github.com/cddmp/enum4linux-ng"},
    "responder":   {"check": "command -v responder",   "install": "apt install -y responder || pip install --user responder", "category": "pivot", "desc": "LLMNR/NBT-NS poisoner", "url": "https://github.com/lgandx/Responder"},
    "mitmproxy":   {"check": "command -v mitmproxy",   "install": "pipx install mitmproxy || pip install --user mitmproxy", "category": "pivot", "desc": "interactive MITM", "url": "https://mitmproxy.org/"},
    "rpcclient":   {"check": "command -v rpcclient",   "install": "apt install -y samba-common-bin || pkg install -y samba", "category": "pivot", "desc": "RPC enumeration", "url": "https://www.samba.org/"},

    # ═══════════════════════════════════════════════════════════════════
    # CREDS / HASH
    # ═══════════════════════════════════════════════════════════════════
    "hydra":       {"check": "command -v hydra",       "install": "apt install -y hydra || pkg install -y hydra", "category": "creds", "desc": "online brute force", "url": "https://github.com/vanhauser-thc/thc-hydra"},
    "medusa":      {"check": "command -v medusa",      "install": "apt install -y medusa || pkg install -y medusa", "category": "creds", "desc": "online brute force", "url": "https://github.com/jmk-foofus/medusa"},
    "crowbar":     {"check": "command -v crowbar",     "install": "apt install -y crowbar || pipx install crowbar", "category": "creds", "desc": "RDP/VNC/SSH brute", "url": "https://github.com/galkan/crowbar"},
    "kerbrute":    {"check": "command -v kerbrute",    "install": "go install -v github.com/ropnop/kerbrute@latest", "category": "creds", "desc": "AD kerberos enum + brute", "url": "https://github.com/ropnop/kerbrute"},
    "patator":     {"check": "command -v patator",     "install": "pipx install patator || pip install --user patator", "category": "creds", "desc": "modular brute force", "url": "https://github.com/lanjelot/patator"},
    "hashcat":     {"check": "command -v hashcat",     "install": "apt install -y hashcat || pkg install -y hashcat", "category": "creds", "desc": "GPU hash crack", "url": "https://hashcat.net/hashcat/"},
    "john":        {"check": "command -v john",        "install": "apt install -y john || pkg install -y john", "category": "creds", "desc": "CPU hash crack", "url": "https://www.openwall.com/john/"},

    # ═══════════════════════════════════════════════════════════════════
    # API
    # ═══════════════════════════════════════════════════════════════════
    "graphql-cop": {"check": "command -v graphql-cop", "install": "pipx install graphql-cop || pip install --user graphql-cop", "category": "api", "desc": "GraphQL misconfig scan", "url": "https://github.com/dolevf/graphql-cop"},
    "graphw00f":   {"check": "command -v graphw00f",   "install": "pipx install graphw00f || pip install --user graphw00f", "category": "api", "desc": "GraphQL engine fingerprint", "url": "https://github.com/dolevf/graphw00f"},
    "clairvoyance": {"check": "command -v clairvoyance", "install": "pipx install clairvoyance || pip install --user clairvoyance", "category": "api", "desc": "recover GraphQL schema", "url": "https://github.com/nikitastupin/clairvoyance"},
    "websocat":    {"check": "command -v websocat",    "install": "curl -sL https://github.com/vi/websocat/releases/latest/download/websocat_$(uname -m)-unknown-linux-musl -o ~/agent/tools/websocat && chmod +x ~/agent/tools/websocat", "category": "api", "desc": "WebSocket CLI client", "url": "https://github.com/vi/websocat"},
    "grpcurl":     {"check": "command -v grpcurl",     "install": "go install -v github.com/fullstorydev/grpcurl/cmd/grpcurl@latest", "category": "api", "desc": "gRPC client", "url": "https://github.com/fullstorydev/grpcurl"},

    # ═══════════════════════════════════════════════════════════════════
    # UTIL
    # ═══════════════════════════════════════════════════════════════════
    "jq":          {"check": "command -v jq",          "install": "apt install -y jq || pkg install -y jq", "category": "util", "desc": "JSON query", "url": "https://stedolan.github.io/jq/"},
    "yq":          {"check": "command -v yq",          "install": "pipx install yq || pip install --user yq", "category": "util", "desc": "YAML query", "url": "https://github.com/kislyuk/yq"},
    "rg":          {"check": "command -v rg",          "install": "apt install -y ripgrep || pkg install -y ripgrep", "category": "util", "desc": "fast grep", "url": "https://github.com/BurntSushi/ripgrep"},
    "dig":         {"check": "command -v dig",         "install": "apt install -y dnsutils || pkg install -y dnsutils", "category": "util", "desc": "DNS lookup", "url": "https://www.isc.org/bind/"},
    "whois":       {"check": "command -v whois",       "install": "apt install -y whois || pkg install -y whois", "category": "util", "desc": "whois", "url": "https://github.com/rfc1036/whois"},
    "smbclient":   {"check": "command -v smbclient",   "install": "apt install -y smbclient || pkg install -y smbclient", "category": "util", "desc": "SMB client", "url": "https://www.samba.org/"},
    "redis-cli":   {"check": "command -v redis-cli",   "install": "apt install -y redis-tools || pkg install -y redis-tools", "category": "util", "desc": "Redis client", "url": "https://redis.io/"},
    "psql":        {"check": "command -v psql",        "install": "apt install -y postgresql-client || pkg install -y postgresql-client", "category": "util", "desc": "Postgres client", "url": "https://www.postgresql.org/"},
    "mongo":       {"check": "command -v mongo",       "install": "apt install -y mongodb-clients || pkg install -y mongodb-clients", "category": "util", "desc": "Mongo client", "url": "https://www.mongodb.com/"},
    "chromium":    {"check": "command -v chromium || command -v chromium-browser", "install": "apt install -y chromium-browser || pkg install -y chromium", "category": "util", "desc": "headless browser", "url": "https://www.chromium.org/"},
    "node":        {"check": "command -v node",        "install": "apt install -y nodejs npm || pkg install -y nodejs", "category": "util", "desc": "JS runtime", "url": "https://nodejs.org/"},
    "go":          {"check": "command -v go",          "install": "apt install -y golang-go || pkg install -y golang", "category": "util", "desc": "Go toolchain", "url": "https://go.dev/"},
    "cargo":       {"check": "command -v cargo",       "install": "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y", "category": "util", "desc": "Rust toolchain", "url": "https://rustup.rs/"},
    "pipx":        {"check": "command -v pipx",        "install": "apt install -y pipx || pip install --user pipx", "category": "util", "desc": "python tool installer", "url": "https://pypa.github.io/pipx/"},
    "gem":         {"check": "command -v gem",         "install": "apt install -y ruby-full || pkg install -y ruby", "category": "util", "desc": "ruby package manager", "url": "https://rubygems.org/"},
    "websockets":  {"check": "python3 -c 'import websockets' 2>/dev/null", "install": "pip install --user websockets", "category": "util", "desc": "python ws client", "url": "https://github.com/python-websockets/websockets"},
    "python-dotenv": {"check": "python3 -c 'import dotenv' 2>/dev/null", "install": "pip install --user python-dotenv", "category": "util", "desc": "env loader", "url": "https://github.com/theskumar/python-dotenv"},
    "playwright":  {"check": "python3 -c 'import playwright' 2>/dev/null", "install": "pip install playwright && python3 -m playwright install chromium", "category": "util", "desc": "headless browser control", "url": "https://playwright.dev/"},

    # ═══════════════════════════════════════════════════════════════════
    # WORDLISTS / DATA
    # ═══════════════════════════════════════════════════════════════════
    "seclists":    {"check": "test -d /usr/share/seclists", "install": "apt install -y seclists || git clone --depth 1 https://github.com/danielmiessler/SecLists ~/agent/wordlists/seclists", "category": "wordlist", "desc": "wordlist collection", "url": "https://github.com/danielmiessler/SecLists"},
    "payloads":    {"check": "test -d ~/agent/wordlists/PayloadsAllTheThings", "install": "git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings ~/agent/wordlists/PayloadsAllTheThings", "category": "wordlist", "desc": "payload repo", "url": "https://github.com/swisskyrepo/PayloadsAllTheThings"},
    "nuclei-templates": {"check": "test -d ~/nuclei-templates || test -d ~/.local/nuclei-templates", "install": "nuclei -update-templates", "category": "wordlist", "desc": "nuclei templates", "url": "https://github.com/projectdiscovery/nuclei-templates"},
    "rockyou":     {"check": "test -f /usr/share/wordlists/rockyou.txt -o -f ~/agent/wordlists/rockyou.txt", "install": "mkdir -p ~/agent/wordlists && curl -sL https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt -o ~/agent/wordlists/rockyou.txt", "category": "wordlist", "desc": "password wordlist", "url": "https://github.com/brannondorsey/naive-hashcat"},

    # ═══════════════════════════════════════════════════════════════════
    # MOBILE
    # ═══════════════════════════════════════════════════════════════════
    "jadx":        {"check": "command -v jadx",        "install": "apt install -y jadx || pkg install -y jadx", "category": "mobile", "desc": "APK -> Java decompiler", "url": "https://github.com/skylot/jadx"},
    "apktool":     {"check": "command -v apktool",     "install": "apt install -y apktool || pkg install -y apktool", "category": "mobile", "desc": "APK decompiler", "url": "https://github.com/iBotPeaches/Apktool"},
    "frida":       {"check": "command -v frida",       "install": "pipx install frida-tools || pip install --user frida-tools", "category": "mobile", "desc": "dynamic instrumentation", "url": "https://frida.re/"},
    "objection":   {"check": "command -v objection",   "install": "pipx install objection || pip install --user objection", "category": "mobile", "desc": "Frida wrapper", "url": "https://github.com/sensepost/objection"},

    # ═══════════════════════════════════════════════════════════════════
    # MISC / EXPLOIT FRAMEWORKS
    # ═══════════════════════════════════════════════════════════════════
    "msfconsole":  {"check": "command -v msfconsole",  "install": "apt install -y metasploit-framework || pkg install -y metasploit", "category": "misc", "desc": "metasploit framework", "url": "https://www.metasploit.com/"},
    "searchsploit": {"check": "command -v searchsploit", "install": "apt install -y exploitdb || git clone --depth 1 https://gitlab.com/exploit-database/exploitdb ~/agent/tools/exploitdb && ln -sf ~/agent/tools/exploitdb/searchsploit ~/agent/tools/searchsploit", "category": "misc", "desc": "exploit-db local search", "url": "https://gitlab.com/exploit-database/exploitdb"},
}


def list_categories():
    cats = {}
    for name, t in TOOLS.items():
        cats.setdefault(t.get("category", "misc"), []).append(name)
    return cats


def find(query):
    """Fuzzy search tools by name or description."""
    q = query.lower().strip()
    out = []
    for name, t in TOOLS.items():
        if q in name.lower() or q in t.get("desc", "").lower():
            out.append((name, t))
    return out

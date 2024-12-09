### Server-Side Request Forgery (SSRF):

#### Description:
Server-Side Request Forgery (SSRF) is a type of web security vulnerability where an attacker tricks a server into making unauthorized requests on its behalf. This often occurs when a web application accepts a URL or network request from the user without proper validation, allowing an attacker to exploit this behavior to access internal resources, such as databases, other internal services, or external servers that would otherwise be restricted.

### How SSRF Attacks Work

In SSRF, a malicious actor typically sends a crafted request to the vulnerable web application with a URL pointing to an internal or external resource. If the server blindly forwards this request, it can access resources the attacker cannot reach directly, like internal networks, metadata endpoints, or private APIs.

**Steps in an SSRF Attack:**
1. **Identify a Vulnerable Endpoint:** The attacker finds an endpoint that accepts URLs or network requests as user input (e.g., an image downloader or metadata fetcher).
2. **Craft Malicious Request:** The attacker crafts a URL pointing to an internal resource or any location they wish to target, such as `http://localhost:8080/admin`.
3. **Submit Request via Vulnerable Server:** The attacker submits this crafted URL as part of their input, and the server makes the request to the target URL.
4. **Access and Exfiltrate Data:** If successful, the attacker gains access to sensitive internal resources or exfiltrates data by manipulating responses.

**Potential SSRF Attack Targets:**
- Internal network services (`http://localhost:3306`)
- Cloud provider metadata services (`http://169.254.169.254` in AWS, for example)
- Private APIs or databases not exposed to the public internet

### Countermeasures for SSRF

Mitigating SSRF requires a combination of strong input validation, network segmentation, and secure configurations. Here are ten key countermeasures to defend against SSRF, along with code snippets for implementation.

---

#### 1. **Input Validation and Whitelisting**

Only allow URLs or IP addresses from trusted domains or IP addresses.

**Code Example:**
```python
from urllib.parse import urlparse

allowed_domains = ["example.com"]

def is_safe_url(url):
    parsed_url = urlparse(url)
    return parsed_url.hostname in allowed_domains

user_url = "http://example.com/resource"
if not is_safe_url(user_url):
    raise ValueError("Invalid URL")
```

#### 2. **Limit Network Access**

Restrict outbound requests from the server to prevent accessing sensitive internal resources.

**Example Implementation:**
On Linux, you can restrict network access using firewall rules to block access to internal IP ranges.
```bash
iptables -A OUTPUT -d 169.254.169.254 -j DROP   # Block AWS metadata endpoint
iptables -A OUTPUT -d 10.0.0.0/8 -j DROP         # Block private network range
```

#### 3. **Disable DNS Rebinding**

Prevent DNS rebinding attacks that can trick the server into making requests to internal resources.

**Configuration Example:**
Configure DNS resolvers to reject private IP ranges. In BIND, for example:
```bash
options {
    allow-query { none; };
    allow-query-cache { none; };
    // Additional configurations
}
```

#### 4. **Use Web Application Firewalls (WAF)**

Deploy a WAF configured to detect and block malicious SSRF payloads. Most WAFs come with rules to block SSRF patterns.

**Example (ModSecurity Rule):**
```apache
SecRule REQUEST_HEADERS:Host "localhost" "deny,log,status:403,id:1001,msg:'SSRF attempt'"
```

#### 5. **Metadata Access Control (for Cloud Environments)**

Block access to the cloud metadata service to prevent data exfiltration.

**Example for AWS EC2 Instances:**
You can configure IAM roles with the `Instance Metadata Service v2` (IMDSv2), which requires session tokens and cannot be accessed as easily.

#### 6. **Enforce URL Schemes and Protocols**

Restrict the allowed schemes (e.g., `https`) and disallow dangerous ones (`file`, `ftp`).

**Code Example:**
```python
def is_safe_scheme(url):
    parsed_url = urlparse(url)
    return parsed_url.scheme in ["http", "https"]

if not is_safe_scheme(user_url):
    raise ValueError("Invalid URL scheme")
```

#### 7. **Validate Response Content Type**

Ensure that the response content matches expected types and formats to prevent unauthorized data exposure.

**Code Example:**
```python
import requests

response = requests.get(user_url)
if "application/json" not in response.headers["Content-Type"]:
    raise ValueError("Unexpected content type")
```

#### 8. **Use DNS-based Allowlisting for IP Verification**

For IP verification, use a DNS lookup to verify that the hostname matches allowed IP addresses and domains.

**Code Example:**
```python
import socket

allowed_ips = ["192.0.2.1", "198.51.100.1"]

def is_allowed_ip(host):
    try:
        ip = socket.gethostbyname(host)
        return ip in allowed_ips
    except socket.error:
        return False

if not is_allowed_ip("example.com"):
    raise ValueError("Disallowed IP")
```

#### 9. **Network Segmentation**

Separate internal services and sensitive resources into isolated network segments, which the application server cannot reach directly.

**Example Implementation:**
Using Virtual Private Cloud (VPC) configurations in AWS to restrict network access between services.

#### 10. **Disable Unnecessary Services**

Disable services and open ports that the application does not need, reducing exposure to potential SSRF entry points.

**Example (Disable ports on Linux):**
```bash
sudo ufw deny 22   # Block SSH
sudo ufw deny 3306 # Block MySQL
```

#### 11. **Apply a Proxy for Outbound Requests**

Route all outbound requests through a controlled proxy that can enforce access policies.

**Code Example for a Python Proxy Configuration:**
```python
import requests

proxies = {
    "http": "http://proxy.example.com:3128",
    "https": "https://proxy.example.com:3128",
}

response = requests.get("http://example.com/resource", proxies=proxies)
```

#### 12. **Limit Response Size and Timeouts**

Limit the amount of data and time a request can consume to prevent SSRF-based resource exhaustion.

**Example Code:**
```python
response = requests.get("http://example.com/resource", timeout=5)
if len(response.content) > 1024:  # Limit response to 1KB
    raise ValueError("Response too large")
```

#### 13. **Monitor and Log Outbound Requests**

Track and analyze outbound requests to detect unusual patterns indicative of SSRF.

**Example Logging Code:**
```python
import logging

logger = logging.getLogger("ssrf_protection")

def log_request(url):
    logger.info(f"Outbound request to: {url}")
```

#### 14. **Implement Rate Limiting on External Requests**

Limit the rate of outbound requests to prevent abuse through repeated SSRF requests.

**Example with Flask-Limiter:**
```python
from flask import Flask
from flask_limiter import Limiter

app = Flask(__name__)
limiter = Limiter(app, key_func=lambda: request.remote_addr)

@app.route("/fetch_resource")
@limiter.limit("5 per minute")  # Allow 5 requests per minute
def fetch_resource():
    # Fetch the resource here
    pass
```

---

By implementing these 14 countermeasures, you can significantly reduce the risk of SSRF vulnerabilities in your applications. Keep in mind that securing against SSRF requires ongoing vigilance, especially as new techniques and attack patterns emerge. Regular updates to code, infrastructure, and security configurations are essential to maintain robust defenses.
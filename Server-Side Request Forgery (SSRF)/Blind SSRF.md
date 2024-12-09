### **Blind SSRF (Server-Side Request Forgery)**

#### **Overview**
Blind SSRF is a sophisticated attack that exploits server-side systems by sending crafted requests to internal services or systems from the server, often bypassing firewalls or network restrictions. Unlike typical SSRF attacks, in Blind SSRF, the attacker does not directly receive feedback from the server in the form of an immediate response (like HTTP status codes or error messages). Instead, the attacker needs to infer information through side effects (e.g., response times or other indirect clues).

In Blind SSRF, the attacker makes a request to the target server that forces it to send an HTTP request to an internal resource (e.g., an internal API or internal service), but the response is not visible to the attacker. By observing behavior such as latency, time delays, or other subtle signals, the attacker can infer valuable information or execute malicious actions.

---

### **How Blind SSRF is Done by Malicious Actors**

1. **Identify Target**: The attacker first identifies a vulnerable endpoint on the target server that allows users to submit URLs or IP addresses, such as an API endpoint that fetches data from a URL provided by the user.
   
2. **Craft Malicious Input**: The attacker crafts a malicious input, typically a URL, which points to internal services (e.g., `http://localhost:5000` or `http://127.0.0.1`). This input is designed to exploit the vulnerable endpoint to trigger server-side requests to restricted internal systems.

3. **Send the Malicious Request**: The attacker sends the malicious request containing the URL to the vulnerable endpoint.

4. **Observe Indirect Responses**: Since the response of the internal server is not sent back directly to the attacker, the attacker uses indirect feedback such as:
   - Increased response time (latency)
   - Changes in behavior (e.g., HTTP error codes returned from internal systems)
   - Resource consumption on the target server

5. **Extract Information**: By iterating through different URLs or payloads, the attacker can extract valuable information about the internal network, such as open ports, internal service names, and even specific vulnerabilities.

---

### **Countermeasures for Blind SSRF**

#### **1. Input Validation and Sanitization**
**Description**: Ensure that user-supplied URLs are strictly validated. By rejecting or sanitizing any inputs that could lead to SSRF, attackers can be blocked from accessing internal resources.

**Countermeasure Actions**:
- Validate the format of the URL to ensure it is a legitimate, externally reachable URL.
- Block internal IP addresses (e.g., `127.0.0.1`, `10.0.0.0/8`, `192.168.0.0/16`) and private IP ranges.

**Code Example**:
```python
import re

# Function to validate URLs
def validate_url(url):
    # Regex to validate proper URL format
    url_pattern = r"^(https?|ftp):\/\/[^\s/$.?#].[^\s]*$"
    if not re.match(url_pattern, url):
        raise ValueError("Invalid URL format")

    # Block private IP ranges
    blocked_ips = ['127.0.0.1', 'localhost', '10.', '192.168.', '172.16.']
    for ip in blocked_ips:
        if ip in url:
            raise ValueError("Private IP addresses are not allowed")

    return True
```

#### **2. URL Whitelisting**
**Description**: Limit requests to known, trusted external URLs by whitelisting specific domains or IP addresses. Only allow requests to URLs that are on the list of allowed external addresses.

**Countermeasure Actions**:
- Implement a URL whitelist that specifies which external services are permissible.
- Reject any request that attempts to access untrusted domains or internal services.

**Code Example**:
```python
# Function to whitelist valid external URLs
allowed_domains = ['example.com', 'api.example.com']

def is_url_allowed(url):
    parsed_url = urlparse(url)
    if parsed_url.netloc not in allowed_domains:
        raise ValueError("URL not allowed")
    return True
```

#### **3. Use DNS Resolution to Detect SSRF Attempts**
**Description**: Resolve URLs using DNS queries and verify if the resolved IP is an internal or private IP address. If the resolved IP points to an internal service, block the request.

**Countermeasure Actions**:
- Perform DNS resolution on the provided URL and check whether the IP address is in a private IP range.
- If the IP falls within internal IP ranges, prevent the request from being processed.

**Code Example**:
```python
import socket

# Function to resolve and check for internal IP
def resolve_and_check_url(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname

    try:
        ip = socket.gethostbyname(hostname)
        if ip.startswith(('10.', '192.', '172.')):
            raise ValueError("Internal IP addresses are blocked")
    except socket.error:
        raise ValueError("Unable to resolve URL")
    return True
```

#### **4. Implement Timeout Limits**
**Description**: To prevent attackers from using time-based blind SSRF techniques, you can set a maximum timeout for any HTTP request.

**Countermeasure Actions**:
- Set a strict timeout limit for all outgoing requests made by the server to internal or external URLs.

**Code Example**:
```python
import requests

# Set a timeout limit for all HTTP requests
def make_request(url):
    try:
        response = requests.get(url, timeout=5)  # 5 seconds timeout
        return response.text
    except requests.exceptions.Timeout:
        raise ValueError("Request timeout exceeded")
```

#### **5. Secure Proxy or Gateway Configuration**
**Description**: Use a secure proxy or gateway to control and monitor outgoing HTTP requests. Requests to internal services can be blocked at the network level.

**Countermeasure Actions**:
- Use a proxy that restricts outgoing HTTP requests to only specific external URLs.
- All outbound traffic should pass through a secure, monitored proxy to prevent malicious requests.

**Code Example**:
```bash
# Example NGINX configuration to restrict outgoing HTTP requests
server {
    location /api/ {
        proxy_pass http://allowed-apis.example.com;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # Block internal IP addresses
    location ~* ^/(127.0.0.1|localhost|10\..*)$ {
        deny all;
    }
}
```

#### **6. Use Security Headers (e.g., X-Content-Type-Options, Strict-Transport-Security)**
**Description**: Use security headers to prevent the server from sending or interpreting sensitive data in a way that could be used in an SSRF attack.

**Countermeasure Actions**:
- Configure appropriate HTTP headers like `X-Content-Type-Options`, `Strict-Transport-Security`, etc., to prevent SSRF.

**Code Example**:
```bash
# NGINX header settings
add_header X-Content-Type-Options "nosniff";
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
```

#### **7. Disable Unnecessary Internal Services**
**Description**: Reduce the attack surface by disabling unnecessary internal services (such as databases or admin panels) that could be targeted via SSRF.

**Countermeasure Actions**:
- Only expose services necessary for the application to function externally.
- Use internal firewalls or security groups to prevent access to unnecessary internal services.

**Code Example**:
```bash
# Firewall rules to block external access to internal ports
sudo ufw deny from any to 127.0.0.1 port 3306
```

#### **8. Monitor and Log Suspicious Activities**
**Description**: Implement detailed logging and monitoring to detect unusual patterns of outbound requests (e.g., access to internal addresses) that might indicate an SSRF attack.

**Countermeasure Actions**:
- Log all outbound requests and monitor for anomalies such as requests to localhost or internal IP addresses.
- Use intrusion detection systems (IDS) to detect patterns consistent with SSRF attacks.

**Code Example**:
```python
import logging

# Set up basic logging
logging.basicConfig(filename='app.log', level=logging.INFO)

# Log outgoing requests
def log_request(url):
    logging.info(f"Outgoing request: {url}")
    # Further logic to process the request
```

#### **9. Restrict User Input Types**
**Description**: Limit the types of user input to prevent the injection of malicious URLs or IP addresses.

**Countermeasure Actions**:
- Limit user inputs to certain formats (e.g., exclude URL inputs that contain `http://`, `https://`, or IP addresses).
- Use regular expressions or built-in validators to restrict input formats.

**Code Example**:
```python
# Function to validate user inputs for only domain names
def validate_domain_name(input_value):
    domain_pattern = r"^[a-zA-Z0-9-]+\.[a-zA-Z]{2,6}$"
    if not re.match(domain_pattern, input_value):
        raise ValueError("Invalid domain name")
    return True
```

#### **10. Use Web Application Firewalls (WAF)**
**Description**: A Web Application Firewall (WAF) can help detect and block malicious traffic, including SSRF attempts.

**Countermeasure Actions**:
- Deploy a WAF to inspect and filter HTTP requests, looking for patterns of SSRF attempts.
- Configure the WAF to block access to internal IP addresses or domains.

**Code Example**:
```bash
# Example mod_security rule for blocking SSRF
SecRule REQUEST_URI "@rx ^(127.0.0.1|localhost|0.0.0.0|169.254)" \
    "phase:2,deny,status:403,msg:'Potential SSRF detected'"
```

---

### **Conclusion**

Blind SSRF is a dangerous vulnerability that can lead to unauthorized access to internal services or systems, data leaks, or system compromise. By implementing the above countermeasures, you can significantly reduce the risk of SSRF attacks on your systems. Ensuring strong input validation, limiting access to trusted services, setting timeouts, and monitoring traffic are some of the key practices to mitigate Blind SSRF effectively. Always stay updated with security best practices and continuously review your security posture to stay ahead of evolving attack techniques.
### Time-Based Blind SSRF (Server-Side Request Forgery)

#### **What is Time-Based Blind SSRF?**

Time-Based Blind SSRF is a specific type of SSRF attack where an attacker tricks the server into making requests to internal resources that are not normally accessible from outside. The term "blind" means the attacker doesn't directly see the response from the request, but can infer the outcome based on how long the server takes to respond. This attack method relies on using time delays (such as waiting for a server response) to exfiltrate information or gain unauthorized access.

In this case, the attacker can exploit time-based mechanisms, such as delay responses, to determine whether the server was able to successfully connect to the internal resource. It's typically used to target services like internal metadata endpoints, databases, and other vulnerable infrastructure that would not normally be exposed.

#### **How Time-Based Blind SSRF Works**

1. **Malicious Request:**
   The attacker sends a crafted request to the web application. The request targets an internal server or service, and it may involve sending a payload that triggers a time-based response on the backend.
   
2. **Time Delay:**
   If the request is successfully processed by the server, it might be designed to introduce a deliberate time delay in the server's response (e.g., a 2-second delay). This delay could indicate that the internal service was accessible.

3. **Infer Results:**
   Since the attacker cannot directly see the response, they will send several requests, each triggering a delay of varying lengths. Based on the response times, the attacker can infer whether the requested internal resource exists or whether certain conditions (like authentication) were met.

#### **Example Attack Scenario**

1. **The Attacker's Goal:**  
   The attacker wants to check if an internal metadata server (like `http://localhost:169.254.169.254` for AWS EC2 metadata) is accessible.

2. **Crafted Request Example:**
   The attacker crafts a URL such as:
   ```
   http://target-site.com/fetch?url=http://localhost:169.254.169.254/latest/meta-data/
   ```
   If this request successfully reaches the internal metadata endpoint, the server might delay its response or crash, giving the attacker an indication of success.

3. **Increased Delay for Further Information:**
   The attacker may attempt different paths or conditions and observe different delays:
   ```
   http://target-site.com/fetch?url=http://localhost:169.254.169.254/latest/meta-data/iam/role
   ```
   If the request takes a long time, the attacker might infer that they have successfully connected to the internal resource.

#### **Malicious Process of Time-Based Blind SSRF**

1. **Preparation:**
   The attacker identifies a vulnerable endpoint on a web server that allows user input, like a URL or server request.

2. **Crafting the Payload:**
   The attacker sends a crafted URL, often using URL encoding or other obfuscation methods to bypass basic input validation.

3. **Observing the Response:**
   Since it's a blind SSRF, the attacker can only observe the response time, looking for time delays or the server's failure to process the request.

4. **Exfiltrating Information:**
   By triggering requests to internal endpoints (e.g., internal APIs, databases, and metadata services), the attacker can indirectly retrieve sensitive information such as metadata, internal server data, or even authentication tokens.

#### **Countermeasures Against Time-Based Blind SSRF**

1. **Input Validation and Sanitization**

   - **Description:** Ensure that user-supplied URLs are properly validated and sanitized before making requests. Reject any URLs pointing to internal services or localhost.
   
   - **Code Snippet:**
     ```python
     from urllib.parse import urlparse

     def is_valid_url(url):
         # Validate URL format
         parsed_url = urlparse(url)
         # Disallow private IPs or local services
         if parsed_url.hostname in ['localhost', '127.0.0.1', '169.254']:
             raise ValueError("Invalid URL: Internal addresses are not allowed")
         return True
     ```

2. **Use a URL Whitelist**

   - **Description:** Only allow requests to known and trusted domains. Any URL that is not on the whitelist should be blocked.
   
   - **Code Snippet:**
     ```python
     ALLOWED_DOMAINS = ['example.com', 'trusted-api.com']

     def validate_url(url):
         parsed_url = urlparse(url)
         if parsed_url.hostname not in ALLOWED_DOMAINS:
             raise ValueError("Domain not allowed")
         return True
     ```

3. **Timeout Limits**

   - **Description:** Limit the maximum time allowed for requests. If a request exceeds this time, it should be canceled.
   
   - **Code Snippet:**
     ```python
     import requests

     def send_request(url):
         try:
             response = requests.get(url, timeout=5)  # Set a timeout limit
             return response.text
         except requests.Timeout:
             raise ValueError("Request timed out")
     ```

4. **Limit HTTP Methods**

   - **Description:** Only allow safe HTTP methods (e.g., GET) and restrict methods like POST or PUT for unauthenticated requests.
   
   - **Code Snippet:**
     ```python
     def handle_request(request):
         if request.method not in ['GET']:
             raise ValueError("Unsupported HTTP method")
         # Process request further
     ```

5. **Restrict Internal Resource Access**

   - **Description:** Use firewalls and network segmentation to prevent access to internal resources or sensitive endpoints from external requests.
   
   - **Code Snippet:**
     ```bash
     # Using a firewall to restrict access to internal services
     sudo ufw deny from any to 169.254.169.254
     ```

6. **Rate Limiting**

   - **Description:** Implement rate limiting to detect and block suspicious or excessive requests that could indicate an SSRF attack.
   
   - **Code Snippet:**
     ```python
     from time import time
     request_times = []

     def rate_limit_request():
         current_time = time()
         request_times.append(current_time)
         # Allow only 10 requests per minute
         request_times = [t for t in request_times if current_time - t < 60]
         if len(request_times) > 10:
             raise ValueError("Too many requests")
         return True
     ```

7. **Detailed Logging and Monitoring**

   - **Description:** Log all incoming requests and analyze the response time to detect anomalies that might indicate an SSRF attempt.
   
   - **Code Snippet:**
     ```python
     import logging

     logging.basicConfig(filename='access.log', level=logging.INFO)

     def log_request(request, response_time):
         logging.info(f"Request: {request.url}, Response Time: {response_time}")
     ```

8. **Blacklisting Internal IP Ranges**

   - **Description:** Block requests to IP ranges typically used by internal services (e.g., private IP ranges like `10.x.x.x`, `192.168.x.x`).
   
   - **Code Snippet:**
     ```python
     def block_internal_ips(url):
         parsed_url = urlparse(url)
         internal_ips = ['10.', '192.168.', '127.']
         if any(parsed_url.hostname.startswith(ip) for ip in internal_ips):
             raise ValueError("Blocked internal IP address")
     ```

9. **Server Response Time Analysis**

   - **Description:** Monitor the server's response times to detect delays caused by malicious requests. Alert the system administrators when suspicious delays are detected.
   
   - **Code Snippet:**
     ```python
     import time

     def monitor_response_time(url):
         start_time = time.time()
         send_request(url)
         end_time = time.time()
         if end_time - start_time > 2:  # Arbitrary threshold of 2 seconds
             alert_admin("Suspicious request detected!")
     ```

10. **Use Web Application Firewalls (WAF)**

    - **Description:** Use WAFs to automatically block SSRF attacks by filtering out suspicious traffic patterns.
    
    - **Code Snippet:**
      ```bash
      # Example configuration for ModSecurity WAF to detect SSRF
      SecRule REQUEST_URI "@rx \blocalhost\b" "id:1001,deny,log,msg:'SSRF attempt detected'"
      ```

11. **Security Headers**

    - **Description:** Implement appropriate security headers, such as `X-Content-Type-Options` and `Strict-Transport-Security`, to ensure secure communication and reduce the chance of SSRF.
    
    - **Code Snippet:**
      ```bash
      # Add security headers in your server configuration
      X-Content-Type-Options: nosniff
      Strict-Transport-Security: max-age=31536000; includeSubDomains
      ```

---

### Conclusion

Time-Based Blind SSRF is a sophisticated attack method where an attacker uses timing delays to infer information about internal resources. By implementing the countermeasures above, you can significantly reduce the risk of such attacks. Always validate and sanitize user input, employ strict network segmentation, and keep your software and infrastructure up-to-date to stay ahead of potential threats.
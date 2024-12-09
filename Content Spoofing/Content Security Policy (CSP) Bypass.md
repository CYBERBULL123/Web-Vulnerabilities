# **Content Security Policy (CSP) Bypass: In-Depth Overview and Countermeasures**

### **Introduction to Content Security Policy (CSP)**

Content Security Policy (CSP) is a powerful browser feature designed to mitigate certain types of attacks, such as Cross-Site Scripting (XSS) and data injection attacks, by specifying which sources the browser should consider to be valid for loading content. By setting up a CSP header, websites can enforce restrictions on where and how content is loaded.

### **How Malicious Actors Exploit CSP Bypass**

Malicious actors may attempt to bypass CSP settings to perform attacks like XSS or data injection. While CSP is a strong security feature, it has its limitations and can sometimes be bypassed due to misconfigurations, improper settings, or browser-specific quirks.

**Common Bypass Methods:**

1. **Using Unsafe Inline Scripts**: CSP blocks inline JavaScript, but attackers may exploit loopholes in CSP configurations (like using `'unsafe-inline'`) to execute malicious scripts.

2. **CSP Reporting (via `report-uri`)**: Attackers can exploit CSP's reporting feature by manipulating the report-uri endpoint, leading to false alerts or data exfiltration.

3. **Exploiting Wildcards in Sources**: Wildcards (like `' * '` or `'self'`) in the policy can allow unwanted content sources to bypass restrictions.

4. **CSS Injection**: CSP usually focuses on JavaScript, but malicious actors can inject payloads via CSS properties (e.g., `background-image` or `url()`), which can be used for XSS attacks.

5. **Using Base64 Encoded Payloads**: Base64 encoding can sometimes bypass CSP restrictions, as it obfuscates malicious code inside data URLs.

6. **Leverage Data URLs**: Data URIs, if not restricted by CSP, can be used to inject malicious content into the site.

7. **Subdomain Takeovers**: If a website’s CSP includes third-party domains, attackers may attempt to take over subdomains of these domains to serve malicious content.

8. **WebSockets**: If a CSP doesn’t include proper WebSocket restrictions, attackers can use WebSockets for command-and-control channels.

9. **Image Element Injection**: CSP doesn't typically cover image elements, and a malicious actor could inject JavaScript via the `src` attribute of an `<img>` tag.

10. **JSONP Exploitation**: Malicious actors may inject JSONP responses that can bypass CSP restrictions, allowing them to execute JavaScript from trusted sources.

---

### **Step-by-Step Process of CSP Bypass by Malicious Actors**

1. **Initial Reconnaissance:**
   - The attacker first inspects the website for the presence of CSP by checking response headers.
   - Tools like Burp Suite, Fiddler, or Chrome DevTools can be used to view the CSP header.
   
2. **Exploiting Weak CSP:**
   - Once the attacker identifies a weak or misconfigured CSP policy (e.g., excessive use of wildcards or `'unsafe-inline'`), they craft an attack vector.
   - This could involve injecting malicious scripts through allowed sources, data URLs, or inline styles.

3. **Payload Delivery:**
   - The attacker may inject a payload into an input field, URL parameter, or even exploit third-party resources.
   - The malicious script may then execute when the page is loaded, bypassing CSP restrictions.

4. **Execution of Malicious Activity:**
   - Once the payload is successfully delivered, it could be used to steal cookies, perform clickjacking, or exploit other vulnerabilities within the application.

5. **Escalation and Exfiltration:**
   - The attacker could escalate privileges by exploiting the JavaScript they injected or exfiltrate sensitive data like session tokens or personal information.

---

### **Countermeasures Against CSP Bypass**

Here are more than 10 practical countermeasures to prevent CSP bypass:

---

#### **1. Use Strict CSP Policies**

**Description:** Always apply a restrictive CSP policy with precise whitelisting of trusted sources. Avoid using overly permissive directives like `'unsafe-inline'` or `'unsafe-eval'`.

**Example Code (Strict CSP Policy):**
```http
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; style-src 'self'; img-src 'self'; report-uri /csp-report-endpoint;
```

---

#### **2. Avoid Using `unsafe-inline`**

**Description:** Avoid using `'unsafe-inline'` for JavaScript and CSS. This directive allows inline JavaScript to execute, which defeats the purpose of CSP in preventing XSS attacks.

**Example Code (Preventing Inline Scripts):**
```http
Content-Security-Policy: script-src 'self' 'nonce-<RANDOM_NONCE>'; style-src 'self';
```

---

#### **3. Implement Nonces for Inline Scripts**

**Description:** Use nonces or hashes for inline scripts to ensure that only authorized scripts can be executed.

**Example Code (Using Nonces for Inline Scripts):**
```html
<script nonce="RANDOM_NONCE_VALUE">
  // Your inline JavaScript here
</script>
```
```http
Content-Security-Policy: script-src 'self' 'nonce-RANDOM_NONCE_VALUE';
```

---

#### **4. Restrict `object-src`**

**Description:** Set `object-src` to `'none'` to prevent the use of `<object>`, `<embed>`, or `<applet>` elements, which can be used for malicious content.

**Example Code (Restricting Object Sources):**
```http
Content-Security-Policy: object-src 'none';
```

---

#### **5. Use the `strict-dynamic` Directive**

**Description:** Use `strict-dynamic` with `script-src` to limit the execution of scripts to those that are dynamically added by trusted sources.

**Example Code (Using `strict-dynamic`):**
```http
Content-Security-Policy: script-src 'self' 'strict-dynamic' https://trusted-source.com;
```

---

#### **6. Enable Subresource Integrity (SRI)**

**Description:** Use Subresource Integrity (SRI) to ensure that third-party scripts loaded from external sources have not been tampered with.

**Example Code (Using SRI for External Resources):**
```html
<script src="https://cdn.example.com/script.js" integrity="sha384-<hash-value>" crossorigin="anonymous"></script>
```

---

#### **7. Implement CSP Reporting**

**Description:** Enable CSP violation reports to monitor suspicious activity and mitigate attacks in real-time.

**Example Code (Enabling CSP Reporting):**
```http
Content-Security-Policy: default-src 'self'; report-uri /csp-report-endpoint;
```

---

#### **8. Use `require-trusted-types-for` Directive**

**Description:** Prevent script injection attacks by enabling the `require-trusted-types-for` directive, which only allows the browser to execute scripts that are verified.

**Example Code (Using Trusted Types):**
```http
Content-Security-Policy: require-trusted-types-for 'script';
```

---

#### **9. Sanitize User Input**

**Description:** Always sanitize user input before including it in the document to prevent malicious code injection, which could exploit CSP bypasses.

**Example Code (Sanitizing User Input in a Web Application):**
```python
import bleach

def sanitize_input(user_input):
    return bleach.clean(user_input, tags=[], attributes={}, styles=[], protocols=['http', 'https'])
```

---

#### **10. Disallow Inline Event Handlers**

**Description:** Avoid using inline event handlers (`onclick`, `onload`, etc.) because they may be bypassed by attackers to inject malicious code.

**Example Code (Avoid Inline Event Handlers):**
```html
<!-- Instead of: -->
<button onclick="alert('Hello')">Click me</button>

<!-- Use: -->
<button id="btn">Click me</button>
<script>
  document.getElementById('btn').addEventListener('click', function() {
    alert('Hello');
  });
</script>
```

---

#### **11. Restrict WebSocket Connections**

**Description:** If your application uses WebSockets, restrict which domains are allowed to establish WebSocket connections.

**Example Code (Restricting WebSockets in CSP):**
```http
Content-Security-Policy: default-src 'self'; connect-src 'self' wss://trusted-source.com;
```

---

#### **12. Use Strong Content-Type Header for Resources**

**Description:** Use the `X-Content-Type-Options` header to prevent browsers from interpreting files as different types.

**Example Code (Setting `X-Content-Type-Options` Header):**
```http
X-Content-Type-Options: nosniff
```

---

### **Conclusion**

CSP is an essential tool for securing modern web applications, but like any security mechanism, it has its limitations. Malicious actors can bypass CSP if not implemented correctly, which is why it's crucial to apply strict configurations, use nonces and hashes, and implement security practices like sanitizing input and using external resources with integrity checks.

By following the best practices outlined above, developers can harden their applications against CSP bypass attempts and mitigate the risk of XSS and other malicious activities.
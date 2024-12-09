### Clickjacking 

**Clickjacking** is a technique used by malicious actors to trick users into unintentionally clicking on something different from what they perceive on a web page. This is often achieved by embedding a transparent or opaque overlay containing a malicious page or element over a legitimate page. Users interact with the underlying malicious content without realizing it, potentially leading to actions such as unauthorized purchases, sharing sensitive information, or compromising accounts.

#### How Clickjacking Works

In a clickjacking attack, a malicious actor typically follows these steps:

1. **Preparation of Malicious Overlay**:
   - The attacker creates a webpage with invisible or transparent iframes containing a target website or specific UI element, such as a "Like" button, login button, or sensitive action button.
  
2. **Embedding the Target Website**:
   - The target site or its elements are embedded within an iframe or overlay, which is then positioned to align with intended actions.

3. **Luring Users**:
   - Victims are lured to the malicious site through phishing emails, ads, or deceptive links. The target site within the iframe is positioned over buttons that may initiate actions without the user’s awareness.
  
4. **User Interaction**:
   - When the user interacts with what they think is the malicious site’s content, they are actually interacting with the hidden elements on the target website, inadvertently performing actions like submitting sensitive data or clicking on payment buttons.

### Impact of Clickjacking

Clickjacking can result in several risks:
- **Unauthorized Actions**: Actions such as transferring funds or posting sensitive data on social media.
- **Compromised Accounts**: Users may unknowingly perform actions in their own accounts.
- **Data Loss or Theft**: Sensitive data can be stolen if attackers trick users into revealing information.
  
### Countermeasures for Preventing Clickjacking

There are multiple techniques for preventing clickjacking. Implementing a combination of these can significantly enhance protection.

#### 1. X-Frame-Options Header

**Description**: The `X-Frame-Options` HTTP header instructs browsers on whether a site can be embedded within an iframe.

- **DENY**: Prevents the page from being displayed in a frame, regardless of the domain.
- **SAMEORIGIN**: Allows embedding only if the request originates from the same domain.
- **ALLOW-FROM URI**: Allows embedding only from a specified domain.

**Code Example**:
```http
# Apache
Header always set X-Frame-Options "DENY"

# Nginx
add_header X-Frame-Options "DENY";
```

#### 2. Content Security Policy (CSP) Frame Ancestors Directive

**Description**: CSP’s `frame-ancestors` directive specifies which domains are allowed to embed the page in an iframe, providing more granular control than `X-Frame-Options`.

**Code Example**:
```http
# Add CSP to allow framing only from the same origin
Content-Security-Policy: frame-ancestors 'self';
```

#### 3. Frame Busting with JavaScript

**Description**: Frame busting is a technique used to prevent your site from being embedded in iframes. This method typically involves JavaScript to break out of any iframe.

**Code Example**:
```javascript
if (window.top !== window.self) {
    window.top.location = window.self.location;
}
```

#### 4. Use of SameSite Cookies

**Description**: By setting cookies with the `SameSite` attribute, you can help prevent cross-origin requests and reduce the risk of clickjacking attacks on sensitive sessions.

**Code Example**:
```http
Set-Cookie: sessionId=abc123; SameSite=Strict; Secure; HttpOnly;
```

#### 5. Implementing Double Submit Cookies

**Description**: A CSRF token can be implemented as a cookie to validate each session request, making clickjacking harder to perform on secure forms.

**Code Example**:
```javascript
// Set token as cookie and form field
document.cookie = "csrf_token=your_csrf_token";
document.getElementById("csrf").value = "your_csrf_token";
```

#### 6. Input Validation and Sanitization

**Description**: Validate all input fields to ensure they don’t contain unexpected characters that could allow clickjacking code to execute if any element is exposed.

**Code Example**:
```python
import re

def validate_input(input_data):
    if re.match("^[a-zA-Z0-9_]*$", input_data):
        return True
    return False
```

#### 7. Multi-Factor Authentication (MFA)

**Description**: By implementing MFA, you require an additional step of authentication, making it much harder for clickjacking attacks to succeed, especially for sensitive actions.

#### 8. User Education and Awareness

**Description**: Educating users about safe browsing practices, such as avoiding suspicious links and recognizing signs of phishing, can reduce the success of clickjacking.

#### 9. Visual Cues for Sensitive Actions

**Description**: Implementing visual confirmation steps before executing high-risk actions, like deleting an account or processing payments, helps users confirm their actions.

#### 10. Disabling Embedding on High-Risk Pages

**Description**: For pages where sensitive actions occur, such as payments, implement a security policy that blocks embedding entirely.

**Code Example**:
```http
# Content Security Policy for High-Risk Pages
Content-Security-Policy: frame-ancestors 'none';
```

#### 11. Intrusion Detection and Logging

**Description**: Implementing logging and monitoring tools that alert security teams of unusual iframe embedding or click-based actions helps detect and respond to clickjacking attempts quickly.

#### 12. Using Secure HTTPS Connections

**Description**: HTTPS ensures that malicious actors cannot modify content mid-transmission, which can prevent some types of clickjacking setups. Configure all web traffic to use HTTPS.

**Code Example**:
```http
# Redirect HTTP to HTTPS (Apache)
<VirtualHost *:80>
   ServerName example.com
   Redirect permanent / https://example.com/
</VirtualHost>
```

### Conclusion

Clickjacking is a serious threat to web security, allowing attackers to exploit the behavior of unaware users. By implementing multiple layers of defense, including security headers, frame-busting techniques, content security policies, and user education, you can effectively mitigate the risk of clickjacking on your site.
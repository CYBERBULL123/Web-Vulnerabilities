### Inadequate Session Timeout

#### Description:
Inadequate Session Timeout refers to improperly configured session expiration, which allows sessions to remain active longer than necessary. This leaves users vulnerable to session hijacking attacks, where a malicious actor gains unauthorized access by using an active session of a legitimate user. Sessions are supposed to expire after a period of inactivity or once the user logs out, but without adequate session timeouts, the session can stay active for hours, days, or even indefinitely. This vulnerability is particularly harmful in sensitive applications like banking, healthcare, and e-commerce, where unauthorized access could lead to severe data breaches.

---

### How Malicious Actors Exploit Inadequate Session Timeout

1. **Session Hijacking**: Attackers can use stolen session IDs to hijack active user sessions. These IDs are often obtained through Cross-Site Scripting (XSS), social engineering, or by sniffing unencrypted traffic.
  
2. **Session Fixation**: In a session fixation attack, the attacker forces a user to authenticate on a predetermined session ID, which the attacker can later reuse.
   
3. **Session Replay Attacks**: In these attacks, malicious actors reuse session tokens to gain access without requiring credentials. With an inadequate timeout policy, these tokens can remain valid for an extended period.
   
4. **Idle Sessions Exploitation**: When users forget to log out or accidentally leave sessions open, attackers who gain access to the same device or network can use these sessions to perform unauthorized actions.

---

### Countermeasures Against Inadequate Session Timeout

Here are some best practices to mitigate the risks associated with inadequate session timeout. Each of these is accompanied by example code snippets for implementing the countermeasure.

#### 1. Set Reasonable Session Timeout Duration

Set a reasonable session timeout for sensitive applications (e.g., 15-30 minutes of inactivity).

**Code Example (Django Web Framework):**
```python
# settings.py
# Set session timeout to 30 minutes
SESSION_COOKIE_AGE = 1800  # 30 minutes
```

#### 2. Implement Idle Timeout for User Inactivity

Idle timeout automatically logs out users after a period of inactivity.

**Code Example (JavaScript):**
```javascript
let idleTime = 0;
setInterval(() => { 
    idleTime++;
    if (idleTime >= 30) { // 30 minutes
        alert("Session expired due to inactivity.");
        window.location.href = '/logout';
    }
}, 60000); // 1 minute interval

// Reset idle time on user activity
document.onmousemove = document.onkeypress = () => { idleTime = 0; };
```

#### 3. Enforce Absolute Session Timeout

Set an absolute session timeout, where users are logged out after a maximum time limit, regardless of activity.

**Code Example (Express.js):**
```javascript
const session = require('express-session');

app.use(session({
    secret: 'your_secret_key',
    cookie: { maxAge: 3600000 }, // 1 hour absolute timeout
    rolling: true, // Reset expiration on activity
    resave: false,
    saveUninitialized: true
}));
```

#### 4. Use Short-Lived Tokens for Sensitive Applications

Use short-lived session tokens for sensitive applications and refresh them periodically to enhance security.

**Code Example (OAuth Token with Refresh, Node.js):**
```javascript
// Generate access and refresh tokens
const accessToken = generateToken({ expiresIn: '15m' }); // 15 minutes
const refreshToken = generateToken({ expiresIn: '1h' }); // 1 hour
```

#### 5. Use Secure Cookies for Session Management

Set the `HttpOnly` and `Secure` flags on cookies to prevent unauthorized access via JavaScript and to ensure they are sent over HTTPS.

**Code Example (Express.js):**
```javascript
app.use(session({
    secret: 'your_secret_key',
    cookie: {
        httpOnly: true,    // Prevent JavaScript access
        secure: true,      // Require HTTPS
        maxAge: 1800000    // 30 minutes
    }
}));
```

#### 6. Implement Session Invalidation on Logout

Explicitly invalidate session tokens on logout to prevent reuse.

**Code Example (Django Logout View):**
```python
from django.contrib.auth import logout
from django.shortcuts import redirect

def logout_view(request):
    logout(request)  # Clears the session
    return redirect('login')
```

#### 7. Use Multi-Factor Authentication (MFA)

Enforce MFA for critical actions and user sessions, making it harder for attackers to exploit stolen sessions.

**Code Example (Python - Pseudocode):**
```python
# After successful login
if user.mfa_enabled:
    send_mfa_code(user.phone_number)
    verify_mfa_code(user_input_code)
```

#### 8. Monitor Session Activity and Log Anomalies

Use activity logs to track unusual session activity patterns, such as simultaneous logins from different locations.

**Code Example (Flask - Pseudocode):**
```python
# Track login location
def log_login(user_id, ip_address, location):
    # Record user login data
    store_login_activity(user_id, ip_address, location)

# Trigger alert if unusual behavior detected
if unusual_login_pattern(user_id):
    alert_user(user_id)
```

#### 9. Implement Cross-Site Request Forgery (CSRF) Protection

Protect session cookies from CSRF attacks by implementing CSRF tokens on state-changing requests.

**Code Example (Django):**
```python
# Add CSRF token in Django template
<form method="post" action="/submit_data/">
    {% csrf_token %}
    <input type="text" name="data">
    <button type="submit">Submit</button>
</form>
```

#### 10. Use Session Rotation

Rotate session identifiers upon login and periodically to reduce the risk of session hijacking.

**Code Example (Flask):**
```python
from flask import session

def rotate_session_id():
    session.clear()  # Clears old session
    session['user_id'] = current_user.id  # Creates new session with a unique ID
```

#### 11. Configure Secure Session Management Headers

Use security headers such as `Strict-Transport-Security` and `Cache-Control` to ensure session data is managed securely over HTTPS.

**Code Example (HTTP headers configuration):**
```http
Strict-Transport-Security: max-age=31536000; includeSubDomains
Cache-Control: no-store
Pragma: no-cache
```

#### 12. Notify Users of New Session Logins

Alert users when a new session is created from a different device or IP to help identify unauthorized access.

**Code Example (Python):**
```python
# Upon successful login
def notify_user_login(user, ip_address):
    send_email(user.email, f"New login from IP: {ip_address}")
```

#### 13. Enforce Strong Password Policies

Encourage users to set strong passwords to reduce the chance of brute-force attacks leading to session hijacking.

**Code Example (Django Password Validation):**
```python
# settings.py
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator', 'OPTIONS': {'min_length': 8}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]
```

#### 14. Implement Session Locking Mechanism for Sensitive Transactions

Restrict access to sensitive operations to a single session, locking other active sessions.

**Code Example (Pseudocode):**
```python
def lock_sensitive_action(user_id, action):
    # Allow only one session for this action
    if user_has_other_active_sessions(user_id):
        return "Action locked to the current session."
```

---

### Summary

Each countermeasure addresses a unique aspect of session security to prevent inadequate session timeout vulnerabilities. Implementing these methods together strengthens your application’s resilience against malicious actors aiming to hijack, fixate, or replay user sessions.
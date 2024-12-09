### HTTP Parameter Pollution (HPP)

#### Overview
HTTP Parameter Pollution (HPP) is a web attack technique where an attacker manipulates or "pollutes" HTTP parameters by injecting multiple instances of the same parameter with different values. This can lead to unintended behavior on the server, potentially causing vulnerabilities such as bypassing security controls, altering data, or triggering unexpected server responses. 

For instance, if a vulnerable application takes multiple `user` parameters in the URL (e.g., `user=admin&user=guest`), the backend server may not handle this ambiguity consistently, leading to unpredictable behavior.

#### Attack Process
1. **Parameter Injection**: The attacker crafts requests with multiple instances of a parameter (e.g., `user=admin&user=guest`).
2. **Ambiguity Exploitation**: Different servers and languages handle repeated parameters differently. An attacker may exploit this behavior:
   - Some servers process the first parameter instance, while others process the last.
   - Some concatenate the values, creating a combined parameter.
3. **Application Manipulation**: The attacker sends polluted parameters to the server, which may misinterpret them, potentially allowing unauthorized access or manipulation of data.
4. **Outcome**: The polluted parameters could cause issues like:
   - Bypassing input validation or authorization checks.
   - Exposing sensitive data.
   - Triggering unexpected behavior in APIs or backend systems.

### Common HPP Attack Scenarios
- **Authentication Bypass**: Polluting parameters that control access, like `role=user&role=admin`, to manipulate roles.
- **Data Manipulation**: Injecting polluted data parameters that modify query behavior, like `amount=100&amount=-100`.
- **API Manipulation**: Polluting API parameters to bypass checks or alter requests to other services.

---

### Countermeasures Against HTTP Parameter Pollution

To protect applications from HPP, here are effective countermeasures and secure coding practices to implement. Each countermeasure includes a description and a code snippet.

---

#### 1. Parameter Validation

Ensure that parameters are strictly validated and only allow expected values for each parameter.

**Code Snippet** (Python Flask example):
```python
@app.route('/login', methods=['POST'])
def login():
    # Explicitly check for a single instance of the 'username' and 'password' parameters
    username = request.args.getlist('username')
    if len(username) != 1:
        abort(400, "Invalid parameter usage")
    password = request.args.getlist('password')
    if len(password) != 1:
        abort(400, "Invalid parameter usage")
    # Continue with login logic
```

#### 2. Restrict Allowed Parameters

Only allow parameters that are explicitly defined in the application, rejecting any unapproved parameters.

**Code Snippet**:
```python
def validate_params(params, allowed_params):
    for param in params.keys():
        if param not in allowed_params:
            abort(400, f"Unexpected parameter: {param}")

# Use it in an endpoint
@app.route('/submit', methods=['GET', 'POST'])
def submit_form():
    allowed_params = {'username', 'email'}
    validate_params(request.args, allowed_params)
    # Process form data
```

#### 3. Enforce Parameter Length Limits

Limit the number of times a parameter can appear by enforcing a max length or count for each parameter.

**Code Snippet**:
```python
@app.route('/process', methods=['POST'])
def process_request():
    if len(request.args.getlist('user')) > 1:
        abort(400, "Duplicate 'user' parameters not allowed")
    # Continue processing
```

#### 4. Implement Strong Input Sanitization

Sanitize input values to prevent malicious injection attempts, such as stripping or encoding suspicious characters.

**Code Snippet**:
```python
import html

@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query', '')
    safe_query = html.escape(query)  # Prevents malicious input
    # Use safe_query in database queries or display
```

#### 5. Use Parameter Encoding

URL-encode parameters to prevent attackers from directly injecting pollution strings.

**Code Snippet**:
```python
import urllib.parse

def safe_url(url, params):
    return url + '?' + urllib.parse.urlencode(params)

# Example usage
safe_url('/search', {'query': 'data'})
```

#### 6. Use Middleware for Parameter Checking

Implement middleware to scan requests for duplicate parameters and block requests that contain them.

**Code Snippet** (Express.js middleware example):
```javascript
app.use((req, res, next) => {
  const seenParams = new Set();
  for (const param in req.query) {
    if (seenParams.has(param)) {
      return res.status(400).send("Duplicate parameters not allowed");
    }
    seenParams.add(param);
  }
  next();
});
```

#### 7. Apply Strong Access Control

Ensure that each parameter is validated against the user's permissions and context to prevent manipulation of sensitive data.

**Code Snippet**:
```python
@app.route('/edit', methods=['POST'])
def edit():
    if not user.has_permission('edit'):
        abort(403)
    item_id = request.args.get('item_id')
    # Further logic to edit item
```

#### 8. Use Secure Frameworks and Libraries

Rely on secure libraries and frameworks that manage parameters securely and help avoid issues with repeated or malformed parameters.

**Example**:
Use Django’s form validation, which ensures parameters are strictly typed and validated:
```python
from django import forms

class UserForm(forms.Form):
    username = forms.CharField(max_length=100)
    email = forms.EmailField()

# In a view
form = UserForm(request.POST)
if not form.is_valid():
    # Handle invalid form
```

#### 9. Utilize Security Headers

Add security headers like `Content-Security-Policy` (CSP) and `X-Content-Type-Options` to reduce the risk of HPP and related attacks.

**Code Snippet**:
```python
from flask import make_response

@app.after_request
def apply_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Content-Type-Options'] = "nosniff"
    return response
```

#### 10. Employ Web Application Firewalls (WAFs)

Use a WAF to filter out and block suspicious or polluted requests based on defined patterns and known attack signatures.

**Example** (Nginx configuration for blocking duplicate parameters):
```nginx
location / {
    if ($arg_user) {
        set $user_dup 1;
    }
    if ($user_dup) {
        return 403;
    }
    proxy_pass http://backend;
}
```

#### 11. Monitor and Log Requests

Implement logging to track abnormal or suspicious request patterns, enabling detection of repeated parameters or malicious activity.

**Code Snippet**:
```python
import logging

logging.basicConfig(level=logging.INFO)

@app.before_request
def log_request():
    if len(request.args) > len(set(request.args.keys())):
        logging.warning("Potential HPP detected: %s", request.args)
```

#### 12. Implement Parameter Hashing

Consider hashing sensitive parameters and verify the hashes on the server side to prevent tampering.

**Code Snippet**:
```python
import hashlib

def hash_parameter(value):
    return hashlib.sha256(value.encode()).hexdigest()

# On server side, verify hashed parameters
def verify_hash(value, hash):
    return hash_parameter(value) == hash
```

#### 13. Enable SameSite Cookies for Session Management

Set cookies to `SameSite=strict` to reduce CSRF and HPP risks, restricting cookies to same-origin requests.

**Code Snippet**:
```python
from flask import make_response

@app.route('/set_cookie')
def set_cookie():
    resp = make_response("Setting cookie")
    resp.set_cookie("session_id", "value", samesite="Strict")
    return resp
```

---

By implementing these countermeasures, you can significantly reduce the risk of HTTP Parameter Pollution attacks in your application. Ensure to test the application with tools like OWASP ZAP or Burp Suite to identify and mitigate parameter pollution issues proactively.
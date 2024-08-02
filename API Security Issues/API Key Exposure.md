### API Key Exposure

**Description:**
API Key Exposure occurs when an API key, which is a credential used to authenticate requests to an API, is inadvertently exposed. This can happen due to improper handling of keys, such as including them in source code repositories, error messages, or publicly accessible areas. Malicious actors can exploit exposed API keys to gain unauthorized access to services, perform malicious actions, or extract sensitive data.

### How Malicious Actors Exploit API Key Exposure

1. **Finding Exposed Keys:**
   - **Source Code Repositories:** Malicious actors often search for exposed API keys in public or private code repositories. Tools like GitHub’s search functionality or automated scanners can identify keys in code.
   - **Error Messages:** Sometimes, API keys are exposed in error messages or logs. Attackers may monitor logs or error responses to find keys.
   - **Browser Developer Tools:** API keys can be visible in network requests made by web applications, which can be viewed using browser developer tools.

2. **Exploitation:**
   - **Unauthorized Access:** Using the exposed key, attackers can make API requests and access data or services that the key grants permission to.
   - **Data Theft or Modification:** Attackers can retrieve, modify, or delete data, depending on the permissions associated with the key.
   - **Service Disruption:** Attackers can use the API key to perform actions that disrupt services or impact performance.

### Countermeasures and Code Snippets

#### 1. **Use Environment Variables for API Keys**

**Description:**
Store API keys in environment variables instead of hardcoding them into source code. This keeps keys out of version control systems and codebases.

**Example Code:**
```python
import os

api_key = os.getenv('API_KEY')

# Use the api_key in your application
```

**Setting Environment Variables (Linux/Mac):**
```bash
export API_KEY='your_api_key_here'
```

**Setting Environment Variables (Windows):**
```cmd
set API_KEY=your_api_key_here
```

#### 2. **Rotate API Keys Regularly**

**Description:**
Regularly rotate API keys to minimize the risk of exposure. Ensure that old keys are invalidated when new ones are issued.

**Example Code:**
```python
def rotate_api_key():
    # API call to rotate key
    response = requests.post('https://api.example.com/rotate-key', headers={'Authorization': 'Bearer ' + old_api_key})
    new_api_key = response.json().get('new_api_key')
    return new_api_key
```

#### 3. **Restrict API Key Usage**

**Description:**
Limit the usage of API keys to specific IP addresses, endpoints, or services to reduce the impact of exposure.

**Example Code:**
```bash
# Configure API key restrictions in your API gateway or management console
# Example in AWS API Gateway:
# - Restrict usage to specific IP addresses or referrer URLs
```

#### 4. **Use Secure Storage Solutions**

**Description:**
Store API keys in secure storage solutions such as cloud key management services or encrypted storage.

**Example Code:**
```python
from cryptography.fernet import Fernet

# Generate and store a key securely
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Encrypt API key
encrypted_api_key = cipher_suite.encrypt(b"your_api_key_here")

# Decrypt API key
decrypted_api_key = cipher_suite.decrypt(encrypted_api_key).decode()
```

#### 5. **Implement API Key Access Controls**

**Description:**
Implement access controls to manage who and what can access your API keys. Ensure that only authorized applications and users can access them.

**Example Code:**
```python
# Implement access control in a web application
from flask import request, abort

def check_access():
    if not request.headers.get('API-Key') in authorized_keys:
        abort(403)  # Forbidden

# Usage in a route
@app.route('/data')
def data_endpoint():
    check_access()
    # Process the request
```

#### 6. **Monitor API Key Usage**

**Description:**
Monitor API key usage for unusual patterns or anomalies that might indicate abuse or unauthorized access.

**Example Code:**
```python
def log_api_usage(api_key, endpoint):
    # Log API key usage to a monitoring system
    logging.info(f"API key {api_key} accessed {endpoint}")
```

#### 7. **Set Up Alerts for Abnormal Activities**

**Description:**
Set up alerts to notify administrators of suspicious or abnormal API key usage.

**Example Code:**
```python
import smtplib
from email.mime.text import MIMEText

def send_alert(email_address, message):
    msg = MIMEText(message)
    msg['Subject'] = 'API Key Usage Alert'
    msg['From'] = 'alert@example.com'
    msg['To'] = email_address

    with smtplib.SMTP('smtp.example.com') as server:
        server.send_message(msg)
```

#### 8. **Use API Gateway Rate Limiting**

**Description:**
Implement rate limiting at the API gateway level to restrict the number of requests made with a given API key.

**Example Code:**
```yaml
# Example configuration for rate limiting in an API gateway
rateLimit:
  - path: /api/*
    limit: 1000 requests per hour
```

#### 9. **Enable Two-Factor Authentication for API Access**

**Description:**
Use two-factor authentication (2FA) for accessing and managing API keys to add an additional layer of security.

**Example Code:**
```python
# Example of using 2FA in a web application
@app.route('/api/keys', methods=['POST'])
def manage_keys():
    if not verify_2fa(request.headers.get('2FA-Token')):
        abort(403)  # Forbidden
    # Manage API keys
```

#### 10. **Encrypt API Keys in Transit and at Rest**

**Description:**
Ensure that API keys are encrypted during transmission and when stored to prevent unauthorized access.

**Example Code:**
```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encrypt_api_key(api_key):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_api_key = encryptor.update(api_key) + encryptor.finalize()
    return encrypted_api_key

def decrypt_api_key(encrypted_api_key):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted_api_key = decryptor.update(encrypted_api_key) + decryptor.finalize()
    return decrypted_api_key
```

#### 11. **Implement API Key Expiration**

**Description:**
Set expiration dates for API keys so that they become invalid after a certain period, reducing the risk of long-term abuse.

**Example Code:**
```python
from datetime import datetime, timedelta

def generate_expiring_api_key():
    expiration_date = datetime.now() + timedelta(days=30)
    api_key = secrets.token_urlsafe(32)
    return api_key, expiration_date

def validate_api_key(api_key, expiration_date):
    if datetime.now() > expiration_date:
        raise ValueError("API key has expired")
```

#### 12. **Regularly Review and Audit API Keys**

**Description:**
Regularly review and audit API keys to ensure they are being used appropriately and to identify any that may need to be revoked.

**Example Code:**
```python
def review_api_keys(api_keys):
    for key, usage in api_keys.items():
        if usage == 'suspicious':
            revoke_api_key(key)

def revoke_api_key(api_key):
    # Revoke the API key
    pass
```

These countermeasures provide a robust approach to handling API key exposure and ensuring that your API keys are protected from unauthorized access. Implementing these practices helps secure your API infrastructure and mitigates the risks associated with key exposure.

### **Clickjacking: An Overview**

**What is Clickjacking?**
Clickjacking, also known as a "UI redress attack," is a malicious technique used by attackers to trick users into clicking on something different from what they perceive, often leading to unintended actions like changing security settings, making unauthorized transactions, or revealing sensitive information. The attacker typically embeds a legitimate webpage within an invisible or partially visible iframe and overlays it with deceptive content, tricking the user into clicking on the hidden elements.

### **How Clickjacking is Done by Malicious Actors**

1. **Embedding the Target Page:**
   - The attacker creates a webpage and embeds the target page (e.g., a banking website or a social media profile) within an iframe. The iframe is often set to be invisible or barely visible.

   **Example Code (Embedding Target Page in an Iframe):**
   ```html
   <iframe src="https://example-bank.com/transfer-funds" style="opacity: 0; position: absolute; top: 0; left: 0; width: 100%; height: 100%;"></iframe>
   ```

2. **Overlaying with Deceptive Content:**
   - The attacker then overlays the iframe with content that deceives the user into clicking a specific area. For example, a fake "Play" button may be placed over the "Confirm Transfer" button on the embedded banking page.

   **Example Code (Overlaying Deceptive Content):**
   ```html
   <button style="position: absolute; top: 50px; left: 50px;">Play Video</button>
   ```

3. **Triggering the Click:**
   - When the user tries to interact with the visible content (e.g., clicking the "Play" button), they inadvertently interact with the hidden iframe's elements, such as confirming a bank transfer or liking a social media post.

### **Countermeasures Against Clickjacking**

Here are more than ten countermeasures to protect your web application from Clickjacking attacks:

1. **X-Frame-Options Header:**
   - This HTTP header controls whether a browser should be allowed to render a page in an iframe. Setting it to `DENY` or `SAMEORIGIN` can prevent your page from being embedded in iframes on other domains.

   **Example Code (Setting X-Frame-Options Header):**
   ```http
   X-Frame-Options: DENY
   ```
   ```http
   X-Frame-Options: SAMEORIGIN
   ```

2. **Content Security Policy (CSP) Frame-Ancestors Directive:**
   - CSP's `frame-ancestors` directive provides fine-grained control over which domains are allowed to embed your content in an iframe. Unlike `X-Frame-Options`, CSP supports multiple domains.

   **Example Code (Setting CSP Header with Frame-Ancestors):**
   ```http
   Content-Security-Policy: frame-ancestors 'self' https://trusted-site.com;
   ```

3. **JavaScript Frame-Busting Techniques:**
   - Implement JavaScript checks to determine if your page is loaded within an iframe. If so, the script can prevent rendering by redirecting the page or breaking out of the frame.

   **Example Code (JavaScript Frame-Busting):**
   ```javascript
   if (window.top !== window.self) {
       window.top.location = window.self.location;
   }
   ```

4. **Frame-Busting with CSS:**
   - Although not as effective as headers, you can use CSS to prevent your content from being displayed if embedded in an iframe.

   **Example Code (CSS Frame-Busting):**
   ```css
   body {
       display: none !important;
   }
   ```

5. **User Interaction Confirmation:**
   - For sensitive actions (e.g., submitting a form), require explicit user confirmation (e.g., a CAPTCHA or a confirmation dialog) to ensure the user’s intent.

   **Example Code (JavaScript Confirmation Dialog):**
   ```javascript
   document.querySelector('form').addEventListener('submit', function(event) {
       if (!confirm('Are you sure you want to proceed?')) {
           event.preventDefault();
       }
   });
   ```

6. **Double-Click Protection:**
   - Require users to click twice on critical buttons (e.g., the first click makes the button active, and the second click performs the action). This technique mitigates the risk of clickjacking by ensuring user intent.

   **Example Code (Double-Click Protection):**
   ```javascript
   let clickCount = 0;
   document.querySelector('#secure-button').addEventListener('click', function(event) {
       if (clickCount === 0) {
           event.preventDefault();
           clickCount++;
           this.innerText = 'Click again to confirm';
       } else {
           // Proceed with the action
       }
   });
   ```

7. **UI Integrity Checks:**
   - Perform checks to ensure that the UI is rendered correctly, and critical elements (e.g., buttons) are visible and not obstructed by other elements.

   **Example Code (Checking Element Visibility):**
   ```javascript
   function isElementVisible(element) {
       const rect = element.getBoundingClientRect();
       return rect.top >= 0 && rect.left >= 0 &&
              rect.bottom <= (window.innerHeight || document.documentElement.clientHeight) &&
              rect.right <= (window.innerWidth || document.documentElement.clientWidth);
   }

   if (!isElementVisible(document.querySelector('#secure-button'))) {
       alert('UI integrity compromised!');
   }
   ```

8. **Audit Logs for Clickjacking Detection:**
   - Maintain audit logs for critical actions. If you detect unusual patterns (e.g., a spike in specific actions), it could indicate a clickjacking attempt.

   **Example Code (Logging Suspicious Activity):**
   ```python
   def log_action(action, user):
       with open('audit_log.txt', 'a') as log:
           log.write(f'{datetime.now()} - {user}: {action}\n')

   log_action('Attempted critical action', 'user123')
   ```

9. **Limiting iFrame Interaction with Cross-Origin Isolation:**
   - Use cross-origin isolation to ensure that only trusted origins can interact with your iframe. This technique can be combined with `COOP` (Cross-Origin Opener Policy) and `COEP` (Cross-Origin Embedder Policy).

   **Example Code (COOP and COEP Headers):**
   ```http
   Cross-Origin-Opener-Policy: same-origin
   Cross-Origin-Embedder-Policy: require-corp
   ```

10. **Restrict Embedding on Specific Pages:**
    - Some pages (e.g., login pages, transaction pages) should never be embedded in an iframe. Implement restrictions specifically for these pages.

    **Example Code (Conditional Frame-Busting for Specific Pages):**
    ```javascript
    if (window.location.pathname === '/login' && window.top !== window.self) {
        window.top.location = window.self.location;
    }
    ```

11. **Using Anti-Clickjacking Widgets:**
    - Implement anti-clickjacking widgets that require direct user interaction, such as dragging a slider or solving a CAPTCHA.

    **Example Code (Simple Drag Slider for Verification):**
    ```html
    <input type="range" min="0" max="100" value="0" id="slider">
    <button id="confirm-button" disabled>Confirm</button>

    <script>
    document.getElementById('slider').addEventListener('input', function() {
        if (this.value === '100') {
            document.getElementById('confirm-button').disabled = false;
        }
    });
    </script>
    ```

12. **Use Visual Feedback:**
    - Provide immediate visual feedback for clicks, such as highlighting buttons or showing loading indicators. This feedback can help users recognize if they clicked something unintentionally.

    **Example Code (Visual Feedback for Button Clicks):**
    ```javascript
    document.querySelector('button').addEventListener('click', function() {
        this.style.backgroundColor = 'green';
        this.innerText = 'Processing...';
    });
    ```

### **Summary**

Clickjacking is a sophisticated attack that leverages user trust and deception to perform unintended actions. To counter it effectively, a multi-layered approach should be adopted, combining HTTP headers, JavaScript techniques, user interaction validation, and security policies like CSP. Each of these countermeasures can be tailored to the specific needs of your application, ensuring robust protection against clickjacking attacks. Implementing these countermeasures will enhance the security posture of your web application and provide a safer experience for your users.

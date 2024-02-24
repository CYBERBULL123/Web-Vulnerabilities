
### Cross-Site Scripting (XSS):

**Description:**
XSS involves injecting malicious scripts into web pages that are then executed by other users' browsers, usually through user input.

**Countermeasures:**
1. Input Validation and Output Encoding:
   - Validate and sanitize user input.
   - Encode output to ensure any user-generated content is treated as data, not executable code.
   - **Example Code:**
     ```python
     def sanitize_input(input_data):
         # Implement input validation and sanitization based on requirements
         return sanitized_data

     def display_user_data(user_data):
         # Encode user-generated content before displaying it
         encoded_data = html.escape(user_data)
         return encoded_data
     ```

2. Content Security Policy (CSP):
   - Implement CSP headers to control the sources from which certain types of content can be loaded.
   - **Example Code (HTTP header):**
     ```
     Content-Security-Policy: default-src 'self';
     ```



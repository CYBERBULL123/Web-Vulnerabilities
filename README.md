# Web-Vulnerabilities

### Injection Vulnerabilities:

1. **SQL Injection (SQLi):**
   - **Description:** SQL Injection is an attack technique where malicious SQL code is inserted into input fields, manipulating the database queries to gain unauthorized access or retrieve sensitive information.
   - **Uses:** Attackers can extract, modify, or delete database records. It can lead to data breaches and compromise the integrity of the application.

2. **Cross-Site Scripting (XSS):**
   - **Description:** XSS involves injecting malicious scripts into web pages that are then executed by other users' browsers. It occurs when a web application does not properly validate or sanitize user inputs.
   - **Uses:** Attackers can steal user cookies, session tokens, or other sensitive information, deface websites, or perform phishing attacks.

3. **Cross-Site Request Forgery (CSRF):**
   - **Description:** CSRF exploits the trust that a website has in a user's browser by making unauthorized requests on behalf of the user without their knowledge.
   - **Uses:** Attackers can perform actions on behalf of the victim, such as changing account settings, initiating transactions, or even performing actions with elevated privileges.

4. **Remote Code Execution (RCE):**
   - **Description:** RCE allows an attacker to execute arbitrary code on a remote server, often gaining full control over the system.
   - **Uses:** Attackers can upload and execute malicious scripts, install backdoors, and compromise the entire server.

5. **Command Injection:**
   - **Description:** Command injection occurs when an application allows an attacker to execute operating system commands.
   - **Uses:** Attackers can run malicious commands, potentially leading to unauthorized access, data theft, or disruption of services.

6. **XML Injection:**
   - **Description:** XML Injection involves injecting malicious content into XML data, leading to unexpected behavior in the parsing process.
   - **Uses:** Attackers can manipulate XML data, potentially causing application errors, disclosure of sensitive information, or even remote code execution.

7. **LDAP Injection:**
   - **Description:** LDAP Injection occurs when untrusted data is inserted into LDAP queries, manipulating the queries and potentially allowing unauthorized access.
   - **Uses:** Attackers can extract, modify, or delete LDAP data, leading to unauthorized access and data exposure.

8. **XPath Injection:**
   - **Description:** XPath Injection is similar to SQL Injection but involves manipulating XPath queries used for XML data retrieval.
   - **Uses:** Attackers can modify XPath queries, leading to unauthorized access or disclosure of sensitive information.

9. **HTML Injection:**
   - **Description:** HTML Injection involves injecting malicious HTML code into web pages.
   - **Uses:** Attackers can perform phishing attacks, deface websites, or execute scripts in the context of other users.

10. **Server-Side Includes (SSI) Injection:**
    - **Description:** SSI Injection occurs when an attacker can manipulate Server-Side Include directives.
    - **Uses:** Attackers can execute arbitrary commands on the server, potentially leading to unauthorized access or data manipulation.

11. **OS Command Injection:**
    - **Description:** Similar to Command Injection, OS Command Injection involves executing operating system commands, exploiting vulnerabilities in command execution.
    - **Uses:** Attackers can run malicious commands, potentially leading to unauthorized access, data theft, or disruption of services.

12. **Blind SQL Injection:**
    - **Description:** Blind SQL Injection occurs when an application is vulnerable, but the results of the injection are not directly visible to the attacker.
    - **Uses:** Attackers use techniques to infer information, such as Boolean-based or time-based blind SQL injection, to extract data.

13. **Server-Side Template Injection (SSTI):**
    - **Description:** SSTI occurs when user input is injected into templates processed on the server, leading to the execution of arbitrary code.
    - **Uses:** Attackers can manipulate templates to execute code, potentially gaining unauthorized access or compromising the server.

### Broken Authentication and Session Management:

14. **Session Fixation:**
    - **Description:** Session Fixation is an attack where an attacker sets the session identifier of a user, leading to potential unauthorized access.
    - **Uses:** Attackers can force users to use a session they control, enabling them to impersonate the victim.

15. **Brute Force Attack:**
    - **Description:** Brute Force Attack involves systematically trying all possible combinations of usernames and passwords until the correct one is found.
    - **Uses:** Attackers can gain unauthorized access to accounts by trying multiple password combinations.

16. **Session Hijacking:**
    - **Description:** Session Hijacking occurs when an attacker intercepts or steals a user's session token.
    - **Uses:** Attackers can impersonate the victim, gaining unauthorized access to their account.

17. **Password Cracking:**
    - **Description:** Password Cracking involves using various techniques to discover a user's password.
    - **Uses:** Attackers can gain unauthorized access to accounts by decrypting or discovering the user's password.

18. **Weak Password Storage:**
    - **Description:** Weak Password Storage occurs when passwords are stored in an insecure manner, such as plain text or with weak encryption.
    - **Uses:** Attackers can easily retrieve and use stored passwords.

19. **Insecure Authentication:**
    - **Description:** Insecure Authentication happens when authentication mechanisms are not robust, allowing attackers to bypass authentication.
    - **Uses:** Attackers can gain unauthorized access by exploiting vulnerabilities in the authentication process.

20. **Cookie Theft:**
    - **Description:** Cookie Theft involves stealing session cookies, giving attackers unauthorized access to a user's session.
    - **Uses:** Attackers can impersonate the victim, gaining access to sensitive information or performing actions on their behalf.

21. **Credential Reuse:**
    - **Description:** Credential Reuse occurs when users employ the same usernames and passwords across multiple platforms.
    - **Uses:** Attackers can use leaked credentials from one platform to gain unauthorized access to other accounts.

### Sensitive Data Exposure:

22. **Inadequate Encryption:**
    - **Description:** Inadequate Encryption involves using weak or insufficient encryption methods for sensitive data.
    - **Uses:** Attackers can intercept and decrypt sensitive information, leading to data exposure.

23. **Insecure Direct Object References (IDOR):**
    - **Description:** IDOR occurs when an attacker can access objects or data they are not authorized to retrieve.
    - **Uses:** Attackers can access or manipulate sensitive data by exploiting flaws in authorization mechanisms.

24. **Data Leakage:**
    - **Description:** Data Leakage involves the unauthorized disclosure of sensitive information.
    - **Uses:** Attackers can gain access to and leak sensitive data, potentially leading to reputational damage or legal consequences.

25. **Unencrypted Data Storage:**
    - **Description:** Unencrypted Data Storage occurs when sensitive data is stored without proper encryption.
    - **Uses:** Attackers can access and read stored data, leading to unauthorized disclosure.

26. **Missing Security Headers:**
    - **Description:** Missing Security Headers involves the absence of HTTP security headers that provide additional protection.
    - **Uses:** Attackers can exploit the absence of security headers to perform various attacks, such as clickjacking or XSS.

27. **Insecure

 File Handling:**
    - **Description:** Insecure File Handling occurs when applications do not properly validate or secure file uploads and downloads.
    - **Uses:** Attackers can upload malicious files, leading to remote code execution or unauthorized access to sensitive files.

### Security Misconfiguration:

28. **Default Passwords:**
    - **Description:** Default Passwords are often set by manufacturers or developers and are unchanged in deployed systems.
    - **Uses:** Attackers can easily gain unauthorized access by exploiting unchanged default passwords.

29. **Directory Listing:**
    - **Description:** Directory Listing occurs when the contents of a directory are exposed, allowing attackers to navigate and access files.
    - **Uses:** Attackers can discover and access sensitive files, potentially leading to data exposure.

30. **Unprotected API Endpoints:**
    - **Description:** Unprotected API Endpoints allow unauthorized access to application functionalities.
    - **Uses:** Attackers can abuse unprotected APIs to retrieve sensitive data or perform actions without proper authentication.

31. **Open Ports and Services:**
    - **Description:** Open Ports and Services can expose unnecessary network services, increasing the attack surface.
    - **Uses:** Attackers can exploit vulnerabilities in open ports or services to gain unauthorized access.

32. **Improper Access Controls:**
    - **Description:** Improper Access Controls occur when users can access functionalities or data they should not be allowed to.
    - **Uses:** Attackers can exploit flaws in access controls to gain unauthorized access to sensitive information or perform unauthorized actions.

33. **Information Disclosure:**
    - **Description:** Information Disclosure occurs when an application reveals sensitive information to unauthorized users.
    - **Uses:** Attackers can gather information to aid in further attacks or exploit disclosed information.

34. **Unpatched Software:**
    - **Description:** Unpatched Software refers to running outdated software versions with known vulnerabilities.
    - **Uses:** Attackers can exploit known vulnerabilities to gain unauthorized access or disrupt services.

35. **Misconfigured CORS:**
    - **Description:** Misconfigured Cross-Origin Resource Sharing (CORS) settings can lead to unauthorized access to resources.
    - **Uses:** Attackers can perform cross-origin requests and access sensitive data from other domains.

36. **HTTP Security Headers Misconfiguration:**
    - **Description:** Misconfiguring HTTP Security Headers can weaken the security posture of a web application.
    - **Uses:** Attackers can exploit the lack of proper security headers to perform various attacks, such as clickjacking or XSS.

### XML-Related Vulnerabilities:

37. **XML External Entity (XXE) Injection:**
    - **Description:** XXE Injection allows attackers to include external entities in XML documents, potentially leading to disclosure of internal files or denial of service.
    - **Uses:** Attackers can read sensitive files, perform denial of service attacks, or execute arbitrary code.

38. **XML Entity Expansion (XEE):**
    - **Description:** XEE involves expanding entities in XML documents to consume excessive resources, leading to a denial of service.
    - **Uses:** Attackers can exhaust system resources by expanding entities, causing the application to become unresponsive.

39. **XML Bomb:**
    - **Description:** An XML Bomb is a malicious XML file designed to overwhelm parsers and consume large amounts of resources.
    - **Uses:** Attackers can use XML Bombs to perform denial of service attacks, causing system or application instability.

### Broken Access Control:

40. **Inadequate Authorization:**
    - **Description:** Inadequate Authorization occurs when an application does not properly restrict access to certain functionalities or resources.
    - **Uses:** Attackers can gain unauthorized access to sensitive data or perform actions they are not allowed to.

41. **Privilege Escalation:**
    - **Description:** Privilege Escalation involves gaining higher levels of access than initially granted.
    - **Uses:** Attackers can elevate their privileges, gaining access to sensitive functionalities or data.

42. **Insecure Direct Object References:**
    - **Description:** Insecure Direct Object References (IDOR) allow attackers to access or manipulate objects they are not authorized to.
    - **Uses:** Attackers can exploit IDOR to gain unauthorized access to sensitive data or perform unauthorized actions.

43. **Forceful Browsing:**
    - **Description:** Forceful Browsing involves accessing unauthorized parts of an application by guessing or manipulating URLs.
    - **Uses:** Attackers can access sensitive pages or functionalities by bypassing insufficient access controls.

44. **Missing Function-Level Access Control:**
    - **Description:** Missing Function-Level Access Control occurs when access controls are not consistently enforced across different functions.
    - **Uses:** Attackers can exploit the inconsistency to gain unauthorized access to restricted functionalities.

### Insecure Deserialization:

45. **Remote Code Execution via Deserialization:**
    - **Description:** Insecure Deserialization allows attackers to execute arbitrary code by manipulating serialized data.
    - **Uses:** Attackers can execute malicious code, potentially gaining unauthorized access or causing system compromise.

46. **Data Tampering:**
    - **Description:** Data Tampering involves modifying serialized data to manipulate application behavior.
    - **Uses:** Attackers can alter serialized data to change the functionality or gain unauthorized access.

47. **Object Injection:**
    - **Description:** Object Injection occurs when untrusted data is used to instantiate objects, potentially leading to unauthorized code execution.
    - **Uses:** Attackers can manipulate object instantiation, leading to the execution of arbitrary code.

### API Security Issues:

48. **Insecure API Endpoints:**
    - **Description:** Insecure API Endpoints lack proper authentication, authorization, or input validation.
    - **Uses:** Attackers can abuse vulnerabilities in API endpoints to access sensitive data or perform unauthorized actions.

49. **API Key Exposure:**
    - **Description:** API Key Exposure occurs when API keys are leaked or improperly secured.
    - **Uses:** Attackers can use exposed API keys to make unauthorized API requests, potentially gaining access to sensitive data or functionalities.

50. **Lack of Rate Limiting:**
    - **Description:** Lack of Rate Limiting allows attackers to perform brute force or denial of service attacks by making a high volume of requests.
    - **Uses:** Attackers can abuse the absence of rate limiting to perform automated attacks, such as brute force or scraping.

51. **Inadequate Input Validation:**
    - **Description:** Inadequate Input Validation occurs when input from API requests is not properly validated.
    - **Uses:** Attackers can exploit input validation flaws to inject malicious data, potentially leading to various attacks.

### Insecure Communication:

52. **Man-in-the-Middle (MITM) Attack:**
    - **Description:** MITM Attacks involve intercepting and manipulating communication between two parties.
    - **Uses:** Attackers can eavesdrop on communication, modify data, or impersonate one of the parties.

53. **Insufficient Transport Layer Security:**
    - **Description:** Insufficient TLS involves weak or misconfigured encryption protocols.
    - **Uses:** Attackers can intercept or manipulate data transmitted over insecure connections.

54. **Insecure SSL/TLS Configuration:**
    - **Description:** Insecure SSL/TLS Configuration involves using weak cipher suites or outdated protocols.
    - **Uses:** Attackers can exploit vulnerabilities in SSL/TLS to perform attacks, such as POODLE or BEAST.

55. **Insecure Communication Protocols:**
   

 - **Description:** Insecure Communication Protocols involve using outdated or insecure communication protocols.
    - **Uses:** Attackers can exploit vulnerabilities in outdated protocols, potentially leading to unauthorized access or data exposure.

### Client-Side Vulnerabilities:

56. **DOM-based XSS:**
    - **Description:** DOM-based XSS occurs when client-side scripts manipulate the Document Object Model (DOM) based on untrusted input.
    - **Uses:** Attackers can inject malicious scripts, potentially leading to the theft of sensitive information or session hijacking.

57. **Insecure Cross-Origin Communication:**
    - **Description:** Insecure Cross-Origin Communication involves vulnerabilities in cross-origin communication mechanisms.
    - **Uses:** Attackers can exploit these vulnerabilities to perform various attacks, such as data theft or injection.

58. **Browser Cache Poisoning:**
    - **Description:** Browser Cache Poisoning occurs when an attacker manipulates the contents of a user's cache.
    - **Uses:** Attackers can inject malicious content into the cache, leading to the execution of malicious scripts or unauthorized access.

59. **Clickjacking:**
    - **Description:** Clickjacking involves tricking users into clicking on a disguised element, leading them to perform unintended actions.
    - **Uses:** Attackers can trick users into clicking on malicious elements, potentially leading to unauthorized actions or disclosure of sensitive information.

60. **HTML5 Security Issues:**
    - **Description:** HTML5 Security Issues involve vulnerabilities specific to the HTML5 standard.
    - **Uses:** Attackers can exploit these vulnerabilities to perform various attacks, such as XSS or data theft.

### Denial of Service (DoS):

61. **Distributed Denial of Service (DDoS):**
    - **Description:** DDoS involves overwhelming a system, service, or network with a flood of traffic from multiple sources.
    - **Uses:** Attackers can disrupt services, causing downtime or making them unavailable to legitimate users.

62. **Application Layer DoS:**
    - **Description:** Application Layer DoS attacks target specific applications, exploiting vulnerabilities to overwhelm them.
    - **Uses:** Attackers can exhaust application resources, leading to slowdowns or unresponsiveness.

63. **Resource Exhaustion:**
    - **Description:** Resource Exhaustion involves depleting system resources to disrupt normal operation.
    - **Uses:** Attackers can exhaust CPU, memory, or other resources, causing performance degradation or system failure.

64. **Slowloris Attack:**
    - **Description:** Slowloris is a type of DoS attack where the attacker keeps multiple connections open to the target, exhausting resources.
    - **Uses:** Attackers can keep connections open, preventing the server from serving legitimate requests.

65. **XML Denial of Service:**
    - **Description:** XML Denial of Service involves exploiting vulnerabilities in XML parsers to cause resource exhaustion.
    - **Uses:** Attackers can craft XML payloads that, when processed, consume excessive resources, leading to denial of service.

### Other Web Vulnerabilities:

66. **Server-Side Request Forgery (SSRF):**
    - **Description:** SSRF occurs when an attacker can make requests to internal resources from the server.
    - **Uses:** Attackers can access internal resources, potentially leading to unauthorized data retrieval or remote code execution.

67. **HTTP Parameter Pollution (HPP):**
    - **Description:** HPP occurs when an attacker manipulates or pollutes parameters to confuse or compromise an application's behavior.
    - **Uses:** Attackers can manipulate parameter values, potentially leading to unauthorized access or injection attacks.

68. **Insecure Redirects and Forwards:**
    - **Description:** Insecure Redirects and Forwards allow attackers to redirect users to malicious websites or perform other unauthorized actions.
    - **Uses:** Attackers can trick users into visiting malicious sites or initiate unauthorized actions.

69. **File Inclusion Vulnerabilities:**
    - **Description:** File Inclusion Vulnerabilities occur when an application includes files based on user input without proper validation.
    - **Uses:** Attackers can include malicious files, potentially leading to remote code execution or unauthorized access.

70. **Security Header Bypass:**
    - **Description:** Security Header Bypass involves finding ways to circumvent security headers, such as Content Security Policy (CSP).
    - **Uses:** Attackers can bypass security controls, potentially executing malicious scripts or performing other unauthorized actions.

71. **Clickjacking:**
    - **Description:** Clickjacking involves tricking users into clicking on a disguised element, leading them to perform unintended actions.
    - **Uses:** Attackers can trick users into clicking on malicious elements, potentially leading to unauthorized actions or disclosure of sensitive information.

72. **Inadequate Session Timeout:**
    - **Description:** Inadequate Session Timeout occurs when user sessions remain active for an extended period, increasing the risk of unauthorized access.
    - **Uses:** Attackers can exploit long session timeouts to gain unauthorized access to active sessions.

73. **Insufficient Logging and Monitoring:**
    - **Description:** Insufficient Logging and Monitoring occur when an application lacks proper logging and monitoring capabilities.
    - **Uses:** Attackers can perform malicious activities without detection, increasing the risk of successful attacks.

74. **Business Logic Vulnerabilities:**
    - **Description:** Business Logic Vulnerabilities involve flaws in the application's logic that can be exploited for unauthorized actions.
    - **Uses:** Attackers can exploit these flaws to manipulate business processes, potentially leading to financial losses or data breaches.

75. **API Abuse:**
    - **Description:** API Abuse involves using APIs in unintended ways to gain unauthorized access or perform malicious actions.
    - **Uses:** Attackers can abuse APIs to retrieve sensitive data, perform unauthorized actions, or manipulate application behavior.

### Mobile Web Vulnerabilities:

76. **Insecure Data Storage on Mobile Devices:**
    - **Description:** Insecure Data Storage on Mobile Devices occurs when sensitive data is stored without proper encryption or protection.
    - **Uses:** Attackers can access and retrieve sensitive data stored on mobile devices.

77. **Insecure Data Transmission on Mobile Devices:**
    - **Description:** Insecure Data Transmission on Mobile Devices involves transmitting sensitive data without proper encryption.
    - **Uses:** Attackers can intercept and eavesdrop on sensitive data during transmission.

78. **Insecure Mobile API Endpoints:**
    - **Description:** Insecure Mobile API Endpoints lack proper authentication, authorization, or input validation.
    - **Uses:** Attackers can abuse vulnerabilities in mobile APIs to access sensitive data or perform unauthorized actions.

79. **Mobile App Reverse Engineering:**
    - **Description:** Mobile App Reverse Engineering involves analyzing and decompiling mobile applications to understand their code or extract sensitive information.
    - **Uses:** Attackers can reverse engineer mobile apps to discover vulnerabilities, manipulate code, or extract sensitive data.

### IoT Web Vulnerabilities:

80. **Insecure IoT Device Management:**
    - **Description:** Insecure IoT Device Management involves vulnerabilities in the management and control of IoT devices.
    - **Uses:** Attackers can exploit these vulnerabilities to take control of IoT devices, potentially leading to unauthorized access or manipulation.

81. **Weak Authentication on IoT Devices:**
    - **Description:** Weak Authentication on IoT Devices occurs when devices use weak or default credentials.
    - **Uses:** Attackers can easily gain access to IoT devices by exploiting weak or default credentials.

82. **IoT Device Vulnerabilities:**
   

 - **Description:** IoT Device Vulnerabilities refer to weaknesses and flaws in the design or implementation of IoT devices.
    - **Uses:** Attackers can exploit these vulnerabilities to compromise the functionality, security, or privacy of IoT devices.

### Web of Things (WoT) Vulnerabilities:

83. **Unauthorized Access to Smart Homes:**
    - **Description:** Unauthorized Access to Smart Homes occurs when attackers gain unauthorized control over smart home devices.
    - **Uses:** Attackers can manipulate smart home devices, potentially causing physical harm or unauthorized access.

84. **IoT Data Privacy Issues:**
    - **Description:** IoT Data Privacy Issues involve concerns about the privacy and security of data generated by IoT devices.
    - **Uses:** Attackers can exploit data privacy issues to access sensitive information or conduct surveillance.

### Authentication Bypass:

85. **Insecure "Remember Me" Functionality:**
    - **Description:** Insecure "Remember Me" Functionality involves vulnerabilities in the implementation of persistent login sessions.
    - **Uses:** Attackers can exploit flaws to gain unauthorized access to accounts without entering valid credentials.

86. **CAPTCHA Bypass:**
    - **Description:** CAPTCHA Bypass involves techniques to circumvent or defeat CAPTCHA challenges.
    - **Uses:** Attackers can automate processes that require human interaction, potentially leading to unauthorized access or abuse.

### Server-Side Request Forgery (SSRF):

87. **Blind SSRF:**
    - **Description:** Blind SSRF occurs when an application makes requests to internal resources without disclosing the results to the attacker.
    - **Uses:** Attackers can use techniques to infer information, such as time-based blind SSRF, to gather sensitive data.

88. **Time-Based Blind SSRF:**
    - **Description:** Time-Based Blind SSRF involves exploiting delays in responses to infer information about internal resources.
    - **Uses:** Attackers can gather information about internal systems by exploiting delays in SSRF responses.

### Content Spoofing:

89. **MIME Sniffing:**
    - **Description:** MIME Sniffing involves browsers interpreting files differently than intended based on content rather than MIME types.
    - **Uses:** Attackers can manipulate content to force browsers into interpreting files in unintended ways, potentially leading to security vulnerabilities.

90. **X-Content-Type-Options Bypass:**
    - **Description:** X-Content-Type-Options Bypass involves circumventing browser security mechanisms that prevent MIME type sniffing.
    - **Uses:** Attackers can trick browsers into interpreting files differently by bypassing the X-Content-Type-Options header.

91. **Content Security Policy (CSP) Bypass:**
    - **Description:** CSP Bypass involves finding ways to circumvent or disable Content Security Policy settings.
    - **Uses:** Attackers can execute malicious scripts or load unauthorized content by bypassing CSP.

### Business Logic Flaws:

92. **Inconsistent Validation:**
    - **Description:** Inconsistent Validation occurs when validation mechanisms are not consistently applied across different parts of the application.
    - **Uses:** Attackers can exploit inconsistencies to manipulate data or perform unauthorized actions.

93. **Race Conditions:**
    - **Description:** Race Conditions involve timing-dependent vulnerabilities where the outcome depends on the sequence of events.
    - **Uses:** Attackers can exploit timing issues to manipulate processes, potentially leading to unauthorized access or data manipulation.

94. **Order Processing Vulnerabilities:**
    - **Description:** Order Processing Vulnerabilities involve flaws in the processing of orders or transactions.
    - **Uses:** Attackers can exploit vulnerabilities to manipulate orders, potentially leading to financial losses or unauthorized access.

95. **Price Manipulation:**
    - **Description:** Price Manipulation involves vulnerabilities in the pricing mechanisms of an application.
    - **Uses:** Attackers can exploit flaws to manipulate prices, potentially leading to financial losses or fraud.

96. **Account Enumeration:**
    - **Description:** Account Enumeration occurs when attackers can determine valid user accounts through different responses.
    - **Uses:** Attackers can identify valid user accounts, potentially aiding in further attacks, such as brute force or phishing.

97. **User-Based Flaws:**
    - **Description:** User-Based Flaws involve vulnerabilities specific to user-related functionalities.
    - **Uses:** Attackers can exploit flaws in user-related functionalities to gain unauthorized access or manipulate user data.

### Zero-Day Vulnerabilities:

98. **Unknown Vulnerabilities:**
    - **Description:** Unknown Vulnerabilities refer to security flaws that are not yet publicly known or patched.
    - **Uses:** Attackers can exploit unknown vulnerabilities before developers have a chance to release patches.

99. **Unpatched Vulnerabilities:**
    - **Description:** Unpatched Vulnerabilities involve security flaws for which patches are available, but the system remains unpatched.
    - **Uses:** Attackers can exploit known vulnerabilities if systems are not updated with the latest patches.

100. **Day-Zero Exploits:**
    - **Description:** Day-Zero Exploits involve attacks targeting vulnerabilities on the same day they are discovered or disclosed.
    - **Uses:** Attackers can exploit vulnerabilities before security patches or mitigations are available, increasing the risk of successful attacks.

## These descriptions provide an overview of each web vulnerability and its potential uses by attackers. In practice, security measures, such as regular patching, secure coding practices, and thorough testing, are crucial to mitigating these vulnerabilities and enhancing overall web security.

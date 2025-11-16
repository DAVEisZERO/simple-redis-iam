Local storage vs session storage vs cookies https://medium.com/@mschoudhary81/how-to-use-local-storage-session-storage-and-cookies-in-angular-cae07c47a8af https://medium.com/@sehban.alam/best-practices-for-storing-access-tokens-in-angular-0d835c14e72c 


token: opaque token vs JWT token

SEttings and KeyVault storage for credentials (keys, passwords)
    .env 
    Pydantic Settings.


FRONTEND: NPM dependency check, vulnerablity/audit fix


A01:2021 – Broken Access Control:  
    1. Not controlling the accestoken/session token --> delete account - [x]
    2. Role escalation: admin, user - [x]
    3. JWT tampering??? - [ ]

A02:2021 – Cryptographic Failures: 
    1. Hardcoding password/keys in the code  -->  .env & Pydantic Settings. --> front-end - [ ]
    2. Are deprecated hash functions such as MD5 or SHA1 in use, or are non-cryptographic hash functions used when cryptographic hash functions are needed? - [x]
    3. Store password as hashes - [x]
    4. TLS enforcement: Is encryption not enforced, e.g., are any HTTP headers (browser) security directives or headers missing? - [x]

A03:2021 – Injection
    1. User-supplied data is not validated, filtered, or sanitized by the application. - [x]
        a.	Validation (Input): Use Pydantic to strictly define what "valid" input looks like
        b.	Escaping (Output): Rely on Jinja2 or your Frontend framework to escape HTML context.
        
    2. Cross-Site Scripting (XSS)  frontend <script>alert(document.cookie)</script>???

A04:2021 – Insecure Design:
    1.	Storing JWTs/session tokens in LocalStorage --> This is an architectural vulnerability to XSS (Cross-Site Scripting). If any JavaScript on the frontend is compromised, the attacker can read localStorage and steal the identity - [x]
    2.  The Design Choice: To be "user-friendly," you design your login endpoint to return specific errors. --> Better Design: The system should return a generic message for both cases: 401 Invalid Email or Password. - [x]
    3. Rate Limiter: An IAM server is the #1 target for bots. Without a design that creates friction for automation, your server is essentially "open" to brute force. --> "slowapi" library- [x]

A05:2021 – Security Misconfiguration: 
    1. use a Security configuratino for redis --> hardening process - [ ]
    2. CORS & general configurations for fastAPI app --> The Fix: Whitelist only the specific domains of your frontend applications - [ ]
    3. Missing Security Headers: FastAPI does not add security headers (like HSTS or X-Frame-Options) by default. - [ ]
        The Fix: Use a library like "secure" or add middleware.

    4. Debug is False in production. - [ ]
    5. cookie missconfiguration???

A06:2021 – Vulnerable and Outdated Components
    1. dependency versino management (nodeja & python) - [ ]
        tools: "pip-audit" tool maintained by the Python Packaging Authority (PyPA). It scans your environment against known vulnerability databases.
        "Safety" Another popular scanner that checks your requirements.txt against a curated database.
       
    2. Lock Files: requirements.txt or poetry.lock - [ ]
         Pin Your Dependencies -->fastapi==0.95.2 (Locks the version so you know exactly what is running).
         Remove unused dependencies, unnecessary features, components, files, and documentation.
    3. docker redis image - [ ]
    

    4. add vulnerablity scanning hook ???
        Automated Pull Requests (Dependabot / Renovate)
    

A07:2021 – Identification and Authentication Failures: 
    1. Passowrds: Permits default, weak, or well-known passwords, such as "Password1" or "admin/admin". - [x]
    2. authenticate users/email --> PKCE flow https://oauth.net/2/pkce/ -> sign-up with and without authentification (email) - [x]
    3. session token management: aren't properly invalidated during logout or a period of inactivity. invalidated upon logoutb - [ ]

    2. session logging: Exposes session identifier in the URL && Reuse session identifier after successful login.
    2. Client Authnetication, security between IAM and Front-ed https://oauth.net/2/client-authentication/ ???


A08:2021 – Software and Data Integrity Failures: code and infrastructure that does not protect against integrity violations.
    1. Download signed packages from official resources --> hash
        docker image -> redis hash/signature



A09:2021 – Security Logging and Monitoring Failures: help detect, escalate, and respond to active breaches.
    1. Never log secrets: Ensure your logger filters out fields like password, access_token, or refresh_token. --> Use Pydantic SecretStr: In your Pydantic models, use SecretStr for sensitive fields.
    2. Must-Log" IAM Events Checklist --> Authentication, Authorization, Token Management, Admin actions and System (startupt/sthudown)
        # Install: pip install structlog uvicorn[standard]
        import structlog
        import logging
    3. use a logging "middlewwear" (Use structlog for JSON Logs) enhanced formating for future monitoring.
        Correlation ID (Tracing) --> from asgi_correlation_id import CorrelationIdMiddleware

A10:2021 – Server-Side Request Forgery (SSRF) 
    1. example by fetching the letterboxd URL: validated or non validated option - [x]

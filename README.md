# httprecon - Advanced Web Server Fingerprinting

## Introduction

The httprecon project is doing some research in the field of web server fingerprinting, also known as http fingerprinting. The goal is the highly accurate identification of given httpd implementations. This is very important within professional vulnerability analysis.

Besides the discussion of different approaches and the documentation of gathered results also an implementation for automated analysis is provided. This software shall improve the easyness and efficiency of this kind of enumeration. Traditional approaches as like banner-grabbing, status code enumeration and header ordering analysis are used. However, many other analysis techniques were introduced to increase the possibilities of accurate web server fingerprinting. Some of them were already discussed in the book _Die Kunst des Penetration Testing_ (Chapter 9.3, HTTP-Fingerprinting, pp. 530-550).

## Flow

The application works very straight forward. After the user has defined the target service which shall be fingerprinted, a common tcp connection is opened to the destination port. If the connection could be established, the http requests are sent to the target service. This one will shall react with responses. These could be dissected to identify some specific fingerprint elements. Those elements are looked up in the local fingerprint database. If there is a match, the according implementation is flagged as "identified". All these flags were counted so httprecon is able to determine which implementation has the best match rate.

![Flow](http://www.computec.ch/projekte/httprecon/documentation/flow.png)

## Architecture

The following picture illustrates the architecture of the whole framework. The scan engine uses nine different requests which are sent to the target web server. These shall provoke the response which can be used for the fingerprinting. There were different kind of requests used. Some of them are very common and legitimate (e.g. GET / HTTP/1.1) and others are usually not accepted due to their malicious nature (e.g. a very long URI in a GET request).

![Architecture](http://www.computec.ch/projekte/httprecon/documentation/architecture.png)

The dissection of the responses is handled by the parsing and fingerprint engine. As you can see many different fingerprint elements are looked up (e.g. statuscode, banner, Etag length, header-order, etc.). These elements are saved in the local fingerprint database which allows the sum of the matches. All data is correlated which will result in the final fingerprint scan report.

## Features

These are the main features of the current implementation of httprecon which makes this solution better than other tools of this kind:

* Many test-cases: There are nine test-cases possible
* HTTPS/SSL support: Secure web servers can be tested too
* Advanced result analysis: Different methods for the analysis of results is provided
* Many fingerprint details: The analysis is based on many fingerprint elements
* Plaintext Database: The fingerprint data is saved in a file-based plaintext database
* Fingerprint Wizard: Fingerprints can be saved and updated within the GUI
* IDS evasion mechanism: The configuration settings allow to use IDS evasion mechanisms
* Reporting: XML, HTML and TXT reporting is provided for professional testers
* Autoupdate: An autoupdate feature informs about new releases
* Open-source (GPLv3): Everyone can improve the application for themselves

There are differen applications for http fingerprinting available. This Excel sheet is comparing the four most popular HTTP fingerprinting tools (httprecon, httprint, hmap, and WebserverFP).

## Key Analysis Index

Most web server implementations come with a Key Analysis Index (KAI), a very special and dominant behaviour which allows a very quick identification. The following list shall demonstrate the KAI for some popular implementations:

* Apache: Every generation of Apache web servers usually introduces these three values first in an http response header: Date, Server, and X-Powered-By (optional). The length of the ETag values varies between 17 and 34 bytes and they are usually surrounded by double-quotes. It is very typical for an Apache installation to announce PHP/x.x.x within the X-Powered-By line (it is also common for Abyss). It is also common that an Apache web server reacts with the statuscode 403 (Forbidden) if a very long URI was proposed within the request. Usually the supported http methods are announced as: GET, HEAD, POST, OPTIONS, and TRACE.
* Microsoft IIS: The length of the ETag values varies between 18 and 23 bytes. This web server is the only one so far which is announcing ASP.NET within the X-Powered-By line.
* Oracle Application Server: The length of the ETag values varies between 15 and 30 bytes and they are usually surrounded by double-quotes. Usually the supported http methods are announced as: OPTIONS, TRACE, GET, and HEAD. In some cases also an additional line similar to Allow is used and defined as Public.
* Sun One Web Server: The implemenation by Sun Microsystems Inc. usually starts with the values Server, {Date|Content-type}.
* Netscape Enterprise Server: This implementation usually uses these three values within a response header: Server, Date, and Content-type.
* Compaq HTTP Server: Old implementations of the generation 5.x always propose HTTP/1.0 instead of HTTP/1.1 as protocol. A very special behaviour is the statustext "Ok" instead of full capitalized "OK" for a successful processing. They also use uncapitalized letters is a response line uses some dash (e.g. Content-type and Content-length). And the response header always consists of: Date, Server, Content-type, Content-length, and Set-Cookie. A Compaq HTTP Server sends the http statuscode 200 (Ok) even a very long URI was proposed within the request (also common for LANCOM DSL router).
* Zyxel: The embedded web server of Zyxel devices proposes usually the same http response header structure: Content-Type, Date, Pragma, Expires, Transfer-Encoding, Server, and EXT. Very special in this case is the header line EXT.
* 4D WebSTAR: Versions prior 4.x always announce the MIME-Version as first element of the http response header. The version 4.x do not use this value anymore and rely on Server as first element. And in the later releases 5.x the Date announcement moved the Server announcement to the second line. A request for a non-existing ressource returns the statuscode "File Not Found" instead of the more common "Not Found".
* Roxen: The length of the ETag values is always set to 34 bytes and they are usually surrounded by double-quotes.
* OmniHTTPd: Another special behaviour for successful requests is the status text "Document Follows" (similar to TclHttpd) where usually an "OK" is used. The response headers usually contain the values Content-Length, Content-Type, Date and the header is ended by the value Server.
* TclHttpd: Another special behaviour for successful requests is the status text "Data follows" (similar to OmniHTTPd) where usually an "OK" is used.
* Gatling: A very special behaviour for successful requests is the status text "Coming Up" where usually an "OK" is used.
* Squid: Common http get requests always produce the announcement of HTTP/1.0 instead of HTTP/1.1 as protocol.

## Counter-measures

The possibility of fingerprinting is not a vulnerability in a traditional way which allows to compromise a host. It is more a flaw or exposure which may provide the foundation for further enumeration and specific attack scenarios.

![Mutation](http://www.computec.ch/projekte/httprecon/documentation/web_server_mutation.png)

Nevertheless, applying some counter-measures to harden a service is always a good idea. Preventing fingerprinting 100 % is not possible due to the nature of interaction between network software. But there are possibilities to decrease the accuracy of such an analysis. These are illustrated in the diagram and listed below:

### Change or supression of banner

The most accepted and widely known approach to defend against fingerprinting is the manipulation or change of the application banner. Within web responses the line Server announces the name of the given implementation. Some web servers allow the change of this value within a configuration file.

Apache supports downstripping the announcement with the ServerToken directive. Downstripping requires the definition of Prod which would announce "Apache" only (see the ServerSignature directive too). To change this value really some manipulation of the file /src/include/httpd.h within the source-code (AP_SERVER_BASEVENDOR, AP_SERVER_BASEPRODUCT, AP_SERVER_MAJORVERSION_NUMBER, AP_SERVER_MINORVERSION_NUMBER, AP_SERVER_PATCHLEVEL_NUMBER) is required:
```/*
* The below defines the base string of the Server: header. Additional
* tokens can be added via the ap_add_version_component() API call.
*
* The tokens are listed in order of their significance for identifying the
* application.
*
* "Product tokens should be short and to the point -- use of them for 
* advertizing or other non-essential information is explicitly forbidden."
*
* Example: "Apache/1.1.0 MrWidget/0.1-alpha" 
*/
#define AP_SERVER_BASEVENDOR "Apache Software Foundation"
#define AP_SERVER_BASEPROJECT "Apache HTTP Server"
#define AP_SERVER_BASEPRODUCT "Apache"

#define AP_SERVER_MAJORVERSION_NUMBER 2
#define AP_SERVER_MINORVERSION_NUMBER 2
#define AP_SERVER_PATCHLEVEL_NUMBER 6
#define AP_SERVER_DEVBUILD_BOOLEAN 0

#if AP_SERVER_DEVBUILD_BOOLEAN
#define AP_SERVER_ADD_STRING     "-dev"
#else
#define AP_SERVER_ADD_STRING     ""
#endif
```
Microsoft IIS requires some hex hack in the library W3SVC.DLL to change the Server-output. There is a freeware named MS IIS/PWS Banner Edit Tool available which automates this manipulation. IISBanner is a well-known ISAPI filter which can be used to safely remove or disguise the IIS server header by editing the INI file. Microsoft suggests the use of URLscan which introduces the same advantages.

thttpd allows some minor changes within the file config.h which steers some of the settings during compilation (e.g. ERR_APPEND_SERVER_INFO for the announcement of the server name within server generated error pages or the default charset of iso-8859-1 in DEFAULT_CHARSET). Furthermore it is possible to change SHOW_SERVER_VERSION which suppresses the version number announcement in the Server line. To change or suppress the real server name a modification of EXPOSED_SERVER_SOFTWARE within libhttpd.c is required:
```#ifdef SHOW_SERVER_VERSION
#define EXPOSED_SERVER_SOFTWARE SERVER_SOFTWARE
#else /* SHOW_SERVER_VERSION */
#define EXPOSED_SERVER_SOFTWARE "thttpd"
#endif /* SHOW_SERVER_VERSION */
```
The open-source web server fnord does not support any configuration settings or constant mutation within the source code to modify the application behavior easily. The announcement of the web server as FNORD is realized within the separated replies created by buffer_puts() in httpd.c. This includes the application banner, status messages and header order. However, enhanced search and replace modifications might improve the obscurity without touching the architecture of the application. Further improvements as like introduction of new http methods (by default only GET, POST and HEAD are suppoted in version 1.10) require some deeper modifications.

Some modules (e.g. PHP and SSH) announce themselves within the Server line. In most cases this can be prevented with a configuration setting for the according module. For PHP in the file php.ini the value expose_php must be set to Off.

### Change statuscode and statustext

Web servers include implementation dependent statuscodes and statustexts in their responses. Changeing them prevents most of todays web server fingerprinting. Only a few http daemons allow such change of basic behaviour within run-time configuration.

Apache requires some changes within the source code and re-compilation. In /src/include/httpd.h the statuscodes are defined as integer constants:
```/**
* The size of the static array in http_protocol.c for storing
* all of the potential response status-lines (a sparse table).
* A future version should dynamically generate the apr_table_t at startup.
*/
#define RESPONSE_CODES 57

#define HTTP_CONTINUE 100
#define HTTP_SWITCHING_PROTOCOLS 101
#define HTTP_PROCESSING 102
#define HTTP_OK 200
#define HTTP_CREATED 201
#define HTTP_ACCEPTED 202
#define HTTP_NON_AUTHORITATIVE 203
#define HTTP_NO_CONTENT 204
#define HTTP_RESET_CONTENT 205
#define HTTP_PARTIAL_CONTENT 206
#define HTTP_MULTI_STATUS 207
#define HTTP_MULTIPLE_CHOICES 300
#define HTTP_MOVED_PERMANENTLY 301
#define HTTP_MOVED_TEMPORARILY 302
#define HTTP_SEE_OTHER 303
#define HTTP_NOT_MODIFIED 304
#define HTTP_USE_PROXY 305
#define HTTP_TEMPORARY_REDIRECT 307
#define HTTP_BAD_REQUEST 400
#define HTTP_UNAUTHORIZED 401
#define HTTP_PAYMENT_REQUIRED 402
#define HTTP_FORBIDDEN 403
#define HTTP_NOT_FOUND 404
#define HTTP_METHOD_NOT_ALLOWED 405
#define HTTP_NOT_ACCEPTABLE 406
#define HTTP_PROXY_AUTHENTICATION_REQUIRED 407
#define HTTP_REQUEST_TIME_OUT 408
#define HTTP_CONFLICT 409
#define HTTP_GONE 410
#define HTTP_LENGTH_REQUIRED 411
#define HTTP_PRECONDITION_FAILED 412
#define HTTP_REQUEST_ENTITY_TOO_LARGE 413
#define HTTP_REQUEST_URI_TOO_LARGE 414
#define HTTP_UNSUPPORTED_MEDIA_TYPE 415
#define HTTP_RANGE_NOT_SATISFIABLE 416
#define HTTP_EXPECTATION_FAILED 417
#define HTTP_UNPROCESSABLE_ENTITY 422
#define HTTP_LOCKED 423
#define HTTP_FAILED_DEPENDENCY 424
#define HTTP_UPGRADE_REQUIRED 426
#define HTTP_INTERNAL_SERVER_ERROR 500
#define HTTP_NOT_IMPLEMENTED 501
#define HTTP_BAD_GATEWAY 502
#define HTTP_SERVICE_UNAVAILABLE 503
#define HTTP_GATEWAY_TIME_OUT 504
#define HTTP_VERSION_NOT_SUPPORTED 505
#define HTTP_VARIANT_ALSO_VARIES 506
#define HTTP_INSUFFICIENT_STORAGE 507
#define HTTP_NOT_EXTENDED 510
```
And in /src/modules/http/http_protocol.c the statustexts are defined as string constants:
```static const char * status_lines[RESPONSE_CODES] =
#else
static const char * const status_lines[RESPONSE_CODES] =
#endif
{
    "100 Continue",
    "101 Switching Protocols",
    "102 Processing",
#define LEVEL_200 3
    "200 OK",
    "201 Created",
    "202 Accepted",
    "203 Non-Authoritative Information",
    "204 No Content",
    "205 Reset Content",
    "206 Partial Content",
    "207 Multi-Status",
#define LEVEL_300 11
    "300 Multiple Choices",
    "301 Moved Permanently",
    "302 Found",
    "303 See Other",
    "304 Not Modified",
    "305 Use Proxy",
    "306 unused",
    "307 Temporary Redirect",
#define LEVEL_400 19
    "400 Bad Request",
    "401 Authorization Required",
    "402 Payment Required",
    "403 Forbidden",
    "404 Not Found",
    "405 Method Not Allowed",
    "406 Not Acceptable",
    "407 Proxy Authentication Required",
    "408 Request Time-out",
    "409 Conflict",
    "410 Gone",
    "411 Length Required",
    "412 Precondition Failed",
    "413 Request Entity Too Large",
    "414 Request-URI Too Large",
    "415 Unsupported Media Type",
    "416 Requested Range Not Satisfiable",
    "417 Expectation Failed",
    "418 unused",
    "419 unused",
    "420 unused",
    "421 unused",
    "422 Unprocessable Entity",
    "423 Locked",
    "424 Failed Dependency",
/* This is a hack, but it is required for ap_index_of_response
* to work with 426.
*/
    "425 No code",
    "426 Upgrade Required",
#define LEVEL_500 46
    "500 Internal Server Error",
    "501 Method Not Implemented",
    "502 Bad Gateway",
    "503 Service Temporarily Unavailable",
    "504 Gateway Time-out",
    "505 HTTP Version Not Supported",
    "506 Variant Also Negotiates",
    "507 Insufficient Storage",
    "508 unused",
    "509 unused",
    "510 Not Extended"
};
```
An easier way to change the status reaction for specific request types (e.g. unsupported http methods as like DELETE) is the use of re-write rules. Instead of react with the expected error message 405 a less usefull forwarding to a 404 error site is possible. Most web servers support such definitions within .htaccess files. The following example is redirecting the unwanted requests to 403 Forbidden instead to 405 Method Not Allowed if the Apache web server has mod_rewrite enabled:
```RewriteCond %{REQUEST_METHOD} !^(GET|POST)
RewriteRule .* - [F]
```

### Change header-values and order

Some web server fingerprinting tools regard header values and header order. Changeing this within the web server usually requires some deep impact to the source code too. This requires a very high level of understanding the given application. The rate of errors might be very high with such an intrusive change.

In Microsoft IIS new custom header values can be added which changes the overview fingerprint of the header order. Just by adding one new header line (usually web browsers ignore those which start with X, e.g. X-Garbage) the possibilities of successful fingerprints can be reduced. This is possible very easily in the tab HTTP headers in the web site properties. Those can be reached within the context menu of the according web site in the Internet Information Services (IIS) Manager. In some cases it is possible to overwrite some other header values (e.g. the location in 302 moved messages). However, this is not possible for the Server banner itself.

    Add Custom HTTP Header in MS IIS

However, some scripting languages as like PHP allow the web developer to have some influence to the headers with the function header(). For example a new header with the call header("X-Powered-By: ASP.NET 2.0") can be used althought no ASP.NET is used at all. This compromises the fingerprint analysis, especially if it is very static and pattern-based, in any way. In ASP.NET the function Response.AppendHeader() is used for the same purposes.

And in JSP different methods of the response object defined by the javax.servlet.http.HttpServletResponse interface might be used: response.setHeader() to set a header value, response.addHeader() to add a new header value, response.setIntHeader() to set an header with an integer value and response.setDateHeader() to set a header with a date value (e.g. from System.currentTimeMillis()).

The ColdFusion Markup Language (CFML) uses the tag cfheader to define headers and their values. Status codes can be changed with a statement like <cfheader statusCode="299" statusText="Very unusual status code"> and new header lines introduced with a statement like <cfheader name="header_name" value="header_value" charset="charset">.

### Redirect known attack scripts

Another way of defending against fingerprinting utilities is to redirect attack scripts as like httprecon. Within the following .htaccess example the well-known user-agents are detected and redirected to the attackers own computer:
```RewriteCond %{HTTP_USER_AGENT} ^libwww-perl [OR]
RewriteCond %{HTTP_USER_AGENT} ^Nikto [OR]
RewriteCond %{HTTP_USER_AGENT} ^Mozilla/4.75 [OR]
RewriteCond %{HTTP_USER_AGENT} ^httprecon
RewriteRule ^(.*)$ http://%{REMOTE_HOST}:80 [R=301,L]
```
This introduces several advantages. First, the attacker is consuming more of his resources which might slow down the scan approach. Second, most of the attack scripts do not recognize the redirect and think the final destination host - which is the attackers own computer - shall be fingerprinted. Thus, in some cases wrong results might be gathered.

However, this blacklist technique only works as long as the attack scripts are detected properly. If the attacker is going to change the approach and behavior of the scanning software, no further redirection might be possible.

## Trivia and Fun Stuff

During the development of httprecon and the use of the software in professional penetration tests several funny things could be observed:

* Wordpress is using the header "X-nananana: Batcache" (@ChrisJohnRiley) (09/22/2010)
* Just one of the major banks in Switzerland is deleting the Server line entirely. (04/25/2009)
* The host www.ibm.com has a mispelled header line which reads "epKe-Alive" instead of "Keep-Alive". (04/16/2009)
* A popular swiss travel agency defined the Server line as "Game Cube" which is abviously not true. (11/24/2007)

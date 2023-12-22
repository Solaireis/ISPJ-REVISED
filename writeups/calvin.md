## Calvin:

- [Functionality of Web Application](#functionality-of-web-application)
  - [User Profile](#user-profile)
  - [Edit Profile Details (Display Name, Bio, Location, Website)](#edit-profile)
  - [Edit Profile Picture & Banner Picture](#edit-profile-pictures)
  - [Post Uploading](#posting)
  - [Liking, Commenting and Sharing of Posts & Comments](#post-features)
  - [Deletion of Posts & Comments](#post-deletion)
  - [Account Settings (Username, Email)](#account-settings)
  - [Set / Change Password](#password-editing)
  - [Display of posts on home page & profile page](#posts-pagination)
- [Data Security](#data-security)
  - [E2E integrity checks](#e2e-integtity)
  - [XSS mitigations](#xss)
  - [Security Header Middlewares](#security-header)
  - [File Analysis](#file-scan)
  - [URL Analysis](#url-scan)
  - [Storing of Analysis Results](#storage-of-results)
  - [URL Redirect Confirmation](#url-redirect-confirmation)
  - [Post & Comment Pagination](#pagination)
  - [Extra Verification to view settings](#extra-authen)
  - [Blocking of Search Engine Crawlers](#seo)
  - [MongoDB Backup (Configuration)](#backup)
- [Research](#research)

## Functionality Of Web Application

<div id="user-profile"></div>

- User Profile

<img src="/demo/calvin/user_profile.png" alt="user profile" style="width: 70%;">

Gyazo Link: https://gyazo.com/62dca0253271654bb1b99cb933e7c89f


<div id="edit-profile"></div>

- Edit Profile Details (Display Name, Bio, Location, Website)

<img src="/demo/calvin/edit_profile.gif" alt="edit profile" style="width: 70%;">

Gyazo Link: https://gyazo.com/21c399dabbb9f411567d2ff91f4c70f6


<div id="edit-profile-pictures"></div>

- Edit Profile Picture & Banner Picture

<img src="/demo/calvin/edit_profile_pic.gif" alt="edit profile pic" style="width: 70%;">

<img src="/demo/calvin/edit_profile_banner.gif" alt="edit profile banner" style="width: 70%;">

Gyazo Links: https://gyazo.com/0a959af59a675de254c31166617a4367 , https://gyazo.com/42793d4f60e3aaf3940c53f90a4a8bed


<div id="posting"></div>

- Post Uploading

<img src="/demo/calvin/posting.gif" alt="posting" style="width: 70%;">

Gyazo Link: https://gyazo.com/d824284c7bb18169ca64a20bda271a49

<div id="post-features"></div>

- Liking, Commenting and Sharing of Posts & Comments

<img src="/demo/calvin/posts_liking.gif" alt="liking posts" style="width: 70%;">

<img src="/demo/calvin/posts_sharing&commenting.gif" alt="sharing & commenting of posts" style="width: 70%;">

Gyazo Links: https://gyazo.com/3a063774bd1905ad946102e603b9aca1 , https://gyazo.com/4e29633991f22a2ef65d2ff26ef50b35

<div id="post-deletion"></div>

- Deletion of Posts & Comments

<img src="/demo/calvin/posts_deleting.gif" alt="deleting made posts" style="width: 70%;">

<img src="/demo/calvin/comment_deleting.gif" alt="deleting made comments" style="width: 70%;">

Gyazo Links: https://gyazo.com/f18d4b42177d3a0df5389a9d0f7fbea0 , https://gyazo.com/5fdba4a18fa9e736d4120bdf755ac857


<div id="account-settings"></div>

- Account Settings (Username, Email)

<img src="/demo/calvin/account_info.png" alt="account settings" style="width: 70%;">

Gyazo Link: https://gyazo.com/c892e0e9d89051d1ae5174578249e1b5

<div id="password-editing"></div>

- Set / Change Password

<img src="/demo/calvin/set_password.png" alt="set password" style="width: 70%;">

<img src="/demo/calvin/change_password.png" alt="change password" style="width: 70%;">

Gyazo Links: https://gyazo.com/ff9783c11db07db5babf988673d9c9be , https://gyazo.com/13eea76511763579ef9142f9fb1bfdfa

<div id="posts-pagination"></div>

- Display of posts on home page & profile page

<img src="/demo/calvin/posts_pagination.gif" alt="pagination" style="width: 70%;">

Gyazo Link: https://gyazo.com/6326a6fa22a96d6197f84f1939cad924

## Implemented:
### Data Security:

<div id="e2e-integtity"></div>

- E2E integrity checks
  - Implemented to ensure the integrity of content uploaded to the website
  - Uses built-in md5 function in Javascript and CRC32C from SheetJS to calculate hashes client side
  - Uses hashlib module to calculate hashes server side
  - Compared on server side

<img src="/demo/calvin/e2e_integrity.png" alt="integrity check code" style="width: 70%;">

Gyazo Link: https://gyazo.com/59ba4f665f590a780cc74183d2421bff

<div id="xss"></div>

- XSS mitigations
  - Implemented CSP to prevent execution of unwanted scripts and/or Javascript libraries
  - Implemented Content Security Policy Middleware
  - Configured Content Security Policy and the Nonces of embedded scripts

<img src="/demo/calvin/csp.png" alt="Content Security Policy" style="width: 70%;">

Gyazo Link: https://gyazo.com/3f69f80ec64bb2dad1e278a840f1f784

<div id="security-header"></div>

- Security Header Middlewares
   - HSTS Middleware
     - Ensures the usage of HSTS
   - XSSProtection Middleware
     - Does not load the page if an XSS Attack is detected
    - FrameOption Middleware
      - Specifies if the browser can render in another page as an embed
  - Referrer Policy Middleware
    -  Controls How much Referrer Information is included in a request
  - ExpectCT Middleware
    - Enforcement of Certificate Transparency requirements which prevent the uses of misissued certificate
  - Content Type Middleware
    - Prevents Mime sniffing attacks

<img src="/demo/calvin/security_headers.png" alt="security headers" style="width: 70%;">

<img src="/demo/calvin/frame_options.png" alt="frame options" style="width: 70%;">

Gyazo Links: https://gyazo.com/ab9fca9a269050e266663064028c6b66 , https://gyazo.com/f8bd3228048831bcd930f1dcab0bd7d9

<div id="file-scan"></div>

- File Analysis
  - Implemented Files to be scanned by VirusTotal API before being uploaded
  - Upon posting, the file runs through the api and will return the results as shown below. We then check the results and decide whether to allow the file to be uploaded or not

<img src="/demo/calvin/file_scan.gif" alt="Scan File for Virus" style="width: 70%;">

Gyazo Link: https://gyazo.com/b29e471c652ef9218c11d475e5fcc5d3

<div id="url-scan"></div>

- URL Analysis
  - Implemented URLs to be scanned by Google WebRisk API & VirusTotal API before being uploaded
  - Redirect Confirmation also runs the URL Analysis

<img src="/demo/calvin/url_scan.gif" alt="url scanning" style="width: 70%;">

<img src="/demo/calvin/url_scan_redirect.gif" alt="redirect confirmation scanning" style="width: 70%;">

Gyazo Links: https://gyazo.com/2cc0c8eddf7c15a69d430c712a5a8c0d , https://gyazo.com/50fe935017bf45f0abe5edd979c49e0a

<div id="storage-of-results"></div>

- Storing of Analysis Results
  - Implemented MongoDB to store the results of the analysis so as to reduce API usage
  - Reduce the risk of attacks on the availability as scans may take a long time and can overload our servers

<img src="/demo/calvin/storage_of_results.png" alt="results storing" style="width: 70%;">

Gyazo Link: https://gyazo.com/3264b8f6f61bbc193d048414f8c4847b

<div id="pagination"></div>

- Post & Comment Pagination
  - Implemented Pagination to reduce the load on the server
  - Fetches a certain number of posts/comments at a time, upon scrolling to a certain height more posts/comments are fetched

<img src="/demo/calvin/posts_pagination.gif" alt="pagination" style="width: 70%;">

Gyazo Link: https://gyazo.com/6326a6fa22a96d6197f84f1939cad924

<div id="extra-authen"></div>

- Extra Verification to view settings
  - A layer of authentication before accessing and editting critical settings

<img src="/demo/calvin/extra_authen.gif" alt="extra authentication" style="width: 70%;">

Gyazo Link: https://gyazo.com/90a9c46b4b51ea71264f3ef2b72e40a6

<div id="seo"></div>

- Blocking of Search Engine Crawlers
  - Implemented to prevent private pages from being indexed to search engines

<img src="/demo/calvin/seo.png" alt="seo" style="width: 70%;">

Gyazo Link: https://gyazo.com/38552becbbbee367268e1a69b17215a5

<div id="backup"></div>

- MongoDB Backup (Configuration)
  - Configured MongoDB to automatically backup to a remote server

<img src="/demo/calvin/backup_config.png" alt="mongodb backup" style="width: 70%;">

Gyazo Link: https://gyazo.com/3d78b3f38833edec08d581903785812d

## Research:
- Virus Scanning APIs and how to implement
  - VirusTotal API
  - WebRisk API

- Javascript Hashing Algorithms
  - CRC32C (SheetJS)

- Javascript Libraries
  - Filepond
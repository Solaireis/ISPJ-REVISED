<h1 align="center">
    <img src="/demo/eden/locked_admins.png" style="width: auto; height: auto;" alt="locked admins">
</h1>


# Eden:

## Functionality Of Web Application

## Implemented:
#### Features [Status: Completed]:
 ```diff
+ Demo User Functions 
+ Error Page Middleware
+ Admin & Root (Maintenance) User Navigation Bars
 
```

#### Features [Status: Not Completed / Work in Progress]:


 ```diff
- N/A
 
```

#### Data Security [Status: Completed]:
```diff
+ • Role Based Access Controls
+	o Roles Used in Mirai Access based Controls
+	o Role Based Access Control Configuration
	
+ • Data Masking & Detection
+	o Data Masking of sensitive information sent as text
+	o Sensitive Data Detection from image uploads using Optical Character Recognition
+	o Sensitive Data Detection of Passport using Machine Learning & Optical Character Recognition
	
+ • Logging & Console

+ • Admin Pages
+	o Admin Dashboard
+	o Admin Ban System
+	o Admin Report dashboard
+	o User Lists
	
+ • Root Account Pages & Functionalities
+	o Root Account Dashboard
+	o Admin Lists
+	o Admin Lock Accounts System
+	o Maintenance Mode
+	o Admin Create Accounts
	
+ • Error Middleware
+	o Shows Locked Account Page
+	o Shows Banned Account page
	
+ • Separate Data Base Servers

+ • Admin Honeypot page

+ • CloudFlare Configuration

```
## Table of contents

#### Features [Status: Completed]:
- Demo User Functions 
- Error Page Middleware
- Admin & Root (Maintenance) User Navigation Bars

#### Data Security [Status: Completed]:
- Role Based Access Controls
    - Roles Used in Mirai Access based Controls
    - Role Based Access Control Configuration
-  Data Masking & Detection
    - Data Masking of sensitive information sent as text
	- Sensitive Data Detection from image uploads using Optical Character Recognition
	- Sensitive Data Detection of Passport using Machine Learning & Optical Character Recognition
-	Logging & Console
-	Admin Pages
	- Admin Dashboard
	- Admin Ban System
	- Admin Report dashboard
	- User Lists
-	Root Account Pages & Functionalities
	- Root Account Dashboard
	- Admin Lists
	- Admin Lock Accounts System
	- Maintenance Mode
	- Admin Create Accounts
-	Error Middleware
	- Shows Locked Account Page
	- Shows Banned Account page
-	Separate Data Base Servers
-	Admin Honeypot page
-	CloudFlare Configuration


#### Data Security [Status: Not Completed / Work in Progress]:

 ```diff
- N/A
 
```

### Features:


#### Demo Users Function

<h1>
    <img src="/demo/eden/demo_users.png" style="width: auto; height: auto;" alt="locked admins">
</h1>

A demo function for internal testing of the web application
-	Create Users (Users, Mirai+ Accounts, Admin, Root)
-	Creation of users using the Oauth2.0 Login system
-	Create Reports Function (for the showcase of a reporting in Mirai)
-	Deletion of Users & reports
-	Create Ban Accounts and Ban Logs

#### Error Pages Application Middleware:

<h1>
    <img src="/demo/eden/error404.png" style="width: auto; height: auto;" alt="locked admins">
</h1>

A middleware handling errors caused in the Mirai social media
-	Custom error pages and handling of web application errors such as error 404, 403, 500
-	Redirect to home page
-	Admin pages will be redirected 404 to not reveal the admin pages

#### Admin & Root(Maintenance) Navigation bars

<div class="container">
   <span class="column" align="left">
     <img src="/demo/eden/rootNavBar.png" style="width: 20%; height: 20%;" alt="locked admins">
   </span>
   <span class="column" align="left" >
    <img src="/demo/eden/adminNavBar.png" style="width: 20%; height: 20%;" alt="locked admins"
   </span>
</div>

Navigation bars for the Maintenance and Administrator accounts
-	integrated with common UI template. 
-	If user is either the admin or root account, it will show their respective role navigation bars

### Data Security Features:
Roles used in Mirai Access Based Controls Overview

Guest: 
> Unable to use the web application can only see public posts & comments

User:
> Able to use Mirai plus features such as post, comments, chats

Mirai Plus:
> A subscription role which gives user extra perks improvements

Admin(moderator):
> Privilege Account that can ban users, view reports made, 

Root Account(Maintenance): 
> The root account which can set site to maintenance mode, lock inactive admin accounts, create administrator

Role Based Access Controls Configuration
1.	Separation of Duties & least privilege
    a.	Maintenance account cannot perform admin roles i.e. ban users
    b.	Admin cannot perform user roles i.e. using Mirai social media app
2.	All roles are given their own router which allows these users to visit their authorized pages
3.	Further checks in place such as session checks to ensure only authorised users can access
4.	Whitelist authorization is done

#### Data Masking for sensitive information 

<h1>
    <img src="/demo/eden/postSSN.png" style="width: auto; height: auto; inline-block" alt="locked admins">
</h1>
	
Integrated with the Posts, Profile Picture, Comments, Chat Functionalities

###### Features:
Detects the following information:
1.	Singapore Street Address, 
2.	American Social Security Number
3.	Credit Cards
###### How it works:
1.	If a user sends any of the above sensitive information via text
2.	 Sensitive data will be detected and be masked as ****

#### Sensitive Data Detection from image uploads using Optical Character Recognition

<h1>
    <img src="/demo/eden/ssn.png" style="width: auto; height: auto; inline-block" alt="locked admins">
</h1>

Integrated with the Posts, Profile Picture, Comments, Chat Functionalities
	
###### Features:
Detect sensitive data such as 
1.	Singapore Street Address, 
2.	American Social Security Number
3.	 Credit Cards
###### How it works:
1.	If a user sends any of the above sensitive information via an image which contains these sensitive information 
2.	the image will not be send & user given a prompt that it contains sensitive information which cannot be send or posted
3.	Credit Card number will be validated from credit card numbers ranging from length of 13 – 19
4.	Credit Cards numbers will be validated with the Luhn algorithm to prevent false positives

#### Sensitive Data Detection of Passport using Machine Learning & Optical Character Recognition
	
<h1>
    <img src="/demo/eden/passport.png" style="width: auto; height: auto; inline-block" alt="locked admins">
</h1>
	
Integrated with the Posts, Profile Picture, Comments, Chat Functionalities
###### Features:
1.	Detects Passports 
2.	Detection of passport is done through OCR and passport recognition is through Machine learning using Python Eye Module
3.	Uses Google tesseract OCR installed on a Docker Container
4.	Function is done on cloud to save resources
5.	Any Detected Passport are logged
6.	Detected passports are cache for faster detection of similar passports

###### How it works:
-	If a user sends any of the above sensitive information via an image which contains these sensitive information 
-	the image will be analysed
-	If a passport was detected, the image will not be send & user given a prompt that it contains sensitive information which cannot be send or posted
-	Detects if the image contains particular information which are contained in a passport
-	Is able to detect type 1 to type 3 Machine Readable zones


#### Logging & Console

<h1>
    <img src="/demo/eden/logging.gif" style="width: auto; height: auto; inline-block" alt="locked admins">
</h1>

Features:
-	Logging of admin & root account page viewed
-	Logging of all action done by the admin and root such as banning
-	Logging of sign ins and sign outs of the admin and root account
-	Logging of passport detected
-	Logging of failed attempts at the admin honeypot page
-	Integrated logging using python logging which is uploaded to the cloud 
-	Uses Google Cloud logging

#### Admin Dashboard

<h1>
    <img src="/demo/eden/adminDashboard.png" style="width: auto; height: auto; inline-block" alt="locked admins">
</h1>

Dashboard showing useful information for the administrator
-	Displays relevant dynamic information on the admin dashboard	
-	Number of ban logs, total users, banned users, reports in system open reports
#### Admin Ban System
	
<h1>
    <img src="/demo/eden/BanLogs.gif" style="width: auto; height: auto; inline-block" alt="locked admins">
</h1>

<h1>
    <img src="/demo/eden/bannedUser.png" style="width: auto; height: auto; inline-block" alt="locked admins">
</h1>

<h1>
    <img src="/demo/eden/bannedProfile.png" style="width: auto; height: auto; inline-block" alt="locked admins">
</h1>
	
Ban system of Mirai
-	When user is banned they will be given a banned page along with the appropriate reasons
-	A banned user posts, comments and profile are hidden from other viewers
#### Admin Report dashboard
	
<h1>
    <img src="/demo/eden/report_list.gif" style="width: auto; height: auto; inline-block" alt="locked admins">
</h1>
	
-	Retrieves the reports made by the user in Mirai web application
-	Shows open and close cases
#### User Lists Dashboard

<h1>
    <img src="/demo/eden/userListPagination.gif" style="width: auto; height: auto; inline-block" alt="locked admins">
</h1>

User lists of all the users in Mirai
-	Pagination to support data availability
-	Allows admin to ban or unban the users in Mirai
-	Allows Admin to ban misbehaving users or suspicious
-	Bans are logged to the cloud
#### Maintenance Dashboard
	
<h1>
    <img src="/demo/eden/MaintenanceDashboard.png" style="width: auto; height: auto; inline-block" alt="locked admins">
</h1>
	
Shows the relevant dynamic information on the maintenance account page
-	Information shown are total admins, locked admins, maintenance mode, lock logs counts
#### Admin Lists Dashboard

<h1>
    <img src="/demo/eden/adminListPagination.gif" style="width: auto; height: auto; inline-block" alt="locked admins">
</h1>

Retrieves the admin lists
-	Allows the root account to lock inactive or unlock admins
-	When an account is locked or unlocked by an admin, a reason is required
-	The action of  executing the lock or unlock will be logged 
-	Implemented Pagination to support data availability
#### Admin Lock Accounts System

<h1>
    <img src="/demo/eden/lockAdmin.gif" style="width: auto; height: auto; inline-block" alt="locked admins">
</h1>


	
Mirai Locked Admins system
-	Lock admins will be locked from accessing Mirai website
-	Lock admins will be given a locked page stating the reason why they are locked
	
#### Maintenance Mode
	
<h1>
    <img src="/demo/eden/maintenanceMode.png" style="width: auto; height: auto; inline-block" alt="locked admins">
</h1>
	
Allows the website to be set in maintenance mode
-	Requires the root to input their username to confirm the action of setting website to maintenance mode
-	This action is logged
-	Implemented ReCAPTCHA Enterprise Validation to prevent bot attempts at setting the site to maintenance mode
-	Page will dynamically change to enable or disable maintenance mode depending on the current site mode
-	When Site is set to Maintenance mode, users who are not admins or root account redirected to maintenance page

#### Admin Create Accounts

<h1>
    <img src="/demo/eden/createAdmins.gif" style="width: auto; height: auto; inline-block" alt="locked admins">
</h1>
	
<h1>
    <img src="/demo/eden/recaptchaCreateAdmins.gif" style="width: auto; height: auto; inline-block" alt="locked admins">
</h1>


Allows the creation of admins in Mirai website
-	Admins email have to end with @miraisocial.live for it to be valid for creation
-	Checks if existing admins already exists
-	Only allows admin to login via Oauth2.0 feature 
-	The creation of admin accounts is logged
-	Implemented ReCAPTCHA Enterprise Validation to deter bot creation of admins
#### Error Middle Ware
Custom error exception handlers 
-	Lock Exception is triggered when an admin has a locked status set to true
-	Banned Exception is triggered when a user has a banned status set to true
-	When any of these exceptions is triggered, user is redirected to the respective pages
#### Separate Data Base Servers
Two Separate database, decentralised system
- Implemented mirai as a user database server for any services on the mirai web application 
- implemented mirai_admin as a database server for any services on the mirai admin pages
- Failsafe in the event of one database server being compromised the other is isolated and seperated from attacks
- requires greater effort in integration and checks
Mirai Database Server
-	For the daily operations of Mirai
-	E.g. Posts Database, Chat Database , Users Database.
Mirai Admin Database
-	For the admin & root account operations of Mirai
-	E.g. Reports database, Ban Database, Admin Database.

#### Admin Honeypot page
	
<h1>
    <img src="/demo/eden/honeypot.png" style="width: auto; height: auto; inline-block" alt="locked admins">
</h1>
	
<h1>
    <img src="/demo/eden/honeypot_logs.png" style="width: auto; height: auto; inline-block" alt="locked admins">
</h1>
	
Fake Admin page located at /admin/login
-	Test for attackers probing the website
-	If attackers input a username and password the attempt will be logged
	- Ip address of attacker
	- Credentials used
-	Administrators can be alerted of logs that shows repeated access from a specific IP address to possibly blacklist them or be alerted of a possible attack
-	Enabled ReCAPTCHA to deter bot attacks
#### Cloudflare configuration

<h1>
    <img src="/demo/eden/cloudflare.png" style="width: auto; height: auto; inline-block" alt="locked admins">
</h1>

<h1>
    <img src="/demo/eden/caching.png" style="width: auto; height: auto; inline-block" alt="locked admins">
</h1>
	
Configured the Cloudflare for security configuration
-	Enabled cache controls for Cloudflare to set time for caching to be 3 hours long
-	Ensure strict query controls are done
-	Enabled HSTS mode on Cloudflare
-	Enabled strict mode for TLS/SSL configuration

#### Demo Accounts
	
<h1>
    <img src="/demo/eden/titanEmail.png" style="width: auto; height: auto; inline-block" alt="locked admins">
</h1>
	
- Use Titan to create email accounts for used on mirai as oauth accounts


### Research Done:

> I have explored Role Based Access Control & the feasibility of it
> For users I will be further implementing Relationship Based Controls as it is better, allows finer tuned controls between users.
> Each user can define how much control the other users can see

> I also have explored Data Masking for street names.
> My friend has offered to help teach me how to train Data Models.
> Using existing Data Models online curated by Singaporeans.
 
#### Sample Research Sources:
> ReBAC
> - https://www.ubisecure.com/access-management/what-is-relationship-based-access-control-rebac/
 
 
> OWASP Authorization
> - https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
 
 
> Data Masking Dataset
> - https://www.kaggle.com/datasets/mylee2009/singapore-postal-code-mapper
 
 
> AI Pytorch
> - https://pytorch.org/docs/stable/index.html

	
<!-- ```diff
- text in red
+ text in green
! text in orange
# text in gray
@@ text in purple (and bold)@@
``` -->

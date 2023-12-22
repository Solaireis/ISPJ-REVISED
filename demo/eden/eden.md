# DO NOT DELETE , this file is archived for future reference

### Fundamentals Features:
-	Create User Function
-	Create Reports
-	Delete Users
-	Delete Reports
-	Data Base Functionalities
-	Error Pages Web Application Middleware
-	Admin Navbar 
-	Maintenance/Root Navbar

#### Admin Pages
-	Admin Dashboard
    > dynamically updated admin dashboard

-	Normal User List
    >	Retrieves all normal users

-	Admin Reports
    >	Retrieves all reported users

-  Admin Bans
    >   Retrieves all banned users log


#### Root/Maintenance Pages 
-    Root Dashboard
    > dyanmically updated root dashboard

-    Admin User List
    > Retrieves all admin users

-   Admin locked accounts
    > Retrieves all locked accounts logs

-   Admin create admin accounts
    > Allows the creation of admin accounts


#### DEMO Functionalities
- Create Users Python function which allows the creation of users in the database
- Create Reports Python function which allows the creation of reports in the database
- Delete Users Python function which allows the deletion of users in the database
- Delete Reports Python function which allows the deletion of reports in the database
- Create bans Python function which allows the creation of bans in the database
- Delete bans Python function which allows the deletion of bans in the database

#### Demo Accounts
- Use Titan to create email accounts for used on mirai as oauth accounts

### Security:
#### Roles
- User
- Mirai+
- Admin(privileged account) (can have multiple administrator accounts)
- Maintenance(root level) ( 1 account only)

> Privilege levels will be as follows
> - User: 0
> - Mirai+: 1 
> - Admin: 2
> - Maintenance: 3
> where maintenance is the highest level of privilege
> do note due to seperation of roles and least privileges principle, the maintenance account will not have access to the admin pages and vice versa
> mirai plus is just a user account but with added benefits 
> TODO: list the roles and privileges of each role

#### Access Control for all user roles, only authorized users can access certain pages
-	IDOR Protection from unauthorizaed access with session checks
-   RBAC Routers implemented to check for the roles of the users
-   Checks the user session to see if the user accessing is who they really are

#### OCR Text Recognition Data Masking
- implemented passportEye to detect the presence of passport in images
- Passports which have been previously detected will be cached for faster processing and detection
- Uses the Google Tesseract OCR engine to detect the presence of text in images
- We also implemented the OCR text recognition as a cloud function so as to not block other I/O operations in the main FastAPI app
- The cloud function is triggered when a new image is uploaded
- We also installed google tesseract into the docker container so that the OCR can be run

#### OCR sensitive data
- implemented Social Security Number Checks to detect the presence of SSN in images
- Street addresses singapore, detected the prensence of singapore addresses in images
- credit card regex, detected the presence of credit card numbers in images

#### Logging
- Implemented logging for all the Admin & Root account pages
- Implemented logging for all the Admin & Root Actions
- Implemented Logging for any failed passport attempts
- Implemented Logging for any login attempts
- Implemented Logging for Admin Account Creation
- Logging is pushed to the google cloud console

#### Error MiddleWare
- Implemented Error Middleware for all pages
- Custom Error exception handling for all pagees to detect whether account is banned or locked
- if account is banned or locked, the user will be redirected to the error page and the user will be signed out
- Banned function is only applicable for non privilege account users
- locked function is only applicable for privilege account users

#### Seperated Database servers
- Implemented mirai as a user database server for any services on the mirai web application 
- implemented mirai_admin as a database server for any services on the mirai admin pages
- Failsafe in the event of one database server being compromised the other is isolated and seperated from attacks
- requires greater effort in integration and checks

#### Honeypot 
- Implemented a honeypot for the mirai web application to detect any brute force attacks
- Fake admin login page to log admin account attempts would be useful if more security is added
- logging of any failed attempts to the honeypot, their ip address, inputs and account tries will be logged to the google cloud logging console

### Integration
- Integrated with common navbar of Mirai+ web application, which changes based on the roles of the user
- Integrated the OCR text recognition data masking with the Mirai web application
- Role based access control is applied universally to the whole web application
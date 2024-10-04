# 未来 Mirai 🌸

<h1 align="center">
    <img src="res/Logo.png" style="width: 50%; height: auto;" alt="Mirai logo">
    <br>
    Mirai - 未来
    <br>
    (Additional Info)
</h1>

## Nanyang Polytechnic Year 2 ISPJ
Our web application is called Mirai, it is a privacy-driven social media platform. We intend to allow the users to have a choice in what data they should give and who they should allow to see.

In our social media platform, the web application is just for the clients to interact with the API. Users would be able to execute account-related tasks like creating an account. Additionally, users will be able to execute features that are essential to a social media platform such as sharing photos, posting comments, and sending messages to people.
However, unlike conventional social media platforms, users will be able to configure their privacy preferences such as enabling self-destructing messages in our social media platform based on the default configurations. 

Existing applications such as Telegram and WhatsApp have introduced their own set of privacy-driven features such as secret chat, self-destructing messages, and more. Hence, adding privacy driven into a social media platform would attract users that are concerned about their privacy to use our social media instead of the already available platforms like Instagram.

It was also hosted on [https://miraisocial.live](https://miraisocial.live) and archived in the [Internet Archive](https://web.archive.org/web/20230401000000*/miraisocial.live).

**Team Members:**
> - Eden (Team Leader)
> - Calvin (Database Management & Data Integrity)
> - Jason (DevOps Lead)
> - Wei Ren (Privacy & Front End Functionalities)

## Mirai Architecture
![Mirai Architecture](res/architecture.png)

## Key Objectives
1. Enhanced Data Security Features
2. Privacy Features
3. Security in Depth to reduce impact of attacks

## Application Features
1. Posting of Video or Photos
2. 1:1 Chat System
3. Privacy Controls and Policies
4. Focuses on Data Security Policies and Best Practices
5. IAM Console and User Managements

---

## Running the Application

> pip install -r requirements.txt
>
> npm ci
> 
> npm run build-css
> 
> npm run build-js
>
> python ./src/app/main.py

* Note: You will need a MongoDB instance running on your local machine and a Google Cloud Platform Project with the necessary configurations to run the application.

## Tasks

### [Eden Will Sng Jin Xuan [201520M]](/writeups/eden.md)
#### Security Implementations
> - Role Based Access Controls (IAM)
>    - Roles Used in Mirai Access based Controls
>    - Role Based Access Control Configuration
> -  Data Masking & Detection
>    - Data Masking of sensitive information sent as text
>	- Sensitive Data Detection from image uploads using Optical Character Recognition
> 	- Sensitive Data Detection of Passport using Machine Learning & Optical Character Recognition
> -	Logging & Console (Monitoring)
> -	Admin Pages
> 	- Admin Dashboard
>	- Admin Ban System
>	- Admin Report dashboard
>	- User Lists
> -	Root Account Pages & Functionalities
>	- Root Account Dashboard
>	- Admin Lists
>	- Admin Lock Accounts System
>	- Maintenance Mode
>	- Admin Create Accounts
> -	Error Middleware
>	- Shows Locked Account Page
>	- Shows Banned Account page
> -	Separate Data Base Servers (Segregation of Network & Resiliency)
> -	Admin Honeypot page 
> -	CloudFlare Configuration 


### [Kuan Jun Hao Jason [201484K]](/writeups/jason.md)
> - Cloud Infrastructure & Deployment
> - GCP asynchronous capable Python codes
> - Login and Register
> - 1:1 Chat
> - Search (for users, comments, and posts)
> - Notifications
> - File uploading logic
> - HTML Embeds
> - Image content moderation
> - Storage of Secrets 
> - Encryption of Data
> - Middlewares
>   - Session
>   - CSRF
> - Role-based Access Controls (RBAC) Logic
> - Automated Attacks Mitigations
>   - Cloudflare
>   - reCAPTCHA Enterprise
> - Data Export as per the user's request
> - URL Redirect Confirmation
> - Account Security
> - XSS Mitigation
> - Cloud Functions
> - Scheduled Cloud Functions
> - Chat Security
> - End-to-end Integrity 
> - Data Masking & OCR Technologies
>   - Using Google Vision API, Google Natural Language API, and regex
> - Pagination
> - Image Validations & Compression

### [Lai Zhenyi Calvin [212775C]](/writeups/calvin.md)
> - File Validation & E2E Integrity Check 
> - Static File Analysis
> - Database Configuration
> - Data backups configurations
> - Security Headers

### [Cheow Wei Ren [213033T]](/writeups/wei_ren.md)
#### Website Features
> - Payment Gateway
> - General Privacy Settings
> - Mirai+ Subscription
> - Follower System
#### Security Implementations
> - Privacy Setup wizard
> - Block/Report System

## Tech Stack 📚
### Frontend
[![Frontend Tech Stack](/res/frontend.png)](https://skillicons.dev)

### Backend
[![Backend Tech Stack](https://skillicons.dev/icons?i=fastapi,python,go,&theme=light)](https://skillicons.dev)

### Others
[![Other Tech Used](https://skillicons.dev/icons?i=cloudflare,gcp,mongodb,&theme=light)](https://skillicons.dev)

### SWE Methodologies used
> - CI/CD
> - DevOps

## Jason:

- [Functionality of Web Application](#functionality-of-web-application)
  - [Login and Register](#login-and-register)
  - [1:1 Chat](#1-1-chat)
  - [Search (for users, comments, and posts)](#search)
  - [Notifications](#notifications)
  - [File uploading logic](#file-uploading-logic)
  - [HTML Embeds](#embeds)
  - [Image content moderation](#image-content-moderation)
- [Implemented](#implemented)
  - [GCP asynchronous capable Python codes](#gcp-async-python-codes)
- [Data Security](#data-security)
  - [Storage of Secrets](#storage-of-secrets)
  - [Encryption of Data](#encryption-of-data)
  - [Middlewares](#middlewares)
  - [Role-based Access Controls (RBAC) Logic](#rbac-logic)
  - [Automated Attacks Mitigations](#automated-attacks-mitigations)
  - [Data Export as per the user's request](#data-export)
  - [URL Redirect Confirmation](#url-redirect-confirmation)
  - [Account Security](#account-security)
  - [XSS Mitigation](#xss-mitigation)
  - [Cloud Functions](#cloud-functions)
  - [Scheduled Cloud Functions](#scheduled-cloud-functions)
  - [Chat Security](#chat-security)
  - [End-to-end Integrity](#end-to-end-integrity)
  - [Data Masking](#data-masking)
  - [Pagination](#pagination)
  - [Image Validations & Compression](#image-validations-and-compression)
- [Integration](#integration)
- [Research](#research)

## Functionality Of Web Application

<div id="login-and-register"></div>

- Login and Register

<img src="/demo/jason/features/login_and_register.gif" alt="login and register feature" style="width: 70%;">

<div id="1-1-chat"></div>

- 1:1 Chat

<img src="/demo/jason/features/chat.gif" alt="chat feature" style="width: 70%;">

<div id="search"></div>

- Search (for users, comments, and posts)

<img src="/demo/jason/features/search.gif" alt="search feature" style="width: 70%;">

<div id="notifications"></div>

- Notifications

<img src="/demo/jason/features/notifications.gif" alt="notifications feature" style="width: 70%;">

<div id="file-uploading-logic"></div>

- File uploading logic
  - Including chunked uploading due to the 32MB limit per request for [Google Cloud Run](https://cloud.google.com/run).

<div id="embeds"></div>

- HTML embeds for popular websites like YouTube

<img src="/demo/jason/features/embeds.gif" alt="embeds feature" style="width: 70%;">


<div id="image-content-moderation"></div>

- Image content moderation using [Google Cloud Platform (GCP)](https://cloud.google.com) [Computer Vision API](https://cloud.google.com/vision)
  - Able to detect explicit content and spoof (aka memes) content.
  - Below is a demo of blocking spoof content.

<img src="/demo/jason/features/spoof_blocked.gif" alt="spoof content moderation feature" style="width: 70%;">

## Implemented

<div id="gcp-async-python-codes"></div>

- [Google Cloud Platform (GCP)](https://cloud.google.com) asynchronous capable Python codes
  - Since most of the GCP's APIs Python libraries are not asynchronous capable, I had to write my own asynchronous capable Python codes for the various APIs to improve the performance of the web application.
  - Additionally, even if the library had async support, it had some issues with the Python's asyncio event loop.

## Data Security

<div id="storage-of-secrets"></div>

- Storage of Secrets
  - All secrets of the web applications such as API access tokens, database credentials, etc. are stored in GCP Secret Manager.

<div id="encryption-of-data"></div>

- Encryption of Data
  - Using Using [Google Cloud Platform (GCP)](https://cloud.google.com) [Key Management Service (KMS)](https://cloud.google.com/security-key-management).
  - Encrypted on the Application Layer using AES-256-GCM.
  - User's data that are encrypted:
    - Phone numbers
      - As it is only used for SMS 2FA
    - Argon2id password hashes
      - as pepper
    - Shared Time-based One-Time Password (TOTP) secrets
      - Used for 2FA with Google Authenticator or other compatible apps
    - Chat messages

  <img src="/demo/jason/data_security/encryption/gcp_kms.png" alt="gcp kms encryption keys" style="width: 70%;">

<div id="middlewares"></div>

- Middlewares
  - CSRF
    - HMAC-SHA256
    - Uses the header and cookie for CSRF validation to prevent CSRF attacks.
    - Uses GCP KMS Cloud HSM to generate a high entropy bytes for the CSRF token.
  - Session
    - HMAC-SHA256
    - Flexible as compared to the in-built FastAPI/Starlette session middleware.
      - Able to become session cookie (without expiry date but the session ID lasts for a day) when the user does not check the `stay signed in` checkbox.
      - If the user checks the `stay signed in` checkbox, the session will become a persistent cookie that expires after 2 weeks.
      - Uses [GCP KMS Cloud HSM](https://cloud.google.com/kms/docs/generate-random) to generate a high entropy bytes for the session ID.
  - Cache control middleware for the web application endpoints.
    - For better performance and availability.

<div id="rbac-logic"></div>

- Role-based Access Controls (RBAC) logic
  - Uses [FastAPI](https://fastapi.tiangolo.com/)'s [dependency injection feature](https://fastapi.tiangolo.com/tutorial/dependencies/).
  - Clears invalid sessions
  - Redirects the user to its default endpoint if not authorised.
  - For sensitive routes like the admin pages, it will raise 404 HTTP error if the user is not authorised.

<div id="automated-attacks-mitigations"></div>

- Automated Attacks Mitigations
  - Rate limiter using [FastAPI limiter](https://pypi.org/project/fastapi-limiter/)
    - Uses [FastAPI](https://fastapi.tiangolo.com/)'s [dependency injection feature](https://fastapi.tiangolo.com/tutorial/dependencies/).

  <img src="/demo/jason/data_security/automated_attacks/rate_limiting.gif" alt="rate limiting demo" style="width: 70%;">

  - Using [reCAPTCHA Enterprise](https://cloud.google.com/recaptcha-enterprise) to increase friction against bots.
  - Integrated [Cloudflare](https://www.cloudflare.com/) to our domain, [miraisocial.live](https://miraisocial.live/) to increase friction against bots and protect against any network attacks.

<div id="data-export"></div>

- Data export as per the user's request.
  - Fulfils [Art. 20 GDPR – Right to data portability](https://gdpr-info.eu/art-20-gdpr/).
  - Fulfils the [PDPA's Data Portability Obligation](https://www.pdpc.gov.sg/overview-of-pdpa/the-legislation/personal-data-protection-act/data-protection-obligations).
  - Uses Cloud Tasks to export the user's data and send it to the user's email.
  - Since I deployed the code to Google Cloud Run, it has a max runtime of 1 hour which is sufficient for this project.
    - For scalability, one could deploy the code to [Google Compute Engine](https://cloud.google.com/compute) or [Google App Engine](https://cloud.google.com/appengine) which can have up to 24 hours of processing time.

  <p>
    <img src="/demo/jason/data_security/data_portability/data_export.gif" alt="data export demo" style="width: 70%;">
    <img src="/demo/jason/data_security/data_portability/zip_content.png" alt="exported zip file data preview" style="width: 70%;">
  </p>

<div id="url-redirect-confirmation"></div>

- URL redirect confirmation for external links posted by users.
  - Intgerated with Calvin's URL analysis feature for suspicious or malicious URLs.

  <img src="/demo/jason/data_security/general/url_redirect_confirmation.png" alt="url redirect confirmation demo" style="width: 70%;">

<div id="account-security"></div>

- Account Security
  - Google and Facebook OAuth2 login.

  <img src="/demo/jason/data_security/account_security/combined_oauth2_logins.gif" alt="google and facebook oauth2 demo" style="width: 70%;">

  - Forgot Password

  <img src="/demo/jason/data_security/account_security/combined_reset_password_process.gif" alt="reset password demo" style="width: 70%;">

  - Voluntary revocation of the user's sessions.

  <img src="/demo/jason/data_security/account_security/sessions.png" alt="sessions page" style="width: 70%;">

  - Alerting users when their passwords are leaked in data breaches using [reCAPTCHA Enterprise](https://cloud.google.com/recaptcha-enterprise) API.
    - Takes the username or a canonicalised email and the user's password and pass it through a Scrypt hash function and then sends it to the [reCAPTCHA Enterprise](https://cloud.google.com/recaptcha-enterprise) API to check if it is in their database of compromised passwords.

  <img src="/demo/jason/data_security/account_security/password_breach.gif" alt="password breach alert demo" style="width: 70%;">

  - Added password policy.

  <img src="/demo/jason/data_security/account_security/password_policy.gif" alt="password policy demo" style="width: 70%;">

  - 2FA using Authenticator app or SMS (using [Twilio](https://www.twilio.com/) API).

  <img src="/demo/jason/data_security/account_security/combined_2fa.gif" alt="sms and authenticator 2fa setup demo" style="width: 70%;">
  <img src="/demo/jason/data_security/account_security/2fa_sms_login.gif" alt="2fa sms login demo" style="width: 70%;">
  <img src="/demo/jason/data_security/account_security/2fa_authenticator_login.gif" alt="2fa authenticator app login demo" style="width: 70%;">

  - 2FA backup single use code to be used to disable their 2FA in the event that they lose access to their device.

  <img src="/demo/jason/data_security/account_security/disable_2fa.gif" alt="2fa backup code demo" style="width: 70%;">

  - Location-based login 2FA if the user is logging in from a new location and does not have 2FA enabled.

  <img src="/demo/jason/data_security/account_security/location_based_2fa.gif" alt="location-based 2fa demo" style="width: 70%;">

<div id="xss-mitigation"></div>

- XSS mitigation for the web application endpoints.
  - Using [DOMPurify](https://github.com/cure53/DOMPurify), [`html.escape()`](https://docs.python.org/3/library/html.html#html.escape), and [Jinja2](https://jinja.palletsprojects.com/en/3.0.x/api/#autoescaping) to escape dirty user inputs.

<div id="cloud-functions"></div>

- [Cloud Functions](https://cloud.google.com/functions)
  - Create Signed URL (Golang)
    - Uses the Golang's [Google Cloud Storage (GCS)](https://pkg.go.dev/cloud.google.com/go/storage) library to create a signed URL for the user to view the file.
      - During the process of signing the [GCS](https://cloud.google.com/storage) URL, it can also contain an expiry time for a short-lived signed URL which will expire and become invalid.
    - Used in posts and chat messages for confidentiality. 

  <img src="/demo/jason/data_security/general/signed_url.gif" alt="signed url demo" style="width: 70%;">

  - Sending Emails (Golang)
    - Since [aiosmtplib](https://pypi.org/project/aiosmtplib/) Python library takes a while (~5 mins) for the user to receive the emails, I had to make a Cloud Function to send the emails which is coded in golang which helped to reduce the time taken for the user to receive the emails to ~15 seconds.

<div id="scheduled-cloud-functions"></div>

- Scheduled [Cloud Functions](https://cloud.google.com/functions)
  - Using [Cloud Scheduler](https://cloud.google.com/scheduler) to schedule the [Cloud Functions](https://cloud.google.com/functions) to run at a specific intervals.

  <img src="/demo/jason/data_security/general/gcp_scheduler_config.png" alt="gcp cloud scheduler configurations" style="width: 70%;">

  - Re-encrypt Database (Golang)
    - Automated the re-encryption of the user's data when the encryption key in [GCP Key Management Service (KMS)]((https://cloud.google.com/security-key-management)) is rotated.
  - Database Cleanups (Golang)
    - As per data retention policy
      - Delete expired chat messages.
      - Delete orphan comments (comments that are not attached to any posts as the post was deleted).
      - Delete the user's data if the user has not logged in for 2 years.
      - Delete the user's data if the user has not verified their email for a month.
      - Delete the admin's account if the admin has been inactive for more than a month.
        - It also due to security reasons such as to minimise the risk of the admin's account being compromised.

  <img src="/demo/jason/data_security/general/cloud_scheduler.png" alt="cloud scheduler" style="width: 70%;">

<div id="chat-security"></div>

- Chat Security

  <img src="/demo/jason/data_security/chat_security/chat_settings.gif" alt="chat data security settings" style="width: 70%;">

  - Allow users to add a chat password for extra security.
    - If the user forgets the password, they can reset it by clicking on the "Forgot Password" button which will send an email to the user's email address with a link to disable their chat password protection.

  <img src="/demo/jason/data_security/chat_security/chat_password.gif" alt="chat password demo" style="width: 70%;">
  <img src="/demo/jason/data_security/chat_security/forgot_chat_password.gif" alt="forgot chat password demo" style="width: 70%;">

  - Disappearing messages that can be configured by either the sender or the receiver.
    - Will take the one with the shortest duration to be used for the message's self-destruct timer.

  <img src="/demo/jason/data_security/chat_security/disappearing_msg.gif" alt="disappearing messages demo" style="width: 70%;">

  - Signed [Google Cloud Storage (GCS)](https://cloud.google.com/storage) URL for files uploaded by users as previously mentioned.

<div id="end-to-end-integrity"></div>

- End-to-end integrity
  - Chat messages are checked using CRC32C and MD5 checksums for integrity checks and also with performance in mind.
    - No need for SHA256 as it is already sent via WebSocket Secure (WSS) which is encrypted and ensures the integrity of the data.
  - Web application/API server to [GCS](https://cloud.google.com/storage) server integrity checks are done by sending the file's MD5 and CRC32C checksums to [GCS](https://cloud.google.com/storage) for file integrity validations on Google's end.

  <img src="/demo/jason/data_security/chat_security/gcs_code.png" alt="gcs integrity check python codes" style="width: 70%;">

<div id="data-masking"></div>

- Data Masking
  - Using [GCP Computer Vision](https://cloud.google.com/vision) API and [GCP Natural Language](https://cloud.google.com/natural-language) API to mask sensitive data in images, pdfs, and text.

  <p>
    <img src="/demo/jason/data_security/data_masking/pdf_content.png" alt="pdf content" style="width: 50%;">
    <img src="/demo/jason/data_security/data_masking/pdf_ocr.gif" alt="pdf OCR demo" style="width: 100%;">
  </p>

  - Using regex to also mask sensitive data in text due to the limitations of the [GCP Natural Language](https://cloud.google.com/natural-language) API.

  <img src="/demo/jason/data_security/data_masking/google_nlp_and_regex.gif" alt="data masking demo" style="width: 70%;">

<div id="pagination"></div>

- Pagination
  - Implemented in the chat as to prevent:
    - The server's and the client's browser memory from being overloaded with too many chat messages which can cause either the server or the client's browser to crash.
    - Overloading or getting rate limited by the [GCP KMS](https://cloud.google.com/security-key-management) API.
  - Search results are also paginated to prevent:
    - The server's and the client's browser memory from being overloaded with too many search results which can cause either the server or the client's browser to crash.

  <img src="/demo/jason/data_security/general/chat_pagination.gif" alt="chat pagination demo" style="width: 70%;">

<div id="image-validations-and-compression"></div>

- Image Validation & Compression
  - Helps to reduce the size of the image files uploaded by the user.
  - Also checks for decompression bomb attacks which can cause the client's browser to crash.
    - Uses Python's [Pillow](https://pypi.org/project/Pillow/) library to compress and do the image decompression bomb attack checks.
    - The attacks are executed by uploading a very large resolution file (E.g. 10,000 x 10,000 pixels) which can cause severe lag and can even crash the client's browser.
    - For posts, the large resolution image will be blocked from being uploaded and the user will be notified.
    - For chat messages, the large resolution image will be treated as a normal file and will not be displayed as an image on the user's browser.
      - This approach is safer as the user can still view the image by downloading it and viewing it directly on his/her device without crashing the client's browser.

  <img src="/demo/jason/data_security/image_validations/image_payload.png" alt="image payload (20098 x 13280)" style="width: 70%;">
  <img src="/demo/jason/data_security/image_validations/chat_image_validation.gif" alt="chat message image validation demo" style="width: 70%;">
  <img src="/demo/jason/data_security/image_validations/post_image_validation.gif" alt="post image validation demo" style="width: 70%;">

  - Original images can be viewed by clicking on the "View Original" button or removing the `?compress=true` query parameter from the image URL.

  <img src="/demo/jason/data_security/general/original_image.gif" alt="original image demo" style="width: 70%;">
  <img src="/demo/jason/data_security/general/compressed_image.gif" alt="compressed image demo" style="width: 70%;">

## Integration
- Helped to deploy the [Cloud Functions](https://cloud.google.com/functions) developed by my group members to GCP.
- Integrated Eden's PassportEye OCR with the file uploading logic.
- Integrated Eden's data security enhancements
  - Separate database servers for user-related data and admin-related data
  - RBAC configurations for the web application endpoints
- Helped to clean up the code and fix bugs in the web application and API.
- Helped to develop asynchronous capable Python codes for the GCP APIs if needed for my group members' features such as the GCP Web Risk API for Calvin's URL analysis.

## Research
- MongoDB Configurations for Data Security
  - MongoDB sharding which allows the database to scale horizontally by splitting the data into chunks and distributing them across multiple servers. This helps to provide higher availability and scalability.
  - Encryption at rest for the MongoDB database.
  - Automatic backups for the MongoDB database (which is also encrypted at rest).
  - Multiple nodes for the MongoDB database for automatic failover to provide higher availability.

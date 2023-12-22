## WeiRen:

## Functionality Of Web Application
- Initial Setup/Privacy Settings Page
  - New users must complete this to access other parts of the app
  - Unless **explicitly** skipped

<div align="center">
  <img src="/demo/wei_ren/setup.gif" alt="privacy_initial_setup" style="width:50%;"><br>
  <sup>Control the level of information you display on Mirai.</sup>
</div><br>

- Follower System
  - |Followers|Following |Pending`#`|Requests|
    |---------|----------|----------|--------|
    |View`*`  |View`*`   |View      |View    |
    |Follow   |Unfollow  |Accept    |Remove  |
    |Unfollow |          |Deny      |        |
  - <sup>`*`Allowed to by other users</sup>
  - <sup>`#`If "requests only" for follower requests</sup>

<div align="center">
  <img src="/demo/wei_ren/followers.gif" alt="follower_system" style="width:50%;"><br>
  <sup>Demonstration of the many features of the system.</sup>
</div><br>

- Blocking Users
  - Selectively remove public users from view
  - Blocked users cannot view your information
    - Logged out users can see information with public permissions
    - Warning displayed to caution user of this loophole

<div align="center">
  <img src="/demo/wei_ren/block.gif" alt="user_blocking" style="width:50%;"><br>
  <sup>Blocking, and unblocking, a user and their posts.</sup>
</div><br>

- Reporting Users <sup>`*`User side</sup>
  - Word limit(s) to ensure proper reports are being made
  - Sent to admin-side for review

<div align="center">
  <img src="/demo/wei_ren/report.gif" alt="user_report" style="width:50%;"><br>
  <sup>Reporting a user for spam. Note the other available selections.</sup>
</div><br>

- Mirai+ Subscription Page
  - E.g. Description of perks
  - Utilises Stripe's payment gateway
  - Integrated with `Mirai+ Perks` by Jason

<div align="center">
  <img src="/demo/wei_ren/stripe.gif" alt="stripe_subscription" style="width:50%;"><br>
  <sup>Subscribing to, canceling and resuming Mirai Plus.</sup>
</div>

#### Implemented:
- Initial Setup
  - Middleware for privacy settings
  - Dummy proof process of setting privacy
  - Encourage infosecurity

- Privacy Settings
  - Provides _Relationship-Based Access Control_
  - Control information sharing based on
    - Following status
    - Public permissions
  - Covers the following:
    - Post visibility (Integrated with Calvin's `Post Fetching`)
    - Profile details (Integrated with Calvin's `Profile Page`)
    - Search indexing (Integrated with Jason's `Search`)
    - Sending chat DMs (Integrated with Jason's `Chat`)
    - Becoming a follower
  - Default: Follower Only

- User Blocking
  - Provides _Role-Based Access Control_
  - Layered security on top of privacy

- Stripe Payment Gateway
  - Uses Stripe's checkout session
  - Avoid storing payment credentials locally
  - Detailed logs and dashboard for transaction management
    <div align="center">
      <img src="/demo/wei_ren/logs.png" alt="stripe_logs" style="width:50%;"><br>
      <sup>Stripe also provides API logs and a dashboard in addition to event logs.</sup>
    </div>

  - Scheduled Golang [Cloud Function](https://cloud.google.com/functions) to remove Mirai+ from:
    - Users with incomplete/late payments
    - Users with cancelled subscriptions (where period has ended)

#### Research:
- Privacy configurations of various social medias
  - Facebook: Setup Wizard
  - Instagram: Data Export (by Jason)
  - Twitter: Follower System

- Stripe Payment Gateway
  - Python SDK was not asynchronous
  - cURL was supported
  - An async [httpx](https://www.python-httpx.org) client had to be configured to optimise the process 

- [Cloud Function](https://cloud.google.com/functions) needed for Stripe
  - Periodic removal of Mirai+ privileges
  - Study on Golang syntax and its Stripe SDK
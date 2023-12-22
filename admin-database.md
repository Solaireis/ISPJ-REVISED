## Report Logs

```json
{
    "id": ObjectID("1..."),
    "title": "Spammed",
    "affected": "Someone else",
    "reasons": "They sent something like \"$VALUES$ $$DEALS$ $CHEAP $$49.998 $$REAL$$ $PRICES$ BARGAIN$\"",
    "created_at": datetime.now(),
    "status": (open|close)
    "reported_user_id": ObjectID("1..."), 
    "reported_username": "user1",
    "reported_by": "fakereporter",
    "report_by_id": ObjectID("1..."),
}
```

## Ban Logs (not added yet)

```json
{
    "user_id": _id,
    "username": user_doc["username"],
    "reason": reason,
    "done_by": rbac_res.user_doc["username"],
    "done_at": datetime.now(),
    "banned_type": "unban"
}
```

## Locked Logs (not added yet)

```json
{
    "user_id": _id,
    "username": user_doc["username"],
    "reason": reason,
    "done_by": rbac_res.user_doc["username"],
    "done_at": datetime.now(),
    "locked_type": "lock"
}
```
## Admin Collection

### Admin , Maintenance , Super Root (Place holder for now)

### Privilege hierachy (highest to lowest)

```
|--> Maintenance (root)
|----> Admin 
```

|                            | Admin | Maintenance(root) |
|----------------------------|-------|-------------------|
| Send Direct Messages       | ✗     | ✗                 | 
| See others Profile         | ✓     | ✗                 | 
| Be follower                | ✗     | ✗                 | 
| See Posts                  | ✓     | ✗                 |
| Ban Users                  | ✓     | ✗                 | 
| Create Admin Account       | ✗     | ✓                 | 
| Create Maintenance Account | ✗     | ✗                 | 
| Delete Admin Account       | ✗     | ✓                 | 
| Delete Maintenance Account | ✗     | ✗                 | 
| Delete User Account        | ✓     | ✗                 | 
| Delete Report              | ✓     | ✗                 | 
| Delete Ban                 | ✓     | ✗                 | 

Reason for maintenance and super root
maintenance are more like managers managing the admin accounts, in a company,
these people tend to be managing the services at the backend


```json
{
    "_id": ObjectID("1..."),
    "email": "admin@example.com",
    "username": "User 1",
    "display_name": "user1",
    "verified": true,
    "security": {
        "role": ["user"],
        "secret_totp_token": "...",
        "recovery_codes": ["...", "...", "..."],
        "last_accessed": [
            {
                "ip": "127.0.0.1",
                "date": Date("2022-01-01")
            },
        ]
    },
    "sessions": [
        {"session_id": "uuid4", "expiry": Date("2022-01-03")},
        {"session_id": "uuid5", "expiry": Date("2022-01-04")},
    ],
    "created_at": Date("2022-01-01"),
    "inactive": {
        "status": false,
        "last_updated": Date("2022-01-01"),
    },
}
```

`inactive.status` is used to check if the admin is inactive or not.
It will be set to true if the admin is inactive, and will be set to false if the admin is active.
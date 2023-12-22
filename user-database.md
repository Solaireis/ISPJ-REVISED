# MongoDB Database Design

## Tips

One-to-One - Prefer key value pairs within the document

One-to-Few - Prefer embedding

One-to-Many - Prefer embedding

One-to-Squillions - Prefer Referencing

Many-to-Many - Prefer Referencing

## Users Collection

### Users (Basic and Professional Account)

```json
{
    "_id": ObjectID("1..."),
    "phone_num": Binary("+6512345678"),
    "email": "user@example.com",
    "username": "User 1",
    "display_name": "user1",
    "verified": true,
    "mirai_plus": false,
    "password": Binary("password_hash"),
    "content_moderation": {
        "sexual_images": true,
        "violent_images": true,
        "meme_images": false,
    },
    "profile": {
        "image": {
            "url": "https://api.dicebear.com/5.x/initials/svg?seed=User 1", 
        },
        "banner_image": {
            "url": "https://storage.googleapis.com/mirai-public/blob.webp",
            "blob_name": "blob.webp",
            "bucket": "mirai-public",
        },
        "bio": "I like pancakes!",
        "location": "New York, NY",
        "url": "https://example.com",
    },
    "privacy": {
        "send_direct_messages": "private",
        "be_follower": "request_needed",
        "see_posts": "followers",
        "search_indexed": "followers",
        "profile_location": "public",
        "profile_url": "public",
        "profile_banner": "public",
        "last_updated": 1671875292.9930356,
    },
    "blocked_users": [
        ObjectID("1..."), ObjectID("2..."), ObjectID("3..."), ...
    ],
    "social": {
        "followers": [ObjectID("1..."), ObjectID("2..."), ObjectID("3..."), ...],
        "following": [ObjectID("1..."), ...],
        "pending":   [ObjectID("2..."), ...],
        "requests":  [ObjectID("3..."), ...],
    },
    "security": {
        "role": ["user", "pro"],
        "sms_2fa": true,
        "sms_code": {
            "code": "123456",
            "created_at": 1671875292.9930356,
            "expiry": 1671875692.9930356,
        },
        "backup_code": Binary("..."),
        "secret_totp_token": Binary("..."),
        "last_login": 1671875292.9930356,
        "last_accessed": [
            {
                "location": "Singapore, SG",
                "datetime": 1671875292.9930356,
            },
        ],
        "email_tokens": ["4qpIbofF9xbbzTAT"],
        "exported_data": {
            "requested_at": 1671875292.9930356,
            "task_name": "projects/ispj-mirai/locations/asia-southeast1/queues/export-user/tasks/4746893477261137613",
        },
    },
    "oauth2": [
        "google", 
        "facebook",
    ],
    "sessions": [
        {
            "session_id": "random_string", 
            "expiry": Date("2022-01-03"),
            "browser": "Chrome",
            "os_name": "Windows 10",
            "location": "New York, US",
            "remember_chat": true,
            "ip_address": "10.10.10.100",
            "user_agent": "user_agent",
        },
        {
            "session_id": "random_string",
            "expiry": Date("2022-01-20"),
            "browser": "Mobile Safari",
            "os_name": "iOS 5.1",
            "location": "Singapore, SG",
            "ip_address": "20.20.20.100",
            "user_agent": "user_agent",
        },
    ],
    "posts": [
        ObjectID("1..."), 
        ObjectID("2...")
    ],
    "chat": {
        "online": false,
        "message_timer": 60,
        "hide_online_status": false,
        "password_protection": Binary(...),",
        "authenticated": [
            ObjectID("1..."), 
            ObjectID("2..."),
        ],
    },
    "created_at": Date("2022-01-01"),
    "banned": false,
}
```

For the `sessions.remember_chat`, the user would be able to view the chat without entering the password every time the user views the chat for the current session.

The session also has a `ip_address` field for the user to see the IP address of the session and revoke the unauthorised session if the user suspects that their account has been compromised.

The `user_agent` field is to reduce the risk of a session hijacking.

#### Privacy:

> See "src\app\schemas\permissions.py"

|                      | "public" | "followers" | "disabled" |  "close_friends" |
|:---------------------|:--------:|:-----------:|:----------:|:----------------:|
| Send Direct Messages | ☑        | ☑          | ☑         | ☑                |
| Profile-Related      | ☑        | ☑          |            |                  |
| Be follower          | inherits  | inherits   |            |                  |
| See Posts            | inherits  | inherits   |            | ☑               |

`Be follower` and `See Posts` inherits from `See Profile`.

`close_friends` is a low priority feature.



For chat message_timer, it is the time in seconds before the chat message is deleted. (disappearing messages)

For images, we might use dicebear API again.
For friends_only, default is false

## Chats

Below is an example of a text message
```json
{
    "_id": ObjectID("1..."),
    "message": Binary("Message Text Content"),
    "sender": ObjectID("1..."),
    "receiver": ObjectID("2..."),
    "timestamp": 1671875292.9930356,
    "type": "text",
    "read": false,
    "expiry": 1671875293.9930356,
}
```

Below is an example of a file message

```json
{
    "_id": bson.ObjectId(),
    "sender": bson.ObjectId(),
    "type": "file",
    "receiver": bson.ObjectId(),
    "timestamp": 1671875292.9930356,
    "message": "Message Text Content",
    "expiry": null,
    "read": false,
    "files": [
        {
            "blob_id": bson.ObjectId(),
            "type": "image/png",
            "filename": "example.png",
            "file_size": 1024,
            "spoiler": false,
            "treat_image_as_file": false,
            "bucket_name": "ispj-confidential",
            "blob_name": "chat/sender_id/random_id/filename",
            "compressed_blob_name": "chat/sender_id/random_id/filename",
            "safe_search_annotation": {
                "adult": "VERY_UNLIKELY",
                "spoof": "UNLIKELY",
                "medical": "POSSIBLE",
                "violence": "LIKELY",
                "racy": "VERY_LIKELY",
            },
        },
    ]
}
```

`treat_image_as_file` is to mitigate image decompression bomb attacks (DoS) which can lag the client's browser which affects availability of the user's chat messages. The check is done server-side using the [PIL](https://pypi.org/project/Pillow/) Python library.

`compressed_blob_name` is the blob name to the compressed version of the file. 
So far, only images are compressed and is done server-side using the [PIL](https://pypi.org/project/Pillow/) Python library.

Safe search annotation is from Google Cloud Vision API:

[https://cloud.google.com/vision/docs/reference/rest/v1/AnnotateImageResponse#Likelihood](https://cloud.google.com/vision/docs/reference/rest/v1/AnnotateImageResponse#Likelihood)

The meaning of each safe search annotation:

[https://developers.google.com/resources/api-libraries/documentation/vision/v1/csharp/latest/classGoogle_1_1Apis_1_1Vision_1_1v1_1_1Data_1_1SafeSearchAnnotation.html](https://developers.google.com/resources/api-libraries/documentation/vision/v1/csharp/latest/classGoogle_1_1Apis_1_1Vision_1_1v1_1_1Data_1_1SafeSearchAnnotation.html)

## Deleted Chats

```json
{
    "_id": ObjectID("1..."),
    "sender": ObjectID("1..."),
    "deleted_at": Date("2022-01-01"),
}
```

`_id` is actually the chat message `_id`.

## File Analysis

```json
{
    "_id": ObjectID("1..."),
    "identifier": "sha3-256_hash | url",
    "malicious": null,
    "safe_search_annotations": {
        "adult": "VERY_UNLIKELY",
        "spoof": "UNLIKELY",
        "medical": "POSSIBLE",
        "violence": "LIKELY",
        "racy": "VERY_LIKELY",
    },
    "contains_passport": false,
    "contain_sensitive_data": false,
    "created_at": Date("2022-01-01"),
}
```

Either `url` or `file_hash` must be provided.

This is to optimise the file analysis process. If the file has been analysed before, we can just retrieve the analysis result from the database instead of sending the file to Google Cloud Vision API or VirusTotal again.

`malicious` is true if the file is malicious using VirusTotal API, if null, the file has not been analysed yet.

`contain_sensitive_data` is true if the image/PDF file contains sensitive data using Google Cloud Vision API.

`safe_search_annotations` is the safe search annotations for the image/PDF file using Google Cloud Vision API.

## Posts

```json
{
    "_id": ObjectID("1..."),
    "description": "Post Text Content",
    "images": [
        {
            "blob_id": ObjectID("1..."),
            "type": "image/png",
            "bucket_name": "ispj-public",
            "blob_name": "posts/post_id/image_id.png",
            "filename": "image.png",
            "file_size": 1024,
            "safe_search_annotations": {
                "adult": "VERY_UNLIKELY",
                "spoof": "UNLIKELY",
                "medical": "POSSIBLE",
                "violence": "LIKELY",
                "racy": "VERY_LIKELY",
            },
            "spoiler": false,
            "treat_image_as_file": false,
            "compressed_blob_name": "posts/post_id/image_id.png",
        },
    ],
    "user_id": ObjectID("1..."),
    "likes": [
        ObjectID("1..."), 
        ObjectID("2...")
    ],
    "created_at": Date("2022-01-01"),
}
```

## Comments
```json
{
    "_id": ObjectID("1..."),
    "post_id": ObjectID("1..."),
    "description": "Post Text Content",
    // "images": [
    //     {
    //         "blob_id": ObjectID("1..."),
    //         "type": "image/png",
    //         "bucket_name": "ispj-public",
    //         "blob_name": "posts/post_id/image_id.png",
    //         "filename": "image.png",
    //         "file_size": 1024,
    //         "safe_search_annotations": {
    //             "adult": "VERY_UNLIKELY",
    //             "spoof": "UNLIKELY",
    //             "medical": "POSSIBLE",
    //             "violence": "LIKELY",
    //             "racy": "VERY_LIKELY",
    //         },
    //         "spoiler": false,
    //         "treat_image_as_file": false,
    //         "compressed_blob_name": "posts/post_id/image_id.png",
    //     },
    // ],
    "user_id": ObjectID("1..."),
    // "likes": [
    //     ObjectID("1..."), 
    //     ObjectID("2...")
    // ],
    "created_at": Date("2022-01-01"),
}
```

## Upload Ids

```json
{
    "_id": ObjectID("1..."),
    "purpose": "chat",
    "created_at": Date("2022-12-24T13:30:16.466+00:00"),
    "created_by": ObjectID("6..."),
    "bucket_name": "mirai-confidential",
    "message": "Message Text Content",
    "number_of_files": 3,
    "files": [
        {
            "upload_url": "https://mirai-confidential.storage.googleapis.com/folder%2Fblob.png?upload_id=<gcp_upload_id>",
            "blob_name": "folder/blob.png",
            "mimetype": "image/png",
        },
    ],
    "uploaded_files": [
        {
            "blob_id": bson.ObjectId(),
            "type": "image/png",
            "filename": "example.png",
            "file_size": 1024,
            "spoiler": false,
            "treat_image_as_file": false,
            "bucket_name": "ispj-public",
            "blob_name": "chat/sender_id/random_id/filename",
            "compressed_blob_name": "chat/sender_id/random_id/filename",
            "safe_search_annotation": {
                "adult": "VERY_UNLIKELY",
                "spoof": "UNLIKELY",
                "medical": "POSSIBLE",
                "violence": "LIKELY",
                "racy": "VERY_LIKELY",
            },
        },
    ],
    ... // extra fields depending on the purpose of the upload
}
```

`uploaded_files` is the list of files that have been uploaded to the bucket.

Extra fields for `chat`:
`receiver` - ObjectID of the receiver

Note that the message is also encrypted.

## Notifications

```json
{
    "_id": ObjectID("1..."),
    "user_id": ObjectID("1..."),
    "type": "follow",
    "created_at": Date("2022-01-01"),
    "read": false,
    "partial_message": "has followed you",
    "other_user": ObjectID("1..."),
}
```

```json
{
    "_id": ObjectID("1..."),
    "user_id": ObjectID("1..."),
    "type": "like_post",
    "created_at": Date("2022-01-01"),
    "read": false,
    "partial_message": "has liked your post",
    "post_id": ObjectID("1..."),
    "other_user": ObjectID("1..."),
}
```

A time to live index is created on `created_at` field such that the notification will be automatically deleted after a week.


## Payments

```json
{
    "_id": ObjectID("1..."),
    "user_id": ObjectID("1..."),
    "checkout_session": "cs_test_a1AFjoWL7bTEo492rpLzwc5yHQB5l14YrcreBCsCFNREwZZpzgCVY0B1jk",
    "subscription": "sub_1MZC1qEDzhQbsrhHDfLWSTDk",
    "start_date": Date("2022-01-01"),
    "end_date": None,
})
```
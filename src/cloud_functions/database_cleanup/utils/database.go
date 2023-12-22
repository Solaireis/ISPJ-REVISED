package utils

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"strings"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"google.golang.org/api/iterator"
	"github.com/stripe/stripe-go/v74"
	stripeSub "github.com/stripe/stripe-go/v74/subscription"
)

func GetConnUri(ctx context.Context, getAdminDb bool) (string, error) {
	if DEBUG_MODE {
		return "mongodb://localhost:27017", nil
	}

	if (!getAdminDb) {
		username, err := GetSecretStr("mongodb-user")
		if err != nil {
			return "", err
		}
		password, err := GetSecretStr("mongodb-pass")
		if err != nil {
			return "", err
		}
		return fmt.Sprintf(
			"mongodb+srv://%s:%s@mirai.v8xh4.mongodb.net/?retryWrites=true&w=majority",
			url.QueryEscape(string(username)), url.QueryEscape(string(password)),
		), nil
	} 

	username, err := GetSecretStr("mongodb-admin-user")
	if err != nil {
		return "", err
	}
	password, err := GetSecretStr("mongodb-admin-pass")
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(
		"mongodb+srv://%s:%s@mirai-admin.oi3011m.mongodb.net/?retryWrites=true&w=majority",
		url.QueryEscape(string(username)), url.QueryEscape(string(password)),
	), nil
}

func GetDatabaseClient(ctx context.Context, getAdminDb bool) (*mongo.Database, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	uri, err := GetConnUri(ctx, getAdminDb)
	if err != nil {
		return nil, err
	}

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		log.Println(err)
		return nil, err
	}

	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		log.Println(err)
		return nil, err
	}
	if getAdminDb {
		return client.Database(ADMIN_DB_NAME), nil
	}
	return client.Database(DB_NAME), nil
}

func DeleteUnwantedUserAccounts(ctx context.Context, client*mongo.Database) error {
	userCollection := client.Collection(USER_COLLECTION)
	chatCollection := client.Collection(CHAT_COLLECTION)
	postCollection := client.Collection(POST_COLLECTION)
	commentCollection := client.Collection(COMMENT_COLLECTION)

	// delete unverified users from the collection after 30 days
	// by looking at the `verified` key in the user document and the `created_at` datetime object
	filter := bson.D{{
		Key: "verified", Value: false,
	}, {
		Key: "created_at", Value: bson.D{{
			Key: "$lt", Value: time.Now().UTC().Add(-30 * 24 * time.Hour),
		}},
	}}
	cursor, err := userCollection.Find(ctx, filter)
	if err != nil {
		log.Println(err)
		return err
	}
	userIdsSet := make(map[primitive.ObjectID]struct{}, 0)
	for cursor.Next(ctx) {
		var user bson.M
		err := cursor.Decode(&user)
		if err != nil {
			log.Println(err)
			return err
		}

		userIdsSet[user["_id"].(primitive.ObjectID)] = struct{}{}
	}

	// Delete all users who have not logged in for 2 years
	// by looking at the `security.last_login` datetime object
	filter = bson.D{{
		Key: "security.last_login", Value: bson.D{{
			Key: "$lt", Value: time.Now().UTC().Add(-2 * 365 * 24 * time.Hour),
		}},
	}}
	cursor, err = userCollection.Find(ctx, filter)
	if err != nil {
		log.Println(err)
		return err
	}
	for cursor.Next(ctx) {
		var user bson.M
		err := cursor.Decode(&user)
		if err != nil {
			log.Println(err)
			return err
		}

		userIdsSet[user["_id"].(primitive.ObjectID)] = struct{}{}
	}

	userIds := make([]primitive.ObjectID, len(userIdsSet))
	for userId := range userIdsSet {
		userIds = append(userIds, userId)
	}

	// delete chats from the unwanted
	// users from the chat collection
	_, err = chatCollection.DeleteMany(ctx, bson.D{{
		Key: "$or", Value: bson.A{
			bson.D{{
				Key: "sender", Value: bson.D{{
					Key: "$in", Value: userIds,
				}},
			}},
			bson.D{{
				Key: "receiver", Value: bson.D{{
					Key: "$in", Value: userIds,
				}},
			}},
		},
	}})
	if err != nil {
		log.Println(err)
		return err
	}

	// delete all posts from the unwanted users via the `author_id` key
	// or pull all the user's comments from all the posts without deleting it via `comments.user` key`
	// and pull from the post likes array via `likes` key
	_, err = postCollection.DeleteMany(ctx, bson.D{{
		Key: "author_id", Value: bson.D{{
			Key: "$in", Value: userIds,
		}},
	}})
	if err != nil {
		log.Println(err)
		return err
	}
	_, err = postCollection.UpdateMany(ctx, bson.D{}, bson.D{{
		Key: "$pull", Value: bson.D{{
			Key: "likes", Value: bson.D{{
				Key: "$in", Value: userIds,
			}},
		}},
	}})
	if err != nil {
		log.Println(err)
		return err
	}

	// delete all comments from the unwanted users via the `user_id` key
	_, err = commentCollection.DeleteMany(ctx, bson.D{{
		Key: "user_id", Value: bson.D{{
			Key: "$in", Value: userIds,
		}},
	}})
	if err != nil {
		log.Println(err)
		return err
	}

	// delete all the unwanted users
	_, err = userCollection.DeleteMany(ctx, bson.D{{
		Key: "_id", Value: bson.D{{
			Key: "$in", Value: userIds,
		}},
	}})
	if err != nil {
		log.Println(err)
		return err
	}
	return nil
}

func DeleteInactiveAdmins(ctx context.Context, client *mongo.Database) error {
	adminCollection := client.Collection(ADMIN_COLLECTION)

	// delete admins is inactive for more than 30 days
	_, err := adminCollection.DeleteMany(ctx, bson.D{{
		Key: "$and", Value: bson.A{
			bson.D{{
				Key: "inactive.status", Value: true,
			}},
			bson.D{{
				Key: "inactive.last_updated", Value: bson.D{{
					Key: "$lt", Value: time.Now().UTC().Add(-30 * 24 * time.Hour),
				}},
			}},
		},
	}})
	if err != nil {
		log.Println(err)
		return err
	}
	return nil
}

func RemoveExpiredSession(ctx context.Context, client *mongo.Database) error {
	collection := client.Collection(USER_COLLECTION)

	// pull expired sessions from the
	// array without deleting the whole user document
	update := bson.D{{
		Key: "$pull", Value: bson.D{{
			Key: "sessions", Value: bson.D{{
				Key: "expiry_date", Value: bson.D{{
					Key: "$lt", Value: time.Now().UTC(),
				}},
			}},
		}},
	}}
	_, err := collection.UpdateMany(ctx, bson.D{}, update)
	if err != nil {
		log.Println(err)
		return err
	}
	return nil
}

type UploadDoc struct {
	Id         string    `bson:"_id"`
	UploadUrl  string    `bson:"upload_url"`
	CreatedAt  time.Time `bson:"created_at"`
	CreatedBy  string    `bson:"created_by"`
	BucketName string    `bson:"bucket_name"`
	BlobName   string    `bson:"blob_name"`
	Mimetype   string    `bson:"mimetype"`
}
func RemoveExpiredUploadIds(ctx context.Context, client *mongo.Database) error {
	collection := client.Collection(UPLOAD_IDS_COLLECTION)

	// delete expired upload ids from the collection
	// if the difference between the current time and the created_at time is greater than 1 hr
	filter := bson.D{{
		Key: "created_at", Value: bson.D{{
			Key: "$lt", Value: time.Now().UTC().Add(-1 * time.Hour),
		}},
	}}
	cursor, err := collection.Find(ctx, filter)
	if err != nil {
		log.Println(err)
		return err
	}

	gcsClient, err := GetStorageClient(ctx)
	if err != nil {
		return err
	}
	for cursor.Next(ctx) {
		var uploadId UploadDoc
		err := cursor.Decode(&uploadId)
		if err != nil {
			log.Println(err)
			return err
		}

		// delete the file from the bucket
		go func(bucket, blob string) {
			gcsClient.DeleteFile(ctx, bucket, blob)
		}(uploadId.BucketName, uploadId.BlobName)
	}

	// delete the upload id from the collection
	_, err = collection.DeleteMany(ctx, filter)
	if err != nil {
		log.Println(err)
		return err
	}
	return nil
}

func DeleteExpiredEmailTokens(ctx context.Context, client *mongo.Database) error {
	collection := client.Collection(USER_COLLECTION)

	// pull expired email tokens from the `security.email_tokens` array
	// without deleting the whole user document
	update := bson.D{{
		Key: "$pull", Value: bson.D{{
			Key: "security.email_tokens", Value: bson.D{{
				Key: "expiry", Value: bson.D{{
					Key: "$lt", Value: time.Now().UTC(),
				}},
			}},
		}},
	}}
	_, err := collection.UpdateMany(ctx, bson.D{}, update)
	if err != nil {
		log.Println(err)
		return err
	}
	return nil
}

func DeleteUnusedSMSTokens(ctx context.Context, client *mongo.Database) error {
	collection := client.Collection(USER_COLLECTION)

	// delete the `security.sms_code` object if the
	// `security.sms_code.expiry` is less than the current time
	filter := bson.D{{
		Key: "security.sms_code.expiry", Value: bson.D{{
			Key: "$lt", Value: time.Now().UTC(),
		}},
	}}

	// Unset the `security.sms_code` object
	_, err := collection.UpdateMany(ctx, filter, bson.D{{
		Key: "$unset", Value: bson.D{{
			Key: "security.sms_code", Value: "",
		}},
	}})
	if err != nil {
		log.Println(err)
		return err
	}
	return nil
}

func SetChatStatusToOffline(ctx context.Context, client *mongo.Database) error {
	collection := client.Collection(USER_COLLECTION)

	// set the status of all chats to offline
	// chat.online = false
	update := bson.D{{
		Key: "$set", Value: bson.D{{
			Key: "chat.online", Value: false,
		}},
	}}
	_, err := collection.UpdateMany(ctx, bson.D{}, update)
	if err != nil {
		log.Println(err)
		return err
	}
	return nil
}

func DeleteOrphanComments(ctx context.Context, client *mongo.Database) error {
	commentCollection := client.Collection(COMMENT_COLLECTION)
	postCollection := client.Collection(POST_COLLECTION)

	// delete all comments with no parent
	var affectedComments []primitive.ObjectID
	postExistsTable := map[primitive.ObjectID]bool{}
	cursor, err := commentCollection.Find(ctx, bson.D{})
	if err != nil {
		log.Println(err)
		return err
	}

	for cursor.Next(ctx) {
		var comment bson.M
		err := cursor.Decode(&comment)
		if err != nil {
			log.Println(err)
			return err
		}

		// get the parent post id
		commentPostId := comment["post_id"].(primitive.ObjectID)
		if _, ok := postExistsTable[commentPostId]; !ok {
			// check if the post exists
			filter := bson.D{{
				Key: "_id", Value: commentPostId,
			}}
			options := options.FindOne()
			options.SetProjection(bson.D{{
				Key: "_id", Value: 1,
			}})

			var postDoc bson.M
			err = postCollection.FindOne(ctx, filter, options).Decode(&postDoc)
			if err == mongo.ErrNoDocuments {
				// if the post does not exist, add the comment id to the affected comments
				affectedComments = append(affectedComments, comment["_id"].(primitive.ObjectID))
				postExistsTable[commentPostId] = false
			} else {
				postExistsTable[commentPostId] = true
			}
		} else if !postExistsTable[commentPostId] {
			affectedComments = append(affectedComments, comment["_id"].(primitive.ObjectID))
		}
	}

	// delete all affected comments
	if len(affectedComments) > 0 {
		filter := bson.D{{
			Key: "_id", Value: bson.D{{
				Key: "$in", Value: affectedComments,
			}},
		}}
		_, err = commentCollection.DeleteMany(ctx, filter)
		if err != nil {
			log.Println(err)
			return err
		}
	}
	return nil
}

func DeleteExpiredChats(ctx context.Context, client *mongo.Database) error {
	chatCollection := client.Collection(CHAT_COLLECTION)

	// creates a filter to find all expired `expiry` int timestamp
	// chat.expiry < current time and if chat.expiry is not null
	filter := bson.D{{
		Key: "expiry", Value: bson.D{{
			Key: "$lt", Value: time.Now().UTC().Unix(),
		}},
	}, {
		Key: "expiry", Value: bson.M{"$ne": nil},
	}}
	cursor, err := chatCollection.Find(ctx, filter)
	if err != nil {
		log.Println(err)
		return err
	}

	gcsClient, err := GetStorageClient(ctx)
	if err != nil {
		return err
	}
	defer gcsClient.Client.Close()
	for cursor.Next(ctx) {
		var chat bson.M
		err := cursor.Decode(&chat)
		if err != nil {
			log.Println(err)
			return err
		}

		// if the message type is not text, remove the file from the bucket
		if chat["type"].(string) != "text" {
			go func(bucket, blob string) {
				gcsClient.DeleteFile(ctx, bucket, blob)
			}(PRIVATE_BUCKET, chat["message"].(string))
		}
	}

	// delete the expired chats from the `chats` collection
	_, err = chatCollection.DeleteMany(ctx, filter)
	if err != nil {
		log.Println(err)
		return err
	}
	return nil
}

func DeleteBlobIfNotInDb(
	ctx context.Context, 
	blobName, 
	blobPrefix,
	dbKey string,
	chatCollection *mongo.Collection,
	postCollection *mongo.Collection, 
	gcsClient *GCSClient,
) {
	var err error
	var bucketName string
	options := options.FindOne()
	options.SetProjection(bson.D{{
		Key: "_id", Value: 1,
	}})
	if strings.HasPrefix(blobName, "chat/") {
		// check if the file is in the database
		var filter bson.D
		if strings.Contains(blobName, "/compressed/") {
			// by checking if the compressed_message == blobName and type != "text"
			filter = bson.D{{
				Key: "files.compressed_blob_name", Value: blobName,
			}, {
				Key: "type", Value: bson.D{{
					Key: "$ne", Value: "text",
				}},
			}}
		} else {
			// by checking if the message == blobName and type != "text"
			filter = bson.D{{
				Key: "files.blob_name", Value: blobName,
			}, {
				Key: "type", Value: bson.D{{
					Key: "$ne", Value: "text",
				}},
			}}
		}

		bucketName = PRIVATE_BUCKET
		err = chatCollection.FindOne(ctx, filter, options).Decode(&bson.M{})
	} else if strings.HasPrefix(blobName, "post/") {
		var filter bson.D
		if strings.Contains(blobName, "/compressed/") {
			// by checking if the compressed_message == blobName
			filter = bson.D{{
				Key: "images.compressed_blob_name", Value: blobName,
			}}
		} else {
			// by checking if the message == blobName
			filter = bson.D{{
				Key: "$or", Value: bson.A{
					bson.D{{
						Key: "images.blob_name", Value: blobName,
					}},
					bson.D{{
						Key: "video.blob_name", Value: blobName,
					}},
				},
			}}
		}

		bucketName = PRIVATE_BUCKET
		err = postCollection.FindOne(ctx, filter, options).Decode(&bson.M{})
	} else {
		return
	}

	if err == mongo.ErrNoDocuments {
		// delete the file
		log.Printf("Deleting %s from %s", blobName, bucketName)
		gcsClient.DeleteFile(ctx, bucketName, blobName)
	}
}

func DeleteFilesNotInDB(ctx context.Context, client *mongo.Database) error {
	gcsClient, err := GetStorageClient(ctx)
	if err != nil {
		return err
	}
	defer gcsClient.Client.Close()

	chatCollection := client.Collection(CHAT_COLLECTION)
	postCollection := client.Collection(POST_COLLECTION)

	// Get a handle to the bucket.
	bucket := gcsClient.Client.Bucket(PRIVATE_BUCKET)

	// Iterate through the objects in the bucket.
	var wg sync.WaitGroup
	it := bucket.Objects(ctx, nil)
	for {
		obj, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			err = fmt.Errorf("iterator.Next: %v", err)
			if DEBUG_MODE {
				log.Println(err)
			}
			return err
		}

		wg.Add(1)
		go func(blobName string) {
			defer wg.Done()
			DeleteBlobIfNotInDb(
				ctx,
				blobName,
				"chat/",
				"files",
				chatCollection,
				postCollection,
				gcsClient,
			)
		}(obj.Name)
	}
	wg.Wait()
	return nil
}

type UserSubscription struct {
	userId				string
	subscriptionId		string
}
func CheckExpiredMiraiPlus(ctx context.Context, client *mongo.Database) error {
	// Get Mongo Client
	userCollection := client.Collection(USER_COLLECTION)
	paymentCollection := client.Collection(PAYMENT_COLLECTION)

	// Get Stripe Client
	var key []byte
	var err error
	if DEBUG_MODE {
		key, err = AccessSecretVersion(
			ctx, ConstructName("stripe-secret-key", "latest"),
		)
	} else {
		key, err = GetSecret("stripe-secret-key")
	}
	if err != nil {
		log.Println(err)
		return err
	}
	stripe.Key = string(key)

	// Get a list of expired
	currentTime := time.Now()
	cursor, err := paymentCollection.Find(
		ctx,
		bson.D{{
			Key: "end_date",
			Value: bson.D{
				{Key: "$gte", Value: currentTime},
				{Key: "$lte", Value: currentTime.Add(-2 * time.Hour)}, // 1 hour buffer
			},
		}},
		options.Find().SetProjection(bson.D{
			{Key: "_id",			Value: false},
			{Key: "user_id",		Value: true},
			{Key: "subscription",	Value: true},
		}),
	)
	if err != nil {
		log.Println(err)
		return err
	}

	userIds := make(map[string]UserSubscription)
	for cursor.Next(ctx) {
		var payment bson.M
		err := cursor.Decode(&payment)
		if err != nil {
			log.Println(err)
			return err
		}
		// fmt.Println(payment)
		// fmt.Printf("%T", payment["user_id"])

		subscription := UserSubscription{
			userId: payment["user_id"].(primitive.ObjectID).String(),
			subscriptionId: payment["subscription"].(string),
		}
		userIds[subscription.userId] = subscription
	}
	// fmt.Printf("User IDs: %v\n", userIds)

	// Get a list of cancelled
	result := stripeSub.Search(
		&stripe.SubscriptionSearchParams{
			SearchParams: stripe.SearchParams{
				Query: `
				status:'incomplete' 
				OR status:'past_due' 
				OR metadata['cancelled']:'true'`,
				Limit: stripe.Int64(10),
			},
		},
	)
	for result.Next() {
		subscription := result.Subscription()
		user := UserSubscription{
			userId: subscription.Metadata["user_id"],
			subscriptionId: subscription.ID,
		}
		userIds[user.userId] = user
		// fmt.Printf("User: %v\n", subscription.Metadata)
	}
	if result.Err() != nil {
		log.Println(err)
		return err
	}

	if len(userIds) == 0 {
		return nil
	}

	// Remove mirai plus
	var affectedUsers []primitive.ObjectID
	for _, subscription := range userIds {
		record, err := stripeSub.Get(subscription.subscriptionId, nil)
		if err != nil {
			log.Println(err)
			return err
		}

		// Check if new entry exists
		newSubscription := paymentCollection.FindOne(
			ctx,
			bson.D{{
				Key: "user_id", 
				Value: subscription.userId,
			}, {
				Key: "end_time", 
				Value: nil,
			}},
		)
		if newSubscription.Err() != nil {
			continue
		}
		if record.EndedAt == 0 {
			continue
		}
		if endTime := time.Unix(record.EndedAt, 0); endTime.After(currentTime) {
			continue
		}
		// fmt.Printf("Record: %v", record.ID)

		stripeSub.Cancel(record.ID, nil)
		userIdObjectId, err := primitive.ObjectIDFromHex(subscription.userId)
		if err != nil {
			err = fmt.Errorf("primitive.ObjectIDFromHex: %v", err)
			log.Println(err)
			return err
		}
		affectedUsers = append(affectedUsers, userIdObjectId)
	}

	userCollection.UpdateMany(
		ctx,
		bson.D{{
			Key: "_id", Value: bson.D{{
				Key: "$in", Value: affectedUsers,
			}},
		}, {
			Key: "end_time", Value: bson.D {{
				Key: "$not", Value: nil,
			}},
		}},
		bson.D{{
			Key: "$set", Value: bson.D{{
				Key: "mirai_plus", Value: false,
			}},
		}},
	)
	return nil
}
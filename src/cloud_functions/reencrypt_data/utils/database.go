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
)

func GetConnUri(ctx context.Context) (string, error) {
	if DEBUG_MODE {
		return "mongodb://localhost:27017", nil
	}

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

func GetDatabaseClient(ctx context.Context) (*mongo.Client, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	uri, err := GetConnUri(ctx)
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
	return client, nil
}

func LogAnyErrors(encryptionErrors chan error) error {
	// Check for any errors
	if len(encryptionErrors) > 0 {
		// log all the errors
		for err := range encryptionErrors {
			err = fmt.Errorf("re-encryption Error (chat messages): %v", err)
			if DEBUG_MODE {
				log.Println(err)
			}
		}
		return fmt.Errorf("some errors occurred during re-encryption (chat messages)")
	}
	return nil
}

func ReEncryptChatMsg(ctx context.Context, client *mongo.Client) error {
	collection := client.Database(DB_NAME).Collection(CHAT_COLLECTION)

	// get all the chat messages with the type="text"
	filter := bson.M{"type": "text"}
	counts, err := collection.CountDocuments(ctx, filter)
	if err != nil {
		log.Println(err)
		return err
	}

	// get a cursor to loop through the chat messages
	cursor, err := collection.Find(ctx, filter)
	if err != nil {
		log.Println(err)
		return err
	}

	kmsClient, err := GetKMSClient(ctx)
	if err != nil {
		return err
	}

	// Create a wait group to track when all goroutines have completed
	var databaseLock sync.Mutex
	var wg sync.WaitGroup
	queue := make(chan struct{}, MAX_CONCURRENCY)
	encryptionErrors := make(chan error, counts)
	// loop through the chat messages
	for cursor.Next(ctx) {
		var chatMsg bson.M
		err := cursor.Decode(&chatMsg)
		if err != nil {
			log.Println(err)
			return err
		}

		wg.Add(1)
		queue <- struct{}{}
		// re-encrypt the message
		go func(chatMsg bson.M) {
			defer func() {
				<-queue
			}()
			defer wg.Done()

			if len(encryptionErrors) > 0 {
				// If there is an error,
				// stop processing the rest of the messages
				return
			}

			reEncrypteChatMsg, err := SymmetricReEncryptData(
				kmsClient,
				ctx,
				SymmetricConstructName(KEYRING, DATABASE_KEY),
				chatMsg["message"].(primitive.Binary).Data,
			)
			if err != nil {
				encryptionErrors <- err
				return
			}

			// update the message
			databaseLock.Lock()
			defer databaseLock.Unlock()
			_, err = collection.UpdateOne(ctx, bson.D{{
				Key: "_id", Value: chatMsg["_id"].(primitive.ObjectID),
			}}, bson.D{{
				Key: "$set", Value: bson.D{{
					Key: "message", Value: reEncrypteChatMsg,
				}},
			}})
			if err != nil {
				encryptionErrors <- err
				return
			}
		}(chatMsg)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	close(encryptionErrors)
	return LogAnyErrors(encryptionErrors)
}

func ReEncryptUserDoc(ctx context.Context, client *mongo.Client) error {
	collection := client.Database(DB_NAME).Collection(USER_COLLECTION)

	// Get all the user documents
	counts, err := collection.CountDocuments(ctx, bson.M{})
	if err != nil {
		log.Println(err)
		return err
	}

	// Get a cursor for all the user documents
	cursor, err := collection.Find(ctx, bson.M{})
	if err != nil {
		log.Println(err)
		return err
	}

	kmsClient, err := GetKMSClient(ctx)
	if err != nil {
		log.Println(err)
		return err
	}

	// Create a wait group to track when all goroutines have completed
	var databaseLock sync.Mutex
	var wg sync.WaitGroup
	queue := make(chan struct{}, MAX_CONCURRENCY)
	encryptionErrors := make(chan error, counts)

	// loop through the user documents
	for cursor.Next(ctx) {
		var userDoc bson.M
		err := cursor.Decode(&userDoc)
		if err != nil {
			log.Println(err)
			return err
		}

		wg.Add(1)
		queue <- struct{}{}
		// re-encrypt the user document
		go func(userDoc bson.M) {
			defer func() {
				<-queue
			}()
			defer wg.Done()

			// re-encrypt the user document
			toReEncrypt := map[string][]byte{
				"phone_num":                  nil,
				"password":                   nil,
				"chat.password_protection":   nil,
				"security.backup_code":       nil,
				"security.secret_totp_token": nil,
			}
			for key := range toReEncrypt {
				if len(encryptionErrors) > 0 {
					// If there is an error,
					// stop processing the rest of the documents
					return
				}

				var reEncryptedVal []byte
				if strings.Contains(key, ".") {
					// nested key
					keys := strings.Split(key, ".")
					if encryptedData, ok := userDoc[keys[0]].(primitive.M)[keys[1]].(primitive.Binary); ok {
						reEncryptedVal, err = SymmetricReEncryptData(
							kmsClient,
							ctx,
							SymmetricConstructName(KEYRING, DATABASE_KEY),
							encryptedData.Data,
						)
						if err != nil {
							encryptionErrors <- err
							return
						}
					}
				} else if encryptedData, ok := userDoc[key].(primitive.Binary); ok {
					reEncryptedVal, err = SymmetricReEncryptData(
						kmsClient,
						ctx,
						SymmetricConstructName(KEYRING, DATABASE_KEY),
						encryptedData.Data,
					)
					if err != nil {
						encryptionErrors <- err
						return
					}
				}

				if reEncryptedVal == nil {
					continue
				}

				toReEncrypt[key] = reEncryptedVal
			}

			// Update the user document
			databaseLock.Lock()
			defer databaseLock.Unlock()
			update := []bson.E{{
				Key: "password", Value: toReEncrypt["password"],
			}}
			for key := range toReEncrypt {
				if key != "password" && toReEncrypt[key] != nil {
					update = append(update, bson.E{
						Key: key, Value: toReEncrypt[key],
					})
				}
			}

			filter := bson.D{{
				Key: "_id", Value: userDoc["_id"].(primitive.ObjectID),
			}}
			_, err = collection.UpdateOne(ctx, filter, bson.D{{
				Key: "$set", Value: update,
			}})
			if err != nil {
				encryptionErrors <- err
				return
			}
		}(userDoc)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	close(encryptionErrors)
	return LogAnyErrors(encryptionErrors)
}

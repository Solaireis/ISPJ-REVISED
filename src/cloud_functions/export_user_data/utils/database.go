package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
	"strconv"
	"strings"

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
	connUri, err := GetConnUri(ctx)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(connUri))
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

func GetUserDocById(ctx context.Context, collection *mongo.Collection, userId string) (bson.M, error) {
	userObjId, err := primitive.ObjectIDFromHex(userId)
	if err != nil {
		log.Println("Invalid user id")
		log.Println(err)
		return nil, err
	}

	// get user document
	var userDoc bson.M
	filter := bson.D{
		{Key: "_id", Value: userObjId},
	}
	err = collection.FindOne(ctx, filter).Decode(&userDoc)
	if err == mongo.ErrNoDocuments {
		log.Println("User not found")
		return nil, err
	} else if err != nil {
		log.Println("Error querying user data")
		log.Println(err)
		return nil, err
	}

	return userDoc, nil
}

var userDocCache = make(map[string]bson.M)
// GetUserDoc returns the user document from the cache if it exists, otherwise it gets it from the database
func GetUserDoc(ctx context.Context, collection *mongo.Collection, userId string) (bson.M, error) {
	// check if the other user's username is in the cache
	if _, ok := userDocCache[userId]; !ok {
		// get the other user's username from the database if not in the cache
		otherUserDoc, err := GetUserDocById(ctx, collection, userId)
		if err != nil {
			err = fmt.Errorf("error getting user doc (%s): %v", userId, err)
			log.Println(err)
			return nil, err
		}
		userDocCache[userId] = otherUserDoc
	}
	return userDocCache[userId], nil
}

type UserData struct {
	UserDoc bson.M
	ChatMessages []bson.M
	Posts []bson.M
	Comments []bson.M
}
func QueryAllUserData(ctx context.Context, userId string) (*UserData, error) {
	client, err := GetDatabaseClient(ctx)
	if err != nil {
		return &UserData{}, err
	}
	defer client.Disconnect(ctx)

	userObjId, err := primitive.ObjectIDFromHex(userId)
	if err != nil {
		log.Println(err)
		return &UserData{}, err
	}

	// get user document
	userDoc, err := GetUserDocById(ctx, client.Database(DB_NAME).Collection(USER_COLLECTION), userId)
	if err != nil {
		// usually when the user is not found
		return &UserData{}, err
	}
	userDocCache[userId] = userDoc

	// get user's chat messages
	collection := client.Database(DB_NAME).Collection(CHAT_COLLECTION)
	filter := bson.D{
		{Key: "$or", Value: bson.A{
			bson.D{{Key: "sender", Value: userObjId}},
			bson.D{{Key: "receiver", Value: userObjId}},
		}},
	}
	cursor, err := collection.Find(ctx, filter)
	if err != nil {
		log.Println(err)
		return &UserData{}, err
	}
	var chatMessages []bson.M
	if err = cursor.All(ctx, &chatMessages); err != nil {
		log.Println(err)
		return &UserData{}, err
	}

	// get user's posts
	collection = client.Database(DB_NAME).Collection(POST_COLLECTION)
	filter = bson.D{{Key: "user_id", Value: userObjId}}
	cursor, err = collection.Find(ctx, filter)
	if err != nil {
		log.Println(err)
		return &UserData{}, err
	}
	var posts []bson.M
	if err = cursor.All(ctx, &posts); err != nil {
		log.Println(err)
		return &UserData{}, err
	}

	// get user's comments
	collection = client.Database(DB_NAME).Collection(COMMENT_COLLECTION)
	filter = bson.D{{Key: "user_id", Value: userObjId}}
	cursor, err = collection.Find(ctx, filter)
	if err != nil {
		log.Println(err)
		return &UserData{}, err
	}
	var comments []bson.M
	if err = cursor.All(ctx, &comments); err != nil {
		log.Println(err)
		return &UserData{}, err
	}

	return &UserData{
		UserDoc: userDoc, 
		ChatMessages: chatMessages,
		Posts: posts, 
		Comments: comments,
	}, nil
}

func ProcessUserDoc(ctx context.Context, userDoc bson.M, gcsClient *GCSService) error {
	ksmClient, err := GetKMSClient(ctx)
	if err != nil {
		return err
	}
	defer ksmClient.Client.Close()

	keyName := SymmetricConstructName(
		KEYRING,
		DATABASE_KEY,
	)

	contentModerationMap := map[string]bool{}
	contentModerationObject := userDoc["content_moderation"].(primitive.M)
	for k, v := range contentModerationObject {
		contentModerationMap[k] = v.(bool)
	}
	newUserDoc := formattedUserDoc{
		Id: userDoc["_id"].(primitive.ObjectID).Hex(),
		Username: userDoc["username"].(string),
		DisplayName: userDoc["display_name"].(string),
		Email: userDoc["email"].(string),
		MiraiPlus: userDoc["mirai_plus"].(bool),
		ContentModeration: contentModerationMap,
		CreatedAt: userDoc["created_at"].(primitive.DateTime).Time().UTC().Unix(),
	}

	// add oauth2 info
	if userDoc["oauth"] != nil {
		oauth2Info := userDoc["oauth"].(primitive.A)
		var oauth2 []string
		for _, v := range oauth2Info {
			oauth2 = append(oauth2, v.(string))
		}
		newUserDoc.Oauth = oauth2
	}

	USER_FOLDER_PATH :=  filepath.Join(
		GetUserDataRootPathFromDoc(userDoc), 
		USER_DATA_FOLDER, 
		USER_FOLDER,
	)
	// add profile info
	profileMap := userDoc["profile"].(primitive.M)

	// get the profile image info
	profileImageMap := profileMap["image"].(primitive.M)
	profileImageUrl := profileImageMap["url"].(string)
	profileImagePath := filepath.Join(USER_FOLDER_PATH, "profile.webp")

	// get the banner image info
	bannerImageMap := profileMap["banner"].(primitive.M)
	bannerImageUrl := bannerImageMap["url"].(string)
	bannerImagePath := filepath.Join(USER_FOLDER_PATH, "banner.webp")

	// download the profile image
	var profileDlErr, bannerDlErr error
	if profileImageMap["blob_name"] != nil && profileImageMap["bucket_name"] != nil {
		bucketName := profileImageMap["bucket_name"].(string)
		blobName := profileImageMap["blob_name"].(string)
		profileDlErr = gcsClient.DownloadFile(ctx, bucketName, blobName, profileImagePath)
	} else {
		profileDlErr = DownloadURL(profileImageUrl, profileImagePath, nil, nil, nil, true)
	}
	if profileDlErr != nil {
		log.Println(profileDlErr)
		newUserDoc.Profile = profileInfo{
			ImageUrl: profileImageUrl,
		}
	} else {
		newUserDoc.Profile = profileInfo{
			ImageUrl: strings.TrimPrefix(
				profileImagePath, 
				filepath.Join(
					GetUserDataRootPathFromDoc(userDoc),
					USER_DATA_FOLDER,
				),
			),
		}
	}

	// download the banner image
	if bannerImageMap["blob_name"] != nil && bannerImageMap["bucket_name"] != nil {
		bucketName := bannerImageMap["bucket_name"].(string)
		blobName := bannerImageMap["blob_name"].(string)
		bannerDlErr = gcsClient.DownloadFile(ctx, bucketName, blobName, bannerImagePath)
	} else {
		bannerDlErr = DownloadURL(bannerImageUrl, bannerImagePath, nil, nil, nil, true)
	}
	if bannerDlErr != nil {
		log.Println(bannerDlErr)
		newUserDoc.Profile.BannerUrl = bannerImageUrl
	} else {	
		newUserDoc.Profile.BannerUrl = strings.TrimPrefix(
			bannerImagePath, 
			filepath.Join(
				GetUserDataRootPathFromDoc(userDoc),
				USER_DATA_FOLDER,
			),
		)
	}

	if profileMap["bio"] != nil {
		newUserDoc.Profile.Bio = profileMap["bio"].(string)
	}
	if profileMap["location"] != nil {
		newUserDoc.Profile.Location = profileMap["location"].(string)
	}
	if profileMap["url"] != nil {
		newUserDoc.Profile.Url = profileMap["url"].(string)
	}

	// add sessions info
	if userDoc["sessions"] != nil {
		sessionsInfo := userDoc["sessions"].(primitive.A)
		var sessions []sessionInfo
		for _, value := range sessionsInfo {
			sessionMap := value.(primitive.M)
			sessionId := sessionMap["session_id"].(string)
			// partial mask the session id
			sessionId = strings.Repeat("*", len(sessionId)-5) + sessionId[len(sessionId)-5:]
			sessions = append(sessions, sessionInfo{
				SessionId: sessionId,
				AddedOn: sessionMap["added_on"].(primitive.DateTime).Time().UTC().Unix(),
				ExpiryDate: sessionMap["expiry_date"].(primitive.DateTime).Time().UTC().Unix(),
				IpAddress: sessionMap["ip_address"].(string),
				Browser: sessionMap["browser"].(string),
				Os: sessionMap["os"].(string),
				Location: sessionMap["location"].(string),
				UserAgent: sessionMap["user_agent"].(string),
			})
		}
		newUserDoc.Sessions = sessions
	}

	// add social info
	socialMap := userDoc["social"].(primitive.M)
	newUserDoc.Social = socialInfo{
		Followers: len(socialMap["followers"].(primitive.A)),
		Following: len(socialMap["following"].(primitive.A)),
		Pending: len(socialMap["pending"].(primitive.A)),
		Requests: len(socialMap["requests"].(primitive.A)),
	}

	// add privacy info
	privacyMap := userDoc["privacy"].(primitive.M)
	newUserDoc.Privacy = privacyInfo{
		SendDMs: privacyMap["send_direct_messages"].(string),
		BeFollowers: privacyMap["be_follower"].(string),
		SeePosts: privacyMap["see_posts"].(string),
		SearchIndexed: privacyMap["search_indexed"].(string),
		Profile: profilePrivacy{
			ProfileLocation: privacyMap["profile_location"].(string),
			ProfileUrl: privacyMap["profile_url"].(string),
		},
	}
	if privacyMap["last_updated"] != nil {
		newUserDoc.Privacy.LastUpdated = privacyMap["last_updated"].(primitive.DateTime).Time().UTC().Unix()
	}

	// add security info
	securityMap := userDoc["security"].(primitive.M)
	newUserDoc.Security = securityInfo{
		HasAuth2FA: securityMap["secret_totp_token"] != nil,
		HasSMS2FA: securityMap["sms_2fa"] != nil,
	}
	if securityMap["last_accessed"] != nil {
		lastAccessed := securityMap["last_accessed"].(primitive.A)
		var lastAccessedFormatted []lastAccessedInfo
		for _, value := range lastAccessed {
			lastAccessedMap := value.(primitive.M)
			lastAccessedFormatted = append(lastAccessedFormatted, lastAccessedInfo{
				Location: lastAccessedMap["location"].(string),
				Date: int64(lastAccessedMap["datetime"].(float64) * 1000),
			})
		}
		newUserDoc.Security.LastAccessed = lastAccessedFormatted
	}

	if securityMap["backup_code"] != nil {
		backupCode, err := ksmClient.DecryptSymmetric(ctx, keyName, securityMap["backup_code"].(primitive.Binary).Data)
		if err != nil {
			return err
		}	
		newUserDoc.Security.BackupCode = string(backupCode)
	}

	// add phone number
	if securityMap["phone_num"] != nil {
		phoneNum, err := ksmClient.DecryptSymmetric(ctx, keyName, securityMap["phone_num"].(primitive.Binary).Data)
		if err != nil {
			return err
		}
		newUserDoc.PhoneNum = string(phoneNum)
	}

	// write to file
	userDocJson, err := json.MarshalIndent(newUserDoc, "", "    ")
	if err != nil {
		err = fmt.Errorf("error marshalling user doc: %v", err)
		log.Println(err)
		return err
	}

	err = WriteStrToPath(
		filepath.Join(USER_FOLDER_PATH, fmt.Sprintf("user_%s.json", newUserDoc.Id)),
		string(userDocJson),
		false,
	)
	if err != nil {
		return err
	}
	return nil
}

type formattedChatMessage struct {
	Message           string `json:"message"`
	Type              string `json:"type"` // text or files
	Timestamp         int64 `json:"timestamp"`
	Files             []map[string]string `json:"files"` 
	OtherUserUsername string `json:"-"`
}

// Processes chat messages by decrypting them
// and writes the formatted messages to a JSON file and downloads any chat media
func ProcessChatMessages(ctx context.Context, chatMessages []bson.M, userId string, gcsClient *GCSService) error {
	ksmClient, err := GetKMSClient(ctx)
	if err != nil {
		return err
	}
	defer ksmClient.Client.Close()

	keyName := SymmetricConstructName(
		KEYRING,
		DATABASE_KEY,
	)
	decryptionWg := sync.WaitGroup{}
	queue := make(chan struct{}, 10)
	errChan := make(chan error, len(chatMessages))
	resChan := make(chan bson.M, len(chatMessages))
	for _, chatMessage := range chatMessages {
		decryptionWg.Add(1)
		queue <- struct{}{}
		go func(chatMessage bson.M) {
			defer decryptionWg.Done()
			// the message field can be null
			if chatMessage["message"] != nil {
				decryptedMsg, err := ksmClient.DecryptSymmetric(
					ctx,
					keyName,
					chatMessage["message"].(primitive.Binary).Data,
				)
				if err != nil {
					chatMessage["error"] = err.Error()
					errChan <- err
					<-queue
					return
				}
				chatMessage["message"] = string(decryptedMsg)
			}
			resChan <- chatMessage
			<-queue
		}(chatMessage)
	}
	decryptionWg.Wait()
	close(resChan)
	close(errChan)
	close(queue)

	var errArr []string
	for err := range errChan {
		errArr = append(errArr, fmt.Sprintf("error decrypting chat message: %v", err))
	}
	if len(errArr) > 0 {
		joinedErrors := strings.Join(errArr, "\n")
		log.Println(joinedErrors)
		return fmt.Errorf(joinedErrors)
	}

	// sort chat messages by timestamp in ascending order
	// since the chat messages order is not guaranteed after the decryption
	sort.Slice(chatMessages, func(i, j int) bool {
		return chatMessages[i]["timestamp"].(float64) < chatMessages[j]["timestamp"].(float64)
	})

	// connect to database to get other user's username
	dbClient, err := GetDatabaseClient(ctx)
	if err != nil {
		return err
	}
	defer dbClient.Disconnect(ctx)
	collection := dbClient.Database(DB_NAME).Collection(USER_COLLECTION)

	msgBaseFolder := filepath.Join(
		GetUserDataRootPathFromId(userId),
		USER_DATA_FOLDER, 
		CHATS_FOLDER,
	)
	userObjId, _ := primitive.ObjectIDFromHex(userId)
	formattedChatMessages := make(map[string][]formattedChatMessage)
	downloadQueue := make(chan struct{}, 5)
	errChan = make(chan error, len(chatMessages))
	downloadWg := sync.WaitGroup{}

	for chatMessage := range resChan {
		sender := chatMessage["sender"].(primitive.ObjectID)
		receiver := chatMessage["receiver"].(primitive.ObjectID)

		// To get the other user's username for readability
		var otherUserId, msgPrefix, otherUserUsername string
		if sender == userObjId {
			otherUserId = receiver.Hex()
			msgPrefix = "You: "
		} else {
			otherUserId = sender.Hex()
		}
		otherUserDoc, err := GetUserDoc(ctx, collection, otherUserId)
		if err != nil {
			return err
		}
		otherUserUsername = otherUserDoc["username"].(string)

		if msgPrefix == "" {
			msgPrefix = "@" + otherUserUsername + ": "
		}

		// append the image/attachment/media url to the message
		var files []map[string]string
		if chatMessage["type"].(string) != "text" {
			chatFiles := chatMessage["files"].(primitive.A)
			for _, file := range chatFiles {
				fileMap := file.(primitive.M)
				// add the filePath to the files array
				mimetype := fileMap["type"].(string)
				blobId := fileMap["blob_id"].(primitive.ObjectID).Hex()

				// download the file in a goroutine
				fileFolderName := GetFileSubfolderName(mimetype)

				blobName := fileMap["blob_name"].(string)
				bucketName := fileMap["bucket_name"].(string)
				blobFilePath := filepath.Join(
					msgBaseFolder, 
					otherUserUsername, 
					fileFolderName, 
					fmt.Sprintf("%s_%s", blobId, fileMap["filename"].(string)),
				)
				downloadWg.Add(1)
				go func(blobName, blobFilePath string) {
					defer downloadWg.Done()
					downloadQueue <- struct{}{}
					// download the file
					err := gcsClient.DownloadFile(ctx, bucketName, blobName, blobFilePath)
					if err != nil {
						errChan <- err
					}
					<-downloadQueue
				}(blobName, blobFilePath)

				files = append(files, map[string]string{
					"url": strings.TrimPrefix(
						blobFilePath, 
						filepath.Join(
							GetUserDataRootPathFromId(userId),
							USER_DATA_FOLDER,
						),
					),
					"type": fileMap["type"].(string),
					"file_size": strconv.Itoa(int(fileMap["file_size"].(int32))),
					"mimetype": mimetype,
				})
			}
		}

		// add chat message to the map
		var chatMsgString string
		if chatMessage["message"] != nil {
			chatMsgString = msgPrefix + chatMessage["message"].(string)
		} else {
			// .strip() in python in golang
			chatMsgString = strings.TrimSpace(msgPrefix)
		}

		formattedChatMessages[otherUserId] = append(formattedChatMessages[otherUserId], formattedChatMessage{
			Message:   chatMsgString,
			Type:      chatMessage["type"].(string),
			Timestamp: int64(chatMessage["timestamp"].(float64) * 1000),
			Files:     files,
			OtherUserUsername: otherUserUsername,
		})
	}
	downloadWg.Wait()
	close(downloadQueue)
	close(errChan)

	if len(errChan) > 0 {
		for err := range errChan {
			log.Println(err)
		}
		return fmt.Errorf("error downloading %d chat files out of %d", len(errChan), len(chatMessages))
	}

	// write the chat messages to the file
	for otherUserId := range formattedChatMessages {
		chatMessageArr := formattedChatMessages[otherUserId]
		if len(chatMessageArr) == 0 {
			// should never happen but just in case
			continue
		}

		chatMessagesFile := filepath.Join(msgBaseFolder, chatMessageArr[0].OtherUserUsername, CHAT_MESSAGES_FILE)
		// create the file if it doesn't exist
		os.MkdirAll(filepath.Dir(chatMessagesFile), 0666)

		messages, err := json.MarshalIndent(chatMessageArr, "", "    ")
		if err != nil {
			err = fmt.Errorf("error marshalling chat messages: %v", err)
			log.Println(err)
			return err
		}

		err = WriteStrToPath(
			chatMessagesFile,
			string(messages),
			false,
		)
		if err != nil {
			return err
		}
	}
	return nil
}

type PostComment struct {
	PostId string                   `json:"post_id"`
	JsonFilePath string             `json:"-"`
	Timestamp int64                 `json:"timestamp"`
	Text string                     `json:"text"`
}
func ProcessComments(ctx context.Context, comments[]bson.M, userDoc bson.M) error {
	var formattedComments []PostComment
	commentBaseFolder := filepath.Join(
		GetUserDataRootPathFromDoc(userDoc), 
		USER_DATA_FOLDER, 
		COMMENTS_FOLDER,
	)

	for _, comment := range comments {
		var formattedComment PostComment
		formattedComment.PostId = comment["post_id"].(primitive.ObjectID).Hex()
		timestamp := comment["timestamp"].(primitive.DateTime).Time()
		formattedComment.Timestamp = timestamp.UTC().Unix()
		formattedComment.JsonFilePath = filepath.Join(
			commentBaseFolder, 
			timestamp.Format("2006-01-02"), 
			fmt.Sprintf("%s.json", comment["_id"].(primitive.ObjectID).Hex()),
		)
		formattedComment.Text = comment["description"].(string)
		formattedComments = append(formattedComments, formattedComment)
	}

	// write the posts to the file
	for _, comment := range formattedComments {
		os.MkdirAll(filepath.Dir(comment.JsonFilePath), 0666)

		commentJson, err := json.MarshalIndent(comment, "", "    ")
		if err != nil {
			err = fmt.Errorf("error marshalling comment json: %s", err.Error())
			log.Println(err)
			return err
		}

		err = WriteStrToPath(
			comment.JsonFilePath,
			string(commentJson),
			false,
		)
		if err != nil {
			return err
		}
	}

	return nil
}

type UserPost struct {
	PostId string                `json:"post_id"`
	Timestamp int64              `json:"timestamp"`
	PostFolderPath string        `json:"-"`
	Text string                  `json:"text,omitempty"`
	Images []map[string]string   `json:"images,omitempty"`
	Video map[string]string      `json:"video,omitempty"`
}
func ProcessPosts(ctx context.Context, userId string, posts[]bson.M, gcsClient *GCSService) error {
	var formattedPosts []UserPost
	downloadQueue := make(chan struct{}, 5)
	downloadWg := sync.WaitGroup{}
	errChan := make(chan error, len(posts))
	postBaseFolder := filepath.Join(
		GetUserDataRootPathFromId(userId), 
		USER_DATA_FOLDER, 
		POSTS_FOLDER,
	)

	for _, post := range posts {
		var formattedPost UserPost
		formattedPost.PostId =  post["_id"].(primitive.ObjectID).Hex()
		timestamp := post["timestamp"].(primitive.DateTime)
		formattedPost.Timestamp = timestamp.Time().UTC().Unix()

		if post["description"] != nil {
			formattedPost.Text = post["description"].(string)
		}

		dateSubFolder := filepath.Join(postBaseFolder, timestamp.Time().Format("2006-01-02"))
		formattedPost.PostFolderPath = dateSubFolder
		if post["images"] != nil {
			images := post["images"].(primitive.A)
			for _, image := range images {
				imageMap := image.(primitive.M)
				mimetype := imageMap["type"].(string)
				blobId := imageMap["blob_id"].(primitive.ObjectID).Hex()

				// download the file in a goroutine
				fileFolderName := GetFileSubfolderName(mimetype)

				blobName := imageMap["blob_name"].(string)
				bucketName := imageMap["bucket_name"].(string)
				blobFilePath := filepath.Join(
					dateSubFolder,
					formattedPost.PostId,
					fileFolderName, 
					fmt.Sprintf("%s_%s", blobId, imageMap["filename"].(string)),
				)
				downloadWg.Add(1)
				go func(blobName, blobFilePath string) {
					defer downloadWg.Done()
					downloadQueue <- struct{}{}
					// download the file
					err := gcsClient.DownloadFile(ctx, bucketName, blobName, blobFilePath)
					if err != nil {
						errChan <- err
					}
					<-downloadQueue
				}(blobName, blobFilePath)

				formattedPost.Images = append(formattedPost.Images, map[string]string{
					"url": strings.TrimPrefix(
						blobFilePath, 
						filepath.Join(
							GetUserDataRootPathFromId(userId), 
							USER_DATA_FOLDER,
						), 
					),
					"type": imageMap["type"].(string),
					"file_size": strconv.Itoa(int(imageMap["file_size"].(int32))),
					"mimetype": mimetype,
				})
			}
		}

		if post["video"] != nil {
			videoArr := post["video"].(primitive.A)
			videoMap := videoArr[0].(primitive.M) // since there's only one video for now
			mimetype :=  videoMap["type"].(string)
			blobId := videoMap["blob_id"].(primitive.ObjectID).Hex()

			// download the file in a goroutine
			fileFolderName := GetFileSubfolderName(mimetype)

			blobName := videoMap["blob_name"].(string)
			bucketName := videoMap["bucket_name"].(string)
			blobFilePath := filepath.Join(
				dateSubFolder,
				formattedPost.PostId,
				fileFolderName, 
				fmt.Sprintf("%s_%s", blobId, videoMap["filename"].(string)),
			)
			downloadWg.Add(1)
			go func(blobName, blobFilePath string) {
				defer downloadWg.Done()
				downloadQueue <- struct{}{}
				// download the file
				err := gcsClient.DownloadFile(ctx, bucketName, blobName, blobFilePath)
				if err != nil {
					errChan <- err
				}
				<-downloadQueue
			}(blobName, blobFilePath)

			formattedPost.Video = map[string]string{
				"url": strings.TrimPrefix(
					blobFilePath, 
					filepath.Join(
						GetUserDataRootPathFromId(userId), 
						USER_DATA_FOLDER,
					),
				),
				"type": videoMap["type"].(string),
				"file_size": strconv.Itoa(int(videoMap["file_size"].(int32))),
				"mimetype": mimetype,
			}
		}

		formattedPosts = append(formattedPosts, formattedPost)
	}
	downloadWg.Wait()
	close(downloadQueue)
	close(errChan)

	if len(errChan) > 0 {
		for err := range errChan {
			log.Println(err)
		}
		return fmt.Errorf("error downloading %d files out of %d", len(errChan), len(formattedPosts))
	}

	// write the posts to the file
	for _, post := range formattedPosts {
		postFile := filepath.Join(post.PostFolderPath, post.PostId, "post.json")
		os.MkdirAll(filepath.Dir(postFile), 0666)

		postJson, err := json.MarshalIndent(post, "", "    ")
		if err != nil {
			err = fmt.Errorf("error marshalling post %s: %v", post.PostId, err)
			log.Println(err)
			return err
		}

		err = WriteStrToPath(
			postFile,
			string(postJson),
			false,
		)
		if err != nil {
			return err
		}
	}
	return nil
}

func FinaliseDataExport(ctx context.Context, userId string, userDoc *UserData, gcsClient *GCSService) error {
	blobName := fmt.Sprintf("user_data/%s.zip", userId)
	zipPath, err := ZipUserData(ctx, userId)
	if err != nil {
		return err
	}

	err = gcsClient.UploadFile(
		ctx,
		PRIVATE_BUCKET,
		blobName,
		zipPath,
	)
	if err != nil {
		return err
	}

	// delete the zip file
	err = os.Remove(zipPath)
	if err != nil {
		err = fmt.Errorf(
			"error deleting zip file %s: %v", 
			zipPath, err,
		)
		log.Println(err)
		return err
	}
	// delete the user data folder
	userDataRootPath := GetUserDataRootPathFromId(userId)
	err = os.RemoveAll(userDataRootPath)
	if err != nil {
		err = fmt.Errorf(
			"error deleting user data folder %s: %v", 
			userDataRootPath, err,
		)
		return err
	}

	expiryDate := time.Now().UTC().Add(time.Hour * 24 * 4)
	signedBlobUrl, err := gcsClient.CreateSignedURL(
		ctx,
		PRIVATE_BUCKET,
		blobName,
		expiryDate,
	)
	if err != nil {
		return err
	}

	client, err := GetDatabaseClient(ctx)
	if err != nil {
		return err
	}
	defer client.Disconnect(ctx)

	userObjId, err := primitive.ObjectIDFromHex(userId)
	if err != nil {
		log.Println(err)
		return err
	}

	// Update the `security.exported_data` to include the signedUrl with the expiry date
	_, err = client.Database(DB_NAME).Collection(USER_COLLECTION).UpdateOne(
		ctx,
		bson.D{{Key: "_id", Value: userObjId}},
		bson.D{
			{Key: "$set", Value: bson.D{
				{Key: "security.exported_data.signed_url", Value: signedBlobUrl},
				{Key: "security.exported_data.expiry_date", Value: expiryDate},
				{Key: "security.exported_data.exported_at", Value: time.Now().UTC().Unix()},
			}},
		},
	)
	if err != nil {
		log.Println(err)
		return err
	}

	err = SendEmail(
		ctx,
		fmt.Sprintf(
			"@%s", 
			userDoc.UserDoc["username"].(string),
		),
		signedBlobUrl,
		userDoc.UserDoc["email"].(string),
	)
	if err != nil {
		log.Println(err)
		return err
	}
	return nil
}
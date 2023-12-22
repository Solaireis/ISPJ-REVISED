package utils

import (
	"os"
	"path/filepath"
	"runtime"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

const (
	DEBUG_MODE         = false
	RETRY_COUNTER	   = 3
	ERROR_KEY          = "error"
	USER_DATA_FOLDER   = "user_data"
	DOWNLOAD_FOLDER    = "downloads"
	USER_FOLDER        = "user"
	ZIPPED_FOLDER      = "zipped"
	CHATS_FOLDER       = "chats"
	POSTS_FOLDER       = "posts"
	COMMENTS_FOLDER    = "comments"
	IMAGES_FOLDER	   = "images"
	AUDIOS_FOLDER	   = "audios"
	VIDEOS_FOLDER	   = "videos"
	FILES_FOLDER       = "files"
	CHAT_MESSAGES_FILE = "messages.json"

	// Email
	EMAIL = "noreply@miraisocial.live"
	SMTP_SERVER = "smtp.titan.email"
	SMTP_PORT = "587"
	BTN_STYLE = "background-color:#eaa7c7;width:min(250px,40%);border-radius:5px;color:white;padding:14px 25px;text-decoration:none;text-align:center;display:inline-block;"

	// GCP
	GCP_PROJECT_ID       = "ispj-mirai"

	// GCP Cloud Storage
	PUBLIC_BUCKET  = "mirai-public"
	PRIVATE_BUCKET = "mirai-confidential"

	// KMS Key IDs
	DATABASE_KEY = "database-key"

	// MongoDB
	DB_USERNAME_SECRET_ID    = "mongodb-user"
	DB_PASSWORD_SECRET_ID    = "mongodb-pass"
	DB_NAME                  = "Mirai"
	USER_COLLECTION          = "users"
	POST_COLLECTION          = "posts"
	COMMENT_COLLECTION       = "comments"
	CHAT_COLLECTION          = "chats"
	REPORT_COLLECTION        = "reports"
	BAN_COLLECTION           = "ban_logs"
	DELETED_CHAT_COLLECTION  = "deleted_chats"
	FILE_ANALYSIS_COLLECTION = "file_analysis"
)

var ROOT_PATH = func() string {
	baseFolderId := primitive.NewObjectID().Hex()
	if !DEBUG_MODE {
		dirname := os.TempDir()
		return filepath.Join(dirname, "mirai", baseFolderId)
	}

	_, filename, _, _ := runtime.Caller(1)
	filePath := filepath.Join(filepath.Dir(filename), "..", baseFolderId)
	return filepath.Clean(filePath)
}()
func GetUserDataRootPathFromId(userId string) string {
	return filepath.Join(ROOT_PATH, userId)
}
func GetUserDataRootPathFromDoc(userDoc bson.M) string {
	userId := userDoc["_id"].(primitive.ObjectID).Hex()
	return GetUserDataRootPathFromId(userId)
}

var GCP_PROJECT_LOCATION = func() string {
	if DEBUG_MODE {
		return "asia-southeast1"
	} 
	return "global"
}()
var KEYRING = func() string {
	if DEBUG_MODE {
		return "dev"
	} 
	return "mirai"
}()


func GetDomain() string {
	var domain string
	if DEBUG_MODE {
		domain = "https://localhost:8080"
	} else {
		domain = "https://miraisocial.live"
	}
	return domain
}
var DOMAIN = GetDomain()
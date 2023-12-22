package utils

import (
	"path/filepath"
	"runtime"
)

func GetRootPath() string {
	_, filename, _, _ := runtime.Caller(1)
	filePath := filepath.Join(filepath.Dir(filename), "..")
	return filepath.Clean(filePath)
}

var ROOT_PATH = GetRootPath()

const (
	ERROR_KEY  = "error"
	DEBUG_MODE = false // set to true to enable debug mode

	// GCP
	GCP_PROJECT_ID = "ispj-mirai"

	// Cloud Bucket
	PRIVATE_BUCKET = "mirai-confidential"

	// MongoDB
	DB_USERNAME_SECRET_ID    = "mongodb-user"
	DB_PASSWORD_SECRET_ID    = "mongodb-pass"
	DB_NAME                  = "Mirai"
	ADMIN_DB_NAME            = "Mirai_Admin"
	USER_COLLECTION          = "users"
	ADMIN_COLLECTION         = "admins"
	DELETE_COLLECTION        = "to_delete"
	POST_COLLECTION          = "posts"
	COMMENT_COLLECTION       = "comments"
	CHAT_COLLECTION          = "chats"
	PAYMENT_COLLECTION		 = "payments"
	UPLOAD_IDS_COLLECTION    = "upload_ids"
	REPORT_COLLECTION        = "reports"
	BAN_COLLECTION           = "ban_logs"
	DELETED_CHAT_COLLECTION  = "deleted_chats"
	FILE_ANALYSIS_COLLECTION = "file_analysis"
)

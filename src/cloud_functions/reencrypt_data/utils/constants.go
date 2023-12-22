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
	DEBUG_MODE      = false
	ERROR_KEY       = "error"
	MAX_CONCURRENCY = 15

	// GCP
	GCP_PROJECT_ID       = "ispj-mirai"

	// KMS Key IDs
	DATABASE_KEY = "database-key"

	// MongoDB
	DB_USERNAME_SECRET_ID    = "mongodb-user"
	DB_PASSWORD_SECRET_ID    = "mongodb-pass"
	DB_NAME                  = "Mirai"
	USER_COLLECTION          = "users"
	POST_COLLECTION          = "posts"
	CHAT_COLLECTION          = "chats"
	REPORT_COLLECTION        = "reports"
	BAN_COLLECTION           = "ban_logs"
	DELETED_CHAT_COLLECTION  = "deleted_chats"
	FILE_ANALYSIS_COLLECTION = "file_analysis"
)
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
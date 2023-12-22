package utils

import (
	"path/filepath"
	"runtime"
)

const (
	DEBUG_MODE = false
	ERROR_KEY  = "error"

	// Email
	SMTP_SERVER = "smtp.titan.email"
	SMTP_PORT = "587"

	// GCP
	GCP_PROJECT_ID = "ispj-mirai"

	// GCP Cloud Storage
	PUBLIC_BUCKET  = "mirai-public"
	PRIVATE_BUCKET = "mirai-confidential"
)

var AVAILABLE_EMAILS = map[string]struct{}{
	"noreply@miraisocial.live": {},
}

var ROOT_PATH = func() string {
	_, filename, _, _ := runtime.Caller(1)
	filePath := filepath.Join(filepath.Dir(filename), "..")
	return filepath.Clean(filePath)
}()
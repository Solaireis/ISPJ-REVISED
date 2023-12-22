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
	DEBUG_MODE = false // set to true to enable debug mode
	ERROR_KEY = "error"

	// GCP
	GCP_PROJECT_ID = "ispj-mirai"
)
// package main
package createSignedUrl

import (
	// "fmt"
	// "log"

	"encoding/json"
	"net/http"
	"time"

	"github.com/GoogleCloudPlatform/functions-framework-go/functions"
	"github.com/Solaireis/CWC-ISPJ/utils"
)

type SignedURLReq struct {
	BucketName string `json:"bucket_name"`
	ObjectName string `json:"object_name"`
	Expiry     int64  `json:"expiry"`
}

func init() {
	functions.HTTP("gcsSignedUrl", gcsSignedUrl)
}

func returnJson(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

func gcsSignedUrl(w http.ResponseWriter, r *http.Request) {
	var req SignedURLReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		returnJson(w, http.StatusUnprocessableEntity, map[string]string{
			utils.ERROR_KEY: "could not decode request body",
		})
		return
	}
	if req.BucketName == "" || req.ObjectName == "" {
		returnJson(w, http.StatusUnprocessableEntity, map[string]string{
			utils.ERROR_KEY: "bucket_name or object_name is empty",
		})
		return
	}
	if req.Expiry < 0 || req.Expiry > 604800 {
		returnJson(w, http.StatusUnprocessableEntity, map[string]string{
			utils.ERROR_KEY: "expiry is invalid, must be between 0 and 604800 (7 days)",
		})
		return
	}

	signedUrl, err := utils.CreateSignedURL(
		req.BucketName,
		req.ObjectName,
		time.Now().UTC().Add(time.Second * time.Duration(req.Expiry)),
	)
	if err != nil {
		returnJson(w, http.StatusInternalServerError, map[string]string{
			utils.ERROR_KEY: "Failed to create signed URL",
		})
		return
	}

	returnJson(w, http.StatusOK, map[string]string{
		"signed_url": signedUrl,
	})
}

// uncomment this to run locally
// func main() {
// 	http.HandleFunc("/", gcsSignedUrl)
// 	log.Println("Listening on localhost:8080")
// 	log.Fatal(http.ListenAndServe(":8080", nil))
// }

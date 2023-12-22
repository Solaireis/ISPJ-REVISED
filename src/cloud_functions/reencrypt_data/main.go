// package main
package reEncryptData

import (
	"context"
	"encoding/json"
	// "fmt"
	// "log"
	"net/http"

	"github.com/GoogleCloudPlatform/functions-framework-go/functions"
	"github.com/Solaireis/CWC-ISPJ/utils"
)

func init() {
	functions.HTTP("reEncryptData", reEncryptData)
}

func returnJson(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

func reEncryptData(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	client, err := utils.GetDatabaseClient(ctx)
	if err != nil {
		returnJson(w, http.StatusInternalServerError, map[string]string{
			utils.ERROR_KEY: "Error getting database client",
		})
		return
	}
	defer client.Disconnect(ctx)

	err = utils.ReEncryptChatMsg(context.Background(), client)
	if err != nil {
		returnJson(w, http.StatusInternalServerError, map[string]string{
			utils.ERROR_KEY: "Error re-encrypting chat messages",
		})
		return
	}

	err = utils.ReEncryptUserDoc(context.Background(), client)
	if err != nil {
		returnJson(w, http.StatusInternalServerError, map[string]string{
			utils.ERROR_KEY: "Error re-encrypting user documents",
		})
		return
	}

	returnJson(w, http.StatusOK, map[string]string{
		"message": "Re-encryption of data in database was successful",
	})
}

// uncomment this to run locally
// func main() {
// 	http.HandleFunc("/", reEncryptData)
// 	fmt.Println("Listening on localhost:8080")
// 	log.Fatal(http.ListenAndServe(":8080", nil))
// }
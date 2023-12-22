// package main
package databaseCleanup

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
	functions.HTTP("databaseCleanup", databaseCleanup)
}

func returnJson(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

func databaseCleanup(w http.ResponseWriter, r *http.Request) {
	userDbCtx := context.Background()
	userDb, err := utils.GetDatabaseClient(userDbCtx, false)
	if err != nil {
		returnJson(w, http.StatusInternalServerError, map[string]string{
			utils.ERROR_KEY: "Error getting user database client",
		})
		return
	}
	defer userDb.Client().Disconnect(userDbCtx)

	adminDbCtx := context.Background()
	adminDb, err := utils.GetDatabaseClient(adminDbCtx, true)
	if err != nil {
		returnJson(w, http.StatusInternalServerError, map[string]string{
			utils.ERROR_KEY: "Error getting admin database client",
		})
		return
	}
	defer adminDb.Client().Disconnect(adminDbCtx)

	err = utils.DeleteOrphanComments(context.Background(), userDb)
	if err != nil {
		returnJson(w, http.StatusInternalServerError, map[string]string{
			utils.ERROR_KEY: "Error removing orphan comments",
		})
		return
	}

	err = utils.DeleteUnwantedUserAccounts(context.Background(), userDb)
	if err != nil {
		returnJson(w, http.StatusInternalServerError, map[string]string{
			utils.ERROR_KEY: "Error removing unverified users",
		})
		return
	}

	err = utils.DeleteInactiveAdmins(context.Background(), adminDb)
	if err != nil {
		returnJson(w, http.StatusInternalServerError, map[string]string{
			utils.ERROR_KEY: "Error removing inactive admins",
		})
		return
	}

	err = utils.RemoveExpiredSession(context.Background(), userDb)
	if err != nil {
		returnJson(w, http.StatusInternalServerError, map[string]string{
			utils.ERROR_KEY: "Error removing expired sessions for user",
		})
		return
	}
	err = utils.RemoveExpiredSession(context.Background(), adminDb)
	if err != nil {
		returnJson(w, http.StatusInternalServerError, map[string]string{
			utils.ERROR_KEY: "Error removing expired sessions for admin",
		})
		return
	}

	err = utils.RemoveExpiredUploadIds(context.Background(), userDb)
	if err != nil {
		returnJson(w, http.StatusInternalServerError, map[string]string{
			utils.ERROR_KEY: "Error removing expired upload ids",
		})
		return
	}

	err = utils.DeleteExpiredEmailTokens(context.Background(), userDb)
	if err != nil {
		returnJson(w, http.StatusInternalServerError, map[string]string{
			utils.ERROR_KEY: "Error deleting expired email tokens",
		})
		return
	}

	err = utils.DeleteUnusedSMSTokens(context.Background(), userDb)
	if err != nil {
		returnJson(w, http.StatusInternalServerError, map[string]string{
			utils.ERROR_KEY: "Error deleting unused sms tokens",
		})
		return
	}

	err = utils.SetChatStatusToOffline(context.Background(), userDb)
	if err != nil {
		returnJson(w, http.StatusInternalServerError, map[string]string{
			utils.ERROR_KEY: "Error setting chat status to offline",
		})
		return
	}

	err = utils.DeleteExpiredChats(context.Background(), userDb)
	if err != nil {
		returnJson(w, http.StatusInternalServerError, map[string]string{
			utils.ERROR_KEY: "Error deleting expired chats",
		})
		return
	}

	if !utils.DEBUG_MODE { // To prevent accidental deletion of files meant for local development with local database when deployed.
		// Delete (chat or post) files that are not in the database
		err = utils.DeleteFilesNotInDB(context.Background(), userDb)
		if err != nil {
			returnJson(w, http.StatusInternalServerError, map[string]string{
				utils.ERROR_KEY: "Error deleting files that are not in the database",
			})
			return
		}
	}

	err = utils.CheckExpiredMiraiPlus(context.Background(), userDb)
	if err != nil {
		returnJson(w, http.StatusInternalServerError, map[string]string{
			utils.ERROR_KEY: "Error removing Mirai Plus from users",
		})
	}

	returnJson(w, http.StatusOK, map[string]string{
		"message": "Database cleanup successful",
	})
}

// uncomment this to run locally
// func main() {
// 	http.HandleFunc("/", databaseCleanup)
// 	fmt.Println("Listening on localhost:8080")
// 	log.Fatal(http.ListenAndServe(":8080", nil))
// }

package main

import (
	"os"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/Solaireis/CWC-ISPJ/utils"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// ReturnJson returns a json response to the client
func returnJson(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

type RequestJson struct {
	UserId string `json:"user_id"`
}

func getAllUserData(w http.ResponseWriter, r *http.Request) {
	var req RequestJson
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		returnJson(w, http.StatusInternalServerError, map[string]string{
			utils.ERROR_KEY: "Invalid request body",
		})
		return
	}
	if req.UserId == "" || len(req.UserId) != 24 {
		returnJson(w, http.StatusInternalServerError, map[string]string{
			utils.ERROR_KEY: "Invalid user id",
		})
		return
	}

	userData, err := utils.QueryAllUserData(context.Background(), req.UserId)
	if err != nil {
		log.Println("Error querying user data: ", err)
		returnJson(w, http.StatusInternalServerError, map[string]string{
			utils.ERROR_KEY: "Error querying user data",
		})
		return
	}

	if !utils.DEBUG_MODE {
		securityInfo := userData.UserDoc["security"].(bson.M)
		if securityInfo["exported_data"] != nil {
			exportDataInfo := securityInfo["exported_data"].(bson.M)
			if exportDataInfo["expiry_date"] != nil {
				// user has exported data before hence check the expiry date
				expiryDate := exportDataInfo["expiry_date"].(primitive.DateTime).Time().UTC().Unix()
				if expiryDate > time.Now().UTC().Unix() {
					returnJson(w, http.StatusBadRequest, map[string]string{
						utils.ERROR_KEY: "User data has already been exported",
						"expiry_date":   fmt.Sprintf("%d", expiryDate),
						"remaining":     fmt.Sprintf("%ds", expiryDate - time.Now().UTC().Unix()),
					})
					return
				}
			} else {
				// user has not exported data before but has requested it
				taskName := exportDataInfo["taskName"]
				if taskName != nil {
					returnJson(w, http.StatusBadRequest, map[string]string{
						utils.ERROR_KEY: "User data cannot be exported as the user has already requested it.",
						"task_name":  taskName.(string),
					})
					return
				}
			}
		} else {
			returnJson(w, http.StatusBadRequest, map[string]string{
				utils.ERROR_KEY: "User data cannot be exported as the user did not request it within the last 24 hours",
			})
			return
		}
	}

	gcsClient, err := utils.GetStorageClient(context.Background())
	if err != nil {
		log.Printf("Error getting google cloud storage client: %v", err)
		returnJson(w, http.StatusInternalServerError, map[string]string{
			utils.ERROR_KEY: "Error getting google cloud storage client",
		})
		return
	}
	err = utils.ProcessChatMessages(context.Background(), userData.ChatMessages, req.UserId, gcsClient)
	if err != nil {
		log.Printf("Error processing chat messages: %v", err)
		returnJson(w, http.StatusInternalServerError, map[string]string{
			utils.ERROR_KEY: "Error processing chat messages",
		})
		return
	}

	err = utils.ProcessPosts(context.Background(), req.UserId, userData.Posts, gcsClient)
	if err != nil {
		log.Printf("Error processing posts: %v", err)
		returnJson(w, http.StatusInternalServerError, map[string]string{
			utils.ERROR_KEY: "Error processing posts",
		})
		return
	}

	err = utils.ProcessComments(context.Background(), userData.Comments, userData.UserDoc)
	if err != nil {
		log.Printf("Error processing comments: %v", err)
		returnJson(w, http.StatusInternalServerError, map[string]string{
			utils.ERROR_KEY: "Error processing comments",
		})
		return
	}

	err = utils.ProcessUserDoc(context.Background(), userData.UserDoc, gcsClient)
	if err != nil {
		log.Printf("Error processing user document: %v", err)
		returnJson(w, http.StatusInternalServerError, map[string]string{
			utils.ERROR_KEY: "Error processing user document",
		})
		return
	}

	// zip the user data folder
	err = utils.FinaliseDataExport(
		context.Background(),
		req.UserId,
		userData,
		gcsClient,
	)
	if err != nil {
		log.Printf("Error zipping or uploading user exported data: %v", err)
		returnJson(w, http.StatusInternalServerError, map[string]string{
			utils.ERROR_KEY: "Error zipping or uploading user exported data",
		})
		return
	}

	returnJson(w, http.StatusOK, map[string]string{
		"message": "Successfully exported user data",
	})
}

func multiplexer(w http.ResponseWriter, r *http.Request) {
    switch r.Method {
    case "POST":
        getAllUserData(w, r)
	default:
		returnJson(w, http.StatusMethodNotAllowed, map[string]string{
			utils.ERROR_KEY: "Method not allowed",
		})
	}
}

func main() {
	log.Print("starting server...")

	// Determine port for HTTP service.
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
		log.Printf("defaulting to port %s", port)
	}
	http.HandleFunc("/", multiplexer)

	// Start HTTP server.
	log.Printf("listening on port %s", port)
	if err := http.ListenAndServe(fmt.Sprintf(":%s", port), nil); err != nil {
		log.Fatal(err)
	}
}
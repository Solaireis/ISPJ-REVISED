// package main
package sendEmail

import (
	// "os"
	// "fmt"
	"context"
	"encoding/json"
	"log"
	"net/http"

	"github.com/GoogleCloudPlatform/functions-framework-go/functions"
	"github.com/Solaireis/CWC-ISPJ/utils"
)

func init() {
	functions.HTTP("sendEmail", sendEmail)
}

// ReturnJson returns a json response to the client
func returnJson(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

type RequestJson struct {
	MiraiEmail string `json:"mirai_email"`
	EmailRecipient string `json:"email_recipient"`
	EmailSubject string `json:"email_subject"`
	EmailBody string `json:"email_body"`
}

func sendEmail(w http.ResponseWriter, r *http.Request) {
	var req RequestJson
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		returnJson(w, http.StatusInternalServerError, map[string]string{
			utils.ERROR_KEY: "Invalid request body",
		})
		return
	}
	if _, ok := utils.AVAILABLE_EMAILS[req.MiraiEmail]; !ok {
		log.Printf("Invalid Mirai email used: %s", req.MiraiEmail)
		returnJson(w, http.StatusBadRequest, map[string]string{
			utils.ERROR_KEY: "Invalid Mirai email",
		})
		return
	}

	err := utils.SendEmail(
		context.Background(),
		req.EmailRecipient,
		req.MiraiEmail,
		req.EmailBody,
		req.EmailSubject,
	)
	if err != nil {
		log.Printf("Error sending email: %s", err)
		returnJson(w, http.StatusInternalServerError, map[string]string{
			utils.ERROR_KEY: "Error sending email",
		})
		return
	}
	returnJson(w, http.StatusOK, map[string]string{
		"message": "Successfully sent email",
	})
}

// func main() {
// 	port := 8080
// 	log.Printf("listening on port %s", port)
// 	http.HandleFunc("/", sendEmail)
// 	if err := http.ListenAndServe(fmt.Sprintf(":%s", port), nil); err != nil {
// 		log.Fatal(err)
// 	}
// }
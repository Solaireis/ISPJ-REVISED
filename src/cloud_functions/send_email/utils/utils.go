package utils

import (
	"context"
	"log"
	"strings"
	"encoding/json"
	"net/smtp"
	"fmt"
)

// convert []byte to map[string]string and get email password
func getPasswordEmail(email string, credInfo []byte) (string, error) {
	credInfoMap := make(map[string]string)
	err := json.Unmarshal(credInfo, &credInfoMap)
	if err != nil {
		log.Println(err)
		return "", err
	}
	return credInfoMap[email], nil
}

func SendEmail(ctx context.Context, to, from, body, subject string) error {
	toList := []string{to}

    // We can't send strings directly in mail,
    // strings need to be converted into slice bytes
	// Compose the message
	encodedMsg := []byte(
		strings.Join([]string{
			"From:", from, "\r\n",
			"To:", to, "\r\n",
			"Subject: ", subject, "\r\n",
			"MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n",
			body,
		}, ""),
	)

    // PlainAuth uses the given username and password to
    // authenticate to host and act as identity.
    // Usually identity should be the empty string,
    // to act as username.
	var err error
	var emailCredentials []byte
	if DEBUG_MODE {
		emailCredentials, err = AccessSecretVersion(
			ctx, 
			ConstructName("titan_email_credentials", "latest"),
		)
	} else {
		emailCredentials, err = GetSecret("titan_email_credentials")
	}
	if err != nil {
		return err
	}

	emailPassword, err := getPasswordEmail(from, emailCredentials)
	if err != nil {
		return err
	}
    auth := smtp.PlainAuth("", from, emailPassword, SMTP_SERVER)

    // SendMail uses TLS connection to send the mail
    // The email is sent to all address in the toList,
    // the body should be of type bytes, not strings
    // This returns error if any occurred.
    err = smtp.SendMail(
		fmt.Sprintf("%s:%s", SMTP_SERVER, SMTP_PORT), 
		auth, 
		from,
		toList, 
		encodedMsg,
	)

    // handling the errors
    if err != nil {
        log.Println(err)
		return err
    }
	return nil
}
package utils

import (
	"context"
	"log"
	"os"
	"strings"
	"encoding/json"
	"net/smtp"
	"math/rand"
	"path/filepath"
	"time"
	"fmt"

	archiver "github.com/mholt/archiver/v4"
)

// ZipUserData zips the user's data folder
// and returns the path to the zipped file
func ZipUserData(ctx context.Context, userId string) (string, error) {
	userDataRootPath := GetUserDataRootPathFromId(userId)
	userDataDirPath := filepath.Join(
		userDataRootPath, 
		USER_DATA_FOLDER,
	)
	files, err := archiver.FilesFromDisk(
		nil,
		map[string]string{
			filepath.Join(userDataDirPath, CHATS_FOLDER): "",
			filepath.Join(userDataDirPath, POSTS_FOLDER): "",
			filepath.Join(userDataDirPath, COMMENTS_FOLDER): "",
			filepath.Join(userDataDirPath, USER_FOLDER): "",
		},
	)
	if err != nil {
		log.Println(err)
		return "", err
	}

	destZipPath := filepath.Join(
		userDataRootPath, 
		ZIPPED_FOLDER, 
		fmt.Sprintf("%s.zip", userId),
	)
	os.MkdirAll(filepath.Dir(destZipPath), 0644)
	f, err := os.Create(destZipPath)
	if err != nil {
		log.Println(err)
		return "", err
	}
	defer f.Close()

	format := archiver.CompressedArchive{
		Archival: archiver.Zip{},
	}
	err = format.Archive(ctx, f, files)
	if err != nil {
		log.Println(err)
		return "", err
	}
	return destZipPath, nil
}

func WriteStrToPath(path, content string, append bool) error {
	os.MkdirAll(filepath.Dir(path), 0644)

	var f *os.File
	var err error
	if append {
		f, err = os.OpenFile(
			path,
			os.O_APPEND|os.O_CREATE|os.O_WRONLY,
			0644,
		)
	} else {
		f, err = os.Create(path)
	}

	if err != nil {
		log.Println(err)
		return err
	}
	defer f.Close()

	_, err = f.WriteString(content)
	if err != nil {
		log.Println(err)
		return err
	}
	return nil
}

// Returns the last part of the given URL string
func GetLastPartOfURL(url string) string {
	removedParams := strings.SplitN(url, "?", 2)
	splittedUrl := strings.Split(removedParams[0], "/")
	return splittedUrl[len(splittedUrl)-1]
}

func RemoveExtFromFilename(filename string) string {
	return strings.TrimSuffix(filename, filepath.Ext(filename))
}

// Returns a random time.Duration between the given min and max arguments
func GetRandomTime(min, max float64) time.Duration {
	rand.Seed(time.Now().UnixNano())
	randomDelay := min + rand.Float64() * (max - min)
	return time.Duration(randomDelay * 1000) * time.Millisecond 
}

// Returns a random time.Duration between the defined min and max delay values in the contants.go file
func GetRandomDelay() time.Duration {
	return GetRandomTime(1, 3)
}

func GetFileSubfolderName(mimetype string) string {
	if strings.HasPrefix(mimetype, "image/") {
		return IMAGES_FOLDER
	} else if strings.HasPrefix(mimetype, "video/") {
		return VIDEOS_FOLDER
	} else if strings.HasPrefix(mimetype, "audio/") {
		return AUDIOS_FOLDER
	} else {
		return FILES_FOLDER
	}
}

// convert []byte to map[string]string and get email password
func getPasswordEmail(credInfo []byte) (string, error) {
	credInfoMap := make(map[string]string)
	err := json.Unmarshal(credInfo, &credInfoMap)
	if err != nil {
		log.Println(err)
		return "", err
	}
	return credInfoMap[EMAIL], nil
}

func SendEmail(ctx context.Context, name, zipUrl, to string) error {
	toList := []string{to}

    // We can't send strings directly in mail,
    // strings need to be converted into slice bytes
	// Compose the message
	encodedMsg := []byte(
		strings.Join([]string{
			"From:", EMAIL, "\r\n",
			"To:", to, "\r\n",
			"Subject: [Mirai] Your data is ready!\r\n",
			"MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n",
			"<p>Hello ", name, ",</p>",
			"<p>Your data has been processed and is ready for download.</p>",
			"<p>Please remember that this data is your private information. Keep it safe. Mirai keeps your data secure and does not sell it to any third parties.</p>",
			"<p>This link will expire in 3 days and please do NOT share this link with anyone!</p>",
			"<p>Click the link below to download your data.</p>",
			"<a href=\"", zipUrl, "\" style=\"", BTN_STYLE, "\">Download</a>",
			"<p>Sincerely,<br><strong>Mirai Team</strong></p>",
			"<img src=\"https://storage.googleapis.com/mirai-public/common/Logo.png\" alt=\"Mirai Logo\" style=\"border-radius: 5px; width: min(250px, 40%);\">",
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

	emailPassword, err := getPasswordEmail(emailCredentials)
	if err != nil {
		return err
	}
    auth := smtp.PlainAuth("", EMAIL, emailPassword, SMTP_SERVER)

    // SendMail uses TLS connection to send the mail
    // The email is sent to all address in the toList,
    // the body should be of type bytes, not strings
    // This returns error if any occurred.
    err = smtp.SendMail(
		fmt.Sprintf("%s:%s", SMTP_SERVER, SMTP_PORT), 
		auth, 
		EMAIL,
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
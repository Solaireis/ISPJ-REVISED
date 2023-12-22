package utils

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/option"
)

func GetStorageClient(ctx context.Context) (*storage.Client, error) {
	var err error
	var clientJson []byte
	if DEBUG_MODE {
		clientJson, err = AccessSecretVersion(
			ctx, ConstructName("cloud-storage", "latest"),
		)
		if err != nil {
			log.Println(err)
			return nil, err
		}
	} else {
		clientJson = []byte(os.Getenv("cloud-storage"))
	}

	client, err := storage.NewClient(
		ctx,
		option.WithCredentialsJSON(clientJson),
	)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	return client, nil
}

func CreateSignedURL(bucket, object string, expires time.Time) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()

	client, err := GetStorageClient(ctx)
	if err != nil {
		return "", err
	}
	defer client.Close()

	signedUrl, err := client.Bucket(bucket).SignedURL(object, &storage.SignedURLOptions{
		Method:  http.MethodGet,
		Expires: expires,
	})
	if err != nil {
		log.Println(err)
		return "", err
	}
	return signedUrl, err
}

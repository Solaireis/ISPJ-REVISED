package utils

import (
	"context"
	"log"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/option"
)

type GCSClient struct {
	Client *storage.Client
}
func GetStorageClient(ctx context.Context) (*GCSClient, error) {
	var err error
	var clientJson []byte
	if DEBUG_MODE {
		clientJson, err = AccessSecretVersion(
			ctx, ConstructName("cloud-storage", "latest"),
		)
	} else {
		clientJson, err = GetSecret("cloud-storage")
	}
	if err != nil {
		log.Println(err)
		return nil, err
	}

	client, err := storage.NewClient(
		ctx,
		option.WithCredentialsJSON(clientJson),
	)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	return &GCSClient{client}, nil
}

func (gcsClient GCSClient) DeleteFile(ctx context.Context, bucketName, objectName string) {
	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	gcsClient.Client.Bucket(bucketName).Object(objectName).Delete(ctx)
}
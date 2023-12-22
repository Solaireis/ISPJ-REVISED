package utils

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/option"
)

type GCSService struct {
	Client *storage.Client
}

func GetStorageClient(ctx context.Context) (*GCSService, error) {
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
	return &GCSService{client}, nil
}

func (gcsService GCSService) CreateSignedURL(ctx context.Context, bucket, object string, expires time.Time) (string, error) {
	signedUrl, err := gcsService.Client.Bucket(bucket).SignedURL(object, &storage.SignedURLOptions{
		Method:  http.MethodGet,
		Expires: expires,
	})
	if err != nil {
		log.Println(err)
		return "", err
	}
	return signedUrl, err
}

// downloadFile downloads an object to a file.
func (gcsService GCSService) DownloadFile(ctx context.Context, bucket, object, destFileName string) error {
	// bucket := "bucket-name"
	// object := "object-name"
	// destFileName := "file.txt"
	ctx, cancel := context.WithTimeout(ctx, time.Second*50)
	defer cancel()

	rc, err := gcsService.Client.Bucket(bucket).Object(object).NewReader(ctx)
	if err != nil {
		// Google Cloud Storage error like Object not found, etc.
		err = fmt.Errorf("Object(%q).NewReader: %v", object, err)
		log.Println(err)
		return err
	}
	defer rc.Close()

	os.MkdirAll(filepath.Dir(destFileName), 0644)
	f, err := os.Create(destFileName)
	if err != nil {
		err = fmt.Errorf("os.Create: %v", err)
		log.Println(err)
		return err
	}
	defer f.Close()

	if _, err := io.Copy(f, rc); err != nil {
		err = fmt.Errorf("io.Copy: %v", err)
		log.Println(err)
		return err
	}
	return nil
}

func (gcsService GCSService) UploadFile(ctx context.Context, bucket, object, sourceFileName string) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute*10)
	defer cancel()

	f, err := os.Open(sourceFileName)
	if err != nil {
		err = fmt.Errorf("os.Open: %v", err)
		log.Println(err)
		return err
	}
	defer f.Close()

	wc := gcsService.Client.Bucket(bucket).Object(object).NewWriter(ctx)
	if _, err = io.Copy(wc, f); err != nil {
		err = fmt.Errorf("io.Copy: %v", err)
		log.Println(err)
		return err
	}
	if err := wc.Close(); err != nil {
		err = fmt.Errorf("Writer.Close: %v", err)
		log.Println(err)
		return err
	}
	return nil
}
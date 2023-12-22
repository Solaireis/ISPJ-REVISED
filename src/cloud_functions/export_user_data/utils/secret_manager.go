package utils

import (
	"os"
	"context"
	"fmt"
	"hash/crc32"
	"log"
	"path/filepath"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/api/option"
)

func GetSecret(secretId string) ([]byte, error) {
	path := filepath.Join("/", secretId, "secret")

	// read secret from file
	secret, err := os.ReadFile(path)
	if err != nil {
		err = fmt.Errorf("failed to read secret, \"%s\", from file: %w", secretId, err)
		log.Println(err)
		return nil, err
	}
	return secret, nil
}

func GetSecretStr(secretId string) (string, error) {
	secret, err := GetSecret(secretId)
	if err != nil {
		return "", err
	}
	return string(secret), nil
}

func GetSMClient(ctx context.Context) (*secretmanager.Client, error) {
	client, err := secretmanager.NewClient(
		ctx,
		option.WithCredentialsFile(filepath.Join(ROOT_PATH, "gcp-sm.json")),
	)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	return client, err
}

// constructName constructs the resource name of the secret version.
// e.g. projects/my-project/secrets/my-secret/versions/latest
func ConstructName(secretId string, versionId string) string {
	return fmt.Sprintf(
		"projects/%s/secrets/%s/versions/%s", GCP_PROJECT_ID, secretId, versionId,
	)
}

// accessSecretVersion accesses the payload for the given secret version if one
// exists. The version can be a version number as a string (e.g. "5") or an
// alias (e.g. "latest").
func AccessSecretVersion(ctx context.Context, name string) ([]byte, error) {
	// Create the client.
	client, err := GetSMClient(ctx)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	// Build the request.
	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: name,
	}

	// Call the API.
	result, err := client.AccessSecretVersion(ctx, req)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	// Verify the data checksum.
	crc32c := crc32.MakeTable(crc32.Castagnoli)
	checksum := int64(crc32.Checksum(result.Payload.Data, crc32c))
	if checksum != *result.Payload.DataCrc32C {
		err = fmt.Errorf(
			"checksums don't match: %d != %d", checksum, *result.Payload.DataCrc32C,
		)
		log.Println(err)
		return nil, err
	}
	return result.Payload.Data, nil
}

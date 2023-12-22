package utils

import (
	"context"
	"fmt"
	"hash/crc32"
	"log"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/api/option"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type KMSService struct {
	Client *kms.KeyManagementClient
}

func GetKMSClient(ctx context.Context) (*KMSService, error) {
	var err error
	var clientJson []byte
	if DEBUG_MODE {
		clientJson, err = AccessSecretVersion(
			ctx, ConstructName("kms", "latest"),
		)
	} else {
		clientJson, err = GetSecret("kms")
	}
	if err != nil {
		log.Println(err)
		return nil, err
	}

	client, err := kms.NewKeyManagementClient(
		ctx,
		option.WithCredentialsJSON(clientJson),
	)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	return &KMSService{client}, nil
}

func SymmetricConstructName(keyRing, key string) string {
	return fmt.Sprintf(
		"projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
		GCP_PROJECT_ID, GCP_PROJECT_LOCATION, keyRing, key,
	)
}

// decryptSymmetric will decrypt the input ciphertext bytes using the specified symmetric key.
func (ksmClient KMSService) DecryptSymmetric(ctx context.Context, name string, ciphertext []byte) ([]byte, error) {
	// name := "projects/my-project/locations/us-east1/keyRings/my-key-ring/cryptoKeys/my-key"
	// ciphertext := []byte("...")  // result of a symmetric encryption call
	// Optional, but recommended: Compute ciphertext's CRC32C.
	crc32c := func(data []byte) uint32 {
		t := crc32.MakeTable(crc32.Castagnoli)
		return crc32.Checksum(data, t)
	}
	ciphertextCRC32C := crc32c(ciphertext)

	// Build the request.
	req := &kmspb.DecryptRequest{
		Name:             name,
		Ciphertext:       ciphertext,
		CiphertextCrc32C: wrapperspb.Int64(int64(ciphertextCRC32C)),
	}

	// Call the API.
	result, err := ksmClient.Client.Decrypt(ctx, req)
	if err != nil {
		err = fmt.Errorf("failed to decrypt ciphertext: %v", err)
		log.Println(err)
		return nil, err
	}

	// Optional, but recommended: perform integrity verification on result.
	// For more details on ensuring E2E in-transit integrity to and from Cloud KMS visit:
	// https://cloud.google.com/kms/docs/data-integrity-guidelines
	if int64(crc32c(result.Plaintext)) != result.PlaintextCrc32C.Value {
		err = fmt.Errorf("decrypt: response corrupted in-transit")
		log.Println(err)
		return nil, err
	}

	return result.Plaintext, nil
}

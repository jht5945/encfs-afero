package encfs

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const LOCAL_MINI_KMS_ADDRESS = "LOCAL_MINI_KMS_ADDRESS"
const ENCRYPTED_ENCRYPTION_MASTER_KEY = "ENCRYPTED_ENCRYPTION_MASTER_KEY"

type MultiViewValue struct {
	ValueHex    string `json:"value_hex"`
	ValueBase64 string `json:"value_base64"`
}

type EncryptRequest struct {
	EncryptedValue string `json:"encrypted_value"`
}

var cachedcEncryptionMasterKey *EncryptionMasterKey = nil
var cachedcEncryptionMasterKeyLock sync.Mutex

func GetCachedEncryptionMasterKey() (*EncryptionMasterKey, error) {
	cachedcEncryptionMasterKeyLock.Lock()
	defer cachedcEncryptionMasterKeyLock.Unlock()
	if cachedcEncryptionMasterKey == nil {
		var err error
		cachedcEncryptionMasterKey, err = GetEncryptionMasterKey()
		if err != nil {
			return nil, err
		}
	}
	return cachedcEncryptionMasterKey, nil
}

func GetEncryptionMasterKey() (*EncryptionMasterKey, error) {
	encryptedEncryptionMasterKey := os.Getenv(ENCRYPTED_ENCRYPTION_MASTER_KEY)
	if encryptedEncryptionMasterKey == "" {
		fmt.Println("[ERROR] encrypted encryption master key is not present")
		return nil, errors.New("encrypted encryption master key is not present")
	}
	key, err := DecryptBytes(encryptedEncryptionMasterKey)
	if err != nil {
		return nil, err
	}
	return NewEncryptionMasterKey(key), nil
}

func DecryptBytes(encryptedValue string) ([]byte, error) {
	localMiniKmsAddress := os.Getenv(LOCAL_MINI_KMS_ADDRESS)
	if localMiniKmsAddress == "" {
		localMiniKmsAddress = "127.0.0.1:5567"
	}
	if !strings.HasPrefix(strings.ToLower(localMiniKmsAddress), "http://") {
		localMiniKmsAddress = fmt.Sprintf("http://%s", localMiniKmsAddress)
	}
	multiViewValue, err := Decrypt(localMiniKmsAddress, encryptedValue)
	if err != nil {
		fmt.Println("[ERROR] Decrypt from", localMiniKmsAddress, "failed, error:", err)
		return nil, err
	}
	valueBytes, err := hex.DecodeString(multiViewValue.ValueHex)
	if err != nil {
		return nil, err
	}
	return valueBytes, nil
}

func Decrypt(endpoint, encryptedValue string) (*MultiViewValue, error) {
	encryptRequest := EncryptRequest{
		EncryptedValue: encryptedValue,
	}
	encryptRequestBytes, err := json.Marshal(&encryptRequest)
	if err != nil {
		return nil, err
	}
	encryptRequestReader := bytes.NewReader(encryptRequestBytes)
	client := http.Client{
		Timeout: 5 * time.Second,
	}
	encryptResponse, err := client.Post(joinEnpointPath(endpoint, "/decrypt"), "application/json", encryptRequestReader)
	if err != nil {
		return nil, err
	}
	if encryptResponse.StatusCode != 200 {
		return nil, fmt.Errorf("decrypt failed, http status: %d", encryptResponse.StatusCode)
	}
	encryptResponseBodyBytes, err := io.ReadAll(encryptResponse.Body)
	if err != nil {
		return nil, err
	}
	var multiViewValue MultiViewValue
	err = json.Unmarshal(encryptResponseBodyBytes, &multiViewValue)
	if err != nil {
		return nil, err
	}
	return &multiViewValue, nil
}

func joinEnpointPath(endpoint, path string) string {
	endpointEndsWithSlash := strings.HasSuffix(endpoint, "/")
	pathStartsWithSlash := strings.HasPrefix(path, "/")
	if endpointEndsWithSlash && pathStartsWithSlash {
		return fmt.Sprintf("%s%s", endpoint, path[1:])
	} else if endpointEndsWithSlash || pathStartsWithSlash {
		return fmt.Sprintf("%s%s", endpoint, path)
	} else {
		return fmt.Sprintf("%s/%s", endpoint, path)
	}
}

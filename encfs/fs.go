package encfs

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/spf13/afero"
)

// copied from afero/os.go

const ENCRYPTED_FILE_NAME_PREFIX = "__ENCFS__"

type EncryptionMasterKey struct {
	key           []byte
	fileNameIv    []byte
	mutex         *sync.Mutex
	pathExistsMap map[string]bool
}

func NewEncryptionMasterKey(key []byte) *EncryptionMasterKey {
	return NewEncryptionMasterKeyWithFileNameIv(key, nil)
}

func NewEncryptionMasterKeyWithFileNameIv(key []byte, fileNameIv []byte) *EncryptionMasterKey {
	mutex := &sync.Mutex{}
	pathExistsMap := make(map[string]bool)
	return &EncryptionMasterKey{
		key,
		fileNameIv,
		mutex,
		pathExistsMap,
	}
}

func (k *EncryptionMasterKey) EncryptFileName(name string) string {
	if k.fileNameIv == nil {
		// DO NOT ENCRYPT
		return name
	}
	absName, err := filepath.Abs(name)
	if err != nil {
		// should not happen, file name is not encrypted
		return name
	}
	encryptedName := k.recursiveEncrpteFileName(absName)
	return encryptedName
}

func (k *EncryptionMasterKey) DecryptFileName(encryptedFileName string) string {
	if k.fileNameIv == nil {
		// DO NOT DECRYPT
		return encryptedFileName
	}
	encrytpedFileNameParts := strings.Split(encryptedFileName, "/")
	for i := 0; i < len(encrytpedFileNameParts); i++ {
		encrytpedFileNameParts[i] = k.decrypteFileNamePart(encrytpedFileNameParts[i])
	}
	return strings.Join(encrytpedFileNameParts, "/")
}

func (k *EncryptionMasterKey) existsPath(path string) bool {
	// perm store plaintext path in memory
	k.mutex.Lock()
	defer k.mutex.Unlock()
	if exists, found := k.pathExistsMap[path]; found {
		return exists
	}
	_, err := os.Stat(path)
	exists := err == nil
	k.pathExistsMap[path] = exists
	return exists
}

func (k *EncryptionMasterKey) recursiveEncrpteFileName(name string) string {
	if name == "" || name == "/" || k.existsPath(name) {
		return name
	}
	for strings.HasSuffix(name, "/") {
		name = strings.TrimSuffix(name, "/")
	}
	parentName, currentName := path.Split(name)
	parentName = k.recursiveEncrpteFileName(parentName)
	currentName = k.encryptFileNamePart(currentName)
	return path.Join(parentName, currentName)
}

func (k *EncryptionMasterKey) encryptFileNamePart(name string) string {
	if name == "" {
		return name
	}
	aesgcm, err := k.newAesGcm()
	if err != nil {
		// should not happen, file name is not encrypted
		return name
	}
	encryptedFileName := aesgcm.Seal(nil, k.fileNameIv, []byte(name), nil)
	return fmt.Sprintf("%s%s", ENCRYPTED_FILE_NAME_PREFIX, base64.RawURLEncoding.EncodeToString(encryptedFileName))
}

func (k *EncryptionMasterKey) decrypteFileNamePart(encrytpedFileNamePart string) string {
	if !strings.HasPrefix(encrytpedFileNamePart, ENCRYPTED_FILE_NAME_PREFIX) {
		// file name is not encrypted
		return encrytpedFileNamePart
	}
	prefixTrimedEncryptedFileName := strings.TrimPrefix(encrytpedFileNamePart, ENCRYPTED_FILE_NAME_PREFIX)
	encryptedFileNameBytes, err := base64.RawURLEncoding.DecodeString(prefixTrimedEncryptedFileName)
	if err != nil {
		// decode file name failed, file name should be incorrect
		return prefixTrimedEncryptedFileName
	}
	aesgcm, err := k.newAesGcm()
	if err != nil {
		// should not happen, file name must be incorrect
		return encrytpedFileNamePart
	}
	nameBytes, err := aesgcm.Open(nil, k.fileNameIv, encryptedFileNameBytes, nil)
	if err != nil {
		// should not happen, file name must be incorrect
		return encrytpedFileNamePart
	}
	return string(nameBytes)
}

func (k *EncryptionMasterKey) newAesGcm() (cipher.AEAD, error) {
	block, err := aes.NewCipher(k.key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

type EncFs struct {
	key *EncryptionMasterKey
}

func NewEncFs(key *EncryptionMasterKey) afero.Fs {
	return &EncFs{
		key: key,
	}
}

func (*EncFs) Name() string { return "EncFs" }

func (encFs *EncFs) Create(name string) (afero.File, error) {
	if err := encFs.checkFileExt(name); err != nil {
		return nil, err
	}
	name = encFs.key.EncryptFileName(name)
	f, e := os.Create(name)
	if f == nil {
		// while this looks strange, we need to return a bare nil (of type nil) not
		// a nil value of type *os.File or nil won't be nil
		return nil, e
	}
	return convertOsFileToEncFile(name, f, e, encFs, true)
}

func (encFs *EncFs) Mkdir(name string, perm os.FileMode) error {
	name = encFs.key.EncryptFileName(name)
	return os.Mkdir(name, perm)
}

func (encFs *EncFs) MkdirAll(path string, perm os.FileMode) error {
	path = encFs.key.EncryptFileName(path)
	return os.MkdirAll(path, perm)
}

func (encFs *EncFs) Open(name string) (afero.File, error) {
	if err := encFs.checkFileExt(name); err != nil {
		return nil, err
	}
	name = encFs.key.EncryptFileName(name)
	f, e := os.Open(name)
	if f == nil {
		// while this looks strange, we need to return a bare nil (of type nil) not
		// a nil value of type *os.File or nil won't be nil
		return nil, e
	}
	return convertOsFileToEncFile(name, f, e, encFs, false)
}

func (encFs *EncFs) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	if err := encFs.checkFileExt(name); err != nil {
		return nil, err
	}
	name = encFs.key.EncryptFileName(name)
	f, e := os.OpenFile(name, flag, perm)
	if f == nil {
		// while this looks strange, we need to return a bare nil (of type nil) not
		// a nil value of type *os.File or nil won't be nil
		return nil, e
	}
	return convertOsFileToEncFile(name, f, e, encFs, false)
}

func (encFs *EncFs) Remove(name string) error {
	name = encFs.key.EncryptFileName(name)
	encFileMetaName := name + EncFileExt
	_ = os.Remove(encFileMetaName)
	return os.Remove(name)
}

func (encFs *EncFs) RemoveAll(path string) error {
	path = encFs.key.EncryptFileName(path)
	fileInfo, err := os.Stat(path)
	if err == nil && !fileInfo.IsDir() {
		return encFs.Remove(path)
	}
	return os.RemoveAll(path)
}

func (encFs *EncFs) Rename(oldname, newname string) error {
	oldname = encFs.key.EncryptFileName(oldname)
	newname = encFs.key.EncryptFileName(newname)
	oldEncFileMetaName := oldname + EncFileExt
	newEncFileMetaName := newname + EncFileExt
	_ = os.Rename(oldEncFileMetaName, newEncFileMetaName)
	return os.Rename(oldname, newname)
}

func (encFs *EncFs) Stat(name string) (os.FileInfo, error) {
	name = encFs.key.EncryptFileName(name)
	return os.Stat(name)
}

func (encFs *EncFs) Chmod(name string, mode os.FileMode) error {
	name = encFs.key.EncryptFileName(name)
	return os.Chmod(name, mode)
}

func (encFs *EncFs) Chown(name string, uid, gid int) error {
	name = encFs.key.EncryptFileName(name)
	return os.Chown(name, uid, gid)
}

func (encFs *EncFs) Chtimes(name string, atime time.Time, mtime time.Time) error {
	name = encFs.key.EncryptFileName(name)
	return os.Chtimes(name, atime, mtime)
}

func (encFs *EncFs) LstatIfPossible(name string) (os.FileInfo, bool, error) {
	name = encFs.key.EncryptFileName(name)
	fi, err := os.Lstat(name)
	return fi, true, err
}

func (encFs *EncFs) SymlinkIfPossible(oldname, newname string) error {
	oldname = encFs.key.EncryptFileName(oldname)
	newname = encFs.key.EncryptFileName(newname)
	return os.Symlink(oldname, newname)
}

func (encFs *EncFs) ReadlinkIfPossible(name string) (string, error) {
	name = encFs.key.EncryptFileName(name)
	return os.Readlink(name)
}

func (encFS *EncFs) checkFileExt(name string) error {
	if encFS.key.fileNameIv != nil {
		// allow all file ext when file name is encrypted
		return nil
	}
	if strings.HasSuffix(name, EncFileExt) {
		return ErrFileForbiddenFileExt
	}
	return nil
}

func convertOsFileToEncFile(name string, file *os.File, e error, encFs *EncFs, isCreate bool) (afero.File, error) {
	if e != nil {
		return nil, e
	}
	encFile, err := NewEncFile(name, file, encFs, isCreate)
	if err != nil {
		return nil, err
	}
	return encFile, nil
}

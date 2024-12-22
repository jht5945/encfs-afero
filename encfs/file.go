package encfs

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"strings"
	"syscall"

	"github.com/spf13/afero"
)

const EncFileExt = ".__encfile"

var (
	ErrFileForbiddenFileExt = errors.New("file ext is forbidden")
)

type EncFileMeta struct {
	Name string `json:"name"`
	Iv   []byte `json:"iv"`
}

func openOrNewEncFileMeta(name string) (*EncFileMeta, error) {
	oldEncFileMeta, err := openEncFileMeta(name)
	if err == nil && oldEncFileMeta != nil {
		return oldEncFileMeta, nil
	}

	iv := make([]byte, 16)
	_, err = rand.Read(iv)
	if err != nil {
		return nil, err
	}
	encFileMeta := &EncFileMeta{
		Name: name,
		Iv:   iv,
	}
	encFileMetaName := name + EncFileExt
	encFileMetaFile, err := os.Create(encFileMetaName)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = encFileMetaFile.Close()
	}()
	encFileMetaBytes, err := marshalEncFileMeta(encFileMeta)
	if err != nil {
		return nil, err
	}
	_, err = encFileMetaFile.Write(encFileMetaBytes)
	if err != nil {
		return nil, err
	}
	return encFileMeta, nil
}

func openEncFileMeta(name string) (*EncFileMeta, error) {
	encFileMetaName := name + EncFileExt
	encFileMetaFile, err := os.Open(encFileMetaName)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() {
		_ = encFileMetaFile.Close()
	}()
	encFileMetaBytes, err := io.ReadAll(encFileMetaFile)
	if err != nil {
		return nil, err
	}
	encFileMeta, err := unmarchalEncFileMeta(encFileMetaBytes)
	if err != nil {
		return nil, err
	}
	return encFileMeta, nil
}

func marshalEncFileMeta(encFileMeata *EncFileMeta) ([]byte, error) {
	return json.Marshal(encFileMeata)
}

func unmarchalEncFileMeta(data []byte) (*EncFileMeta, error) {
	var encFileMeta EncFileMeta
	err := json.Unmarshal(data, &encFileMeta)
	if err != nil {
		return nil, err
	}
	return &encFileMeta, nil
}

type EncFileInfo struct {
	os.FileInfo
	encFile *EncFile
}

func (encFileInfo *EncFileInfo) Name() string {
	return encFileInfo.encFile.encFs.key.DecryptFileName(encFileInfo.FileInfo.Name())
}

func NewEncFileInfo(encFile *EncFile, fileInfo os.FileInfo) os.FileInfo {
	return &EncFileInfo{
		fileInfo,
		encFile,
	}
}

type EncFile struct {
	isDir       bool
	closed      bool
	encFileMeta *EncFileMeta
	encFs       *EncFs
	filePos     int64
	file        *os.File
}

func NewEncFile(name string, file *os.File, encFs *EncFs, isCreate bool) (*EncFile, error) {
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	isDir := fileInfo.IsDir()
	var encFileMeta *EncFileMeta = nil

	fileState, err := os.Stat(name)
	if err == nil && !fileState.IsDir() && fileState.Size() == 0 {
		isCreate = true
	}

	if !isDir {
		if isCreate {
			encFileMeta, err = openOrNewEncFileMeta(name)
		} else {
			encFileMeta, err = openEncFileMeta(name)
		}
		if err != nil {
			return nil, err
		}
	}
	return &EncFile{
		isDir:       isDir,
		closed:      false,
		encFileMeta: encFileMeta,
		encFs:       encFs,
		filePos:     0,
		file:        file,
	}, nil
}

func (f *EncFile) Close() error {
	if f.closed {
		return afero.ErrFileClosed
	}

	f.closed = true
	return f.file.Close()
}

func (f *EncFile) Read(p []byte) (n int, err error) {
	checkIsFileErr := f.checkIsFile()
	if checkIsFileErr != nil {
		return 0, checkIsFileErr
	}

	beforeReadFilePos := f.filePos
	readLen, err := f.file.Read(p)
	if err == nil {
		f.filePos += int64(readLen)
		if f.encFs != nil && f.encFs.key != nil && f.encFileMeta != nil {
			encryptedBytes, err := generateCtrEncryptBytes(f.encFs.key.key, f.encFileMeta.Iv, beforeReadFilePos, int64(readLen))
			if err != nil {
				return 0, err
			}
			for i := 0; i < readLen; i++ {
				p[i] = p[i] ^ encryptedBytes[i]
			}
		}
	}
	return readLen, err
}

func (f *EncFile) ReadAt(p []byte, off int64) (n int, err error) {
	checkIsFileErr := f.checkIsFile()
	if checkIsFileErr != nil {
		return 0, checkIsFileErr
	}

	readLen, err := f.file.ReadAt(p, off)
	if err == nil {
		if f.encFs != nil && f.encFs.key != nil && f.encFileMeta != nil {
			encryptedBytes, err := generateCtrEncryptBytes(f.encFs.key.key, f.encFileMeta.Iv, off, int64(readLen))
			if err != nil {
				return 0, err
			}
			for i := 0; i < readLen; i++ {
				p[i] = p[i] ^ encryptedBytes[i]
			}
		}
	}
	return readLen, err
}

func (f *EncFile) Seek(offset int64, whence int) (int64, error) {
	checkIsFileErr := f.checkIsFile()
	if checkIsFileErr != nil {
		return 0, checkIsFileErr
	}

	ret, err := f.file.Seek(offset, whence)
	if err == nil {
		f.filePos = ret
	}
	return ret, err
}

func (f *EncFile) Write(p []byte) (n int, err error) {
	checkIsFileErr := f.checkIsFile()
	if checkIsFileErr != nil {
		return 0, checkIsFileErr
	}

	writeBuff := p
	if f.encFs != nil && f.encFs.key != nil && f.encFileMeta != nil {
		buff := make([]byte, len(p))
		encryptedBytes, err := generateCtrEncryptBytes(f.encFs.key.key, f.encFileMeta.Iv, f.filePos, int64(len(p)))
		if err != nil {
			return 0, err
		}
		for i := 0; i < len(p); i++ {
			buff[i] = p[i] ^ encryptedBytes[i]
		}
		writeBuff = buff
	}

	writeLen, err := f.file.Write(writeBuff)
	if err == nil {
		f.filePos += int64(writeLen)
	}
	return writeLen, err
}

func (f *EncFile) WriteAt(p []byte, off int64) (n int, err error) {
	checkIsFileErr := f.checkIsFile()
	if checkIsFileErr != nil {
		return 0, checkIsFileErr
	}

	writeBuff := p
	if f.encFs != nil && f.encFs.key != nil && f.encFileMeta != nil {
		buff := make([]byte, len(p))
		encryptedBytes, err := generateCtrEncryptBytes(f.encFs.key.key, f.encFileMeta.Iv, off, int64(len(p)))
		if err != nil {
			return 0, err
		}
		for i := 0; i < len(p); i++ {
			buff[i] = p[i] ^ encryptedBytes[i]
		}
		writeBuff = buff
	}

	writeLen, err := f.file.WriteAt(writeBuff, off)
	return writeLen, err
}

func (f *EncFile) Name() string {
	return f.encFs.key.DecryptFileName(f.file.Name())
}

func (f *EncFile) Readdir(count int) ([]os.FileInfo, error) {
	if f.closed {
		return nil, afero.ErrFileClosed
	}

	// FIXME is count * 2 just ok?
	fileInfos, err := f.file.Readdir(count * 2)
	if err != nil {
		return nil, err
	}

	filterFileInfos := make([]os.FileInfo, 0)
	for _, fileInfo := range fileInfos {
		isEncFileMetaFile := strings.HasSuffix(fileInfo.Name(), EncFileExt)
		if !isEncFileMetaFile {
			filterFileInfos = append(filterFileInfos, NewEncFileInfo(f, fileInfo))
		}
		if count > 0 && len(filterFileInfos) >= count {
			break
		}
	}

	return filterFileInfos, nil
}

func (f *EncFile) Readdirnames(n int) ([]string, error) {
	fi, err := f.Readdir(n)
	if err != nil {
		return nil, err
	}

	var names []string
	for _, f := range fi {
		names = append(names, f.Name())
	}

	return names, nil
}

func (f *EncFile) Stat() (os.FileInfo, error) {
	fileInfo, err := f.file.Stat()
	if err != nil {
		return nil, err
	}
	return NewEncFileInfo(f, fileInfo), nil
}

func (f *EncFile) Sync() error {
	return f.file.Sync()
}

func (f *EncFile) Truncate(size int64) error {
	return f.file.Truncate(size)
}

func (f *EncFile) WriteString(s string) (ret int, err error) {
	return f.Write([]byte(s))
}

func (f *EncFile) checkIsFile() error {
	if f.closed {
		return afero.ErrFileClosed
	}
	if f.isDir {
		return syscall.EISDIR
	}
	return nil
}

func generateCtrEncryptBytes(key, iv []byte, offset, len int64) ([]byte, error) {
	endOffset := offset + len
	blockOffset := offset / 16
	encryptStartOffset := blockOffset * 16
	encryptEndOffset := (endOffset / 16) * 16
	if endOffset%16 > 0 {
		encryptEndOffset += 16
	}
	blocksCount := int((encryptEndOffset - encryptStartOffset) / 16)

	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	encryptBytes := make([]byte, blocksCount*16)
	for i := 0; i < blocksCount; i++ {
		encNonce := nonceAdd(iv, uint64(i)+uint64(blockOffset))
		cipher.Encrypt(encryptBytes[i*16:(i+1)*16], encNonce)
	}
	encryptedBytes := encryptBytes[offset-encryptStartOffset : offset-encryptStartOffset+len]
	//fmt.Println("XX", hex.EncodeToString(key), hex.EncodeToString(iv), offset, len, hex.EncodeToString(encryptedBytes))
	return encryptedBytes, nil
}

func nonceAdd(nonce []byte, incrementValue uint64) []byte {
	n1 := binary.BigEndian.Uint64(nonce[:8])
	n2 := binary.BigEndian.Uint64(nonce[8:])

	leftToMax := math.MaxUint64 - n2
	if leftToMax <= incrementValue {
		incrementValue -= leftToMax + 1
		n2 = incrementValue
		n1 += 1
	} else {
		n2 += incrementValue
	}

	newNonce := make([]byte, 16)
	binary.BigEndian.PutUint64(newNonce, n1)
	binary.BigEndian.PutUint64(newNonce[8:], n2)
	return newNonce
}

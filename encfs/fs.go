package encfs

import (
	"os"
	"strings"
	"time"

	"github.com/spf13/afero"
)

// copied from afero/os.go

type EncryptionMasterKey struct {
	key []byte
}

func NewEncryptionMasterKey(key []byte) *EncryptionMasterKey {
	return &EncryptionMasterKey{
		key,
	}
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
	if err := checkFileExt(name); err != nil {
		return nil, err
	}
	f, e := os.Create(name)
	if f == nil {
		// while this looks strange, we need to return a bare nil (of type nil) not
		// a nil value of type *os.File or nil won't be nil
		return nil, e
	}
	return convertOsFileToEncFile(name, f, e, encFs, true)
}

func (*EncFs) Mkdir(name string, perm os.FileMode) error {
	return os.Mkdir(name, perm)
}

func (*EncFs) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

func (encFs *EncFs) Open(name string) (afero.File, error) {
	if err := checkFileExt(name); err != nil {
		return nil, err
	}
	f, e := os.Open(name)
	if f == nil {
		// while this looks strange, we need to return a bare nil (of type nil) not
		// a nil value of type *os.File or nil won't be nil
		return nil, e
	}
	return convertOsFileToEncFile(name, f, e, encFs, false)
}

func (encFs *EncFs) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	if err := checkFileExt(name); err != nil {
		return nil, err
	}
	f, e := os.OpenFile(name, flag, perm)
	if f == nil {
		// while this looks strange, we need to return a bare nil (of type nil) not
		// a nil value of type *os.File or nil won't be nil
		return nil, e
	}
	return convertOsFileToEncFile(name, f, e, encFs, false)
}

func (*EncFs) Remove(name string) error {
	encFileMetaName := name + EncFileExt
	_ = os.Remove(encFileMetaName)
	return os.Remove(name)
}

func (encFs *EncFs) RemoveAll(path string) error {
	fileInfo, err := os.Stat(path)
	if err == nil && !fileInfo.IsDir() {
		return encFs.Remove(path)
	}
	return os.RemoveAll(path)
}

func (*EncFs) Rename(oldname, newname string) error {
	oldEncFileMetaName := oldname + EncFileExt
	newEncFileMetaName := newname + EncFileExt
	_ = os.Rename(oldEncFileMetaName, newEncFileMetaName)
	return os.Rename(oldname, newname)
}

func (*EncFs) Stat(name string) (os.FileInfo, error) {
	return os.Stat(name)
}

func (*EncFs) Chmod(name string, mode os.FileMode) error {
	return os.Chmod(name, mode)
}

func (*EncFs) Chown(name string, uid, gid int) error {
	return os.Chown(name, uid, gid)
}

func (*EncFs) Chtimes(name string, atime time.Time, mtime time.Time) error {
	return os.Chtimes(name, atime, mtime)
}

func (*EncFs) LstatIfPossible(name string) (os.FileInfo, bool, error) {
	fi, err := os.Lstat(name)
	return fi, true, err
}

func (*EncFs) SymlinkIfPossible(oldname, newname string) error {
	return os.Symlink(oldname, newname)
}

func (*EncFs) ReadlinkIfPossible(name string) (string, error) {
	return os.Readlink(name)
}

func checkFileExt(name string) error {
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

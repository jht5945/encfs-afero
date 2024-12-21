package encfs

import (
	"os"
	"path"
	"path/filepath"
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
	baseDirectory string
	key           *EncryptionMasterKey
}

func NewEncFs(key *EncryptionMasterKey) afero.Fs {
	return NewEncFsWithBaseDirecotry("", key)
}

func NewEncFsWithBaseDirecotry(baseDirectory string, key *EncryptionMasterKey) afero.Fs {
	return &EncFs{
		baseDirectory,
		key,
	}
}

func (*EncFs) Name() string { return "EncFs" }

func (encFs *EncFs) Create(name string) (afero.File, error) {
	if name = encFs.resolve(name); name == "" {
		return nil, os.ErrNotExist
	}
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

func (encFs *EncFs) Mkdir(name string, perm os.FileMode) error {
	if name = encFs.resolve(name); name == "" {
		return os.ErrNotExist
	}
	return os.Mkdir(name, perm)
}

func (encFs *EncFs) MkdirAll(path string, perm os.FileMode) error {
	if path = encFs.resolve(path); path == "" {
		return os.ErrNotExist
	}
	if path == filepath.Clean(encFs.baseDirectory) {
		// Prohibit removing the virtual root directory.
		return os.ErrInvalid
	}
	return os.MkdirAll(path, perm)
}

func (encFs *EncFs) Open(name string) (afero.File, error) {
	if name = encFs.resolve(name); name == "" {
		return nil, os.ErrNotExist
	}
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
	if name = encFs.resolve(name); name == "" {
		return nil, os.ErrNotExist
	}
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

func (encFs *EncFs) Remove(name string) error {
	if name = encFs.resolve(name); name == "" {
		return os.ErrNotExist
	}
	encFileMetaName := name + EncFileExt
	_ = os.Remove(encFileMetaName)
	return os.Remove(name)
}

func (encFs *EncFs) RemoveAll(path string) error {
	if path = encFs.resolve(path); path == "" {
		return os.ErrNotExist
	}
	if path == filepath.Clean(encFs.baseDirectory) {
		// Prohibit removing the virtual root directory.
		return os.ErrInvalid
	}
	fileInfo, err := os.Stat(path)
	if err == nil && !fileInfo.IsDir() {
		return encFs.Remove(path)
	}
	return os.RemoveAll(path)
}

func (encFs *EncFs) Rename(oldname, newname string) error {
	if oldname = encFs.resolve(oldname); oldname == "" {
		return os.ErrNotExist
	}
	if newname = encFs.resolve(newname); newname == "" {
		return os.ErrNotExist
	}
	if root := filepath.Clean(encFs.baseDirectory); root == oldname || root == newname {
		// Prohibit renaming from or to the virtual root directory.
		return os.ErrInvalid
	}
	oldEncFileMetaName := oldname + EncFileExt
	newEncFileMetaName := newname + EncFileExt
	_ = os.Rename(oldEncFileMetaName, newEncFileMetaName)
	return os.Rename(oldname, newname)
}

func (encFs *EncFs) Stat(name string) (os.FileInfo, error) {
	if name = encFs.resolve(name); name == "" {
		return nil, os.ErrNotExist
	}
	return os.Stat(name)
}

func (encFs *EncFs) Chmod(name string, mode os.FileMode) error {
	if name = encFs.resolve(name); name == "" {
		return os.ErrNotExist
	}
	return os.Chmod(name, mode)
}

func (encFs *EncFs) Chown(name string, uid, gid int) error {
	if name = encFs.resolve(name); name == "" {
		return os.ErrNotExist
	}
	return os.Chown(name, uid, gid)
}

func (encFs *EncFs) Chtimes(name string, atime time.Time, mtime time.Time) error {
	if name = encFs.resolve(name); name == "" {
		return os.ErrNotExist
	}
	return os.Chtimes(name, atime, mtime)
}

func (encFs *EncFs) LstatIfPossible(name string) (os.FileInfo, bool, error) {
	if name = encFs.resolve(name); name == "" {
		return nil, false, os.ErrNotExist
	}
	fi, err := os.Lstat(name)
	return fi, true, err
}

func (encFs *EncFs) SymlinkIfPossible(oldname, newname string) error {
	if oldname = encFs.resolve(oldname); oldname == "" {
		return os.ErrNotExist
	}
	if newname = encFs.resolve(newname); newname == "" {
		return os.ErrNotExist
	}
	if root := filepath.Clean(encFs.baseDirectory); root == oldname || root == newname {
		// Prohibit symlink from or to the virtual root directory.
		return os.ErrInvalid
	}
	return os.Symlink(oldname, newname)
}

func (encFs *EncFs) ReadlinkIfPossible(name string) (string, error) {
	if name = encFs.resolve(name); name == "" {
		return "", os.ErrNotExist
	}
	return os.Readlink(name)
}

// copy from: golang.org/x/net/webdav/file.go
func (encFs *EncFs) resolve(name string) string {
	if encFs.baseDirectory == "" {
		return name
	}
	// This implementation is based on Dir.Open's code in the standard net/http package.
	if filepath.Separator != '/' && strings.IndexRune(name, filepath.Separator) >= 0 ||
		strings.Contains(name, "\x00") {
		return ""
	}
	dir := string(encFs.baseDirectory)
	if dir == "" {
		dir = "."
	}
	return filepath.Join(dir, filepath.FromSlash(slashClean(name)))
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

// copy from: golang.org/x/net/webdav/file.go
// slashClean is equivalent to but slightly more efficient than
// path.Clean("/" + name).
func slashClean(name string) string {
	if name == "" || name[0] != '/' {
		name = "/" + name
	}
	return path.Clean(name)
}

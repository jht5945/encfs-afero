# encfs-afero


Sample code:
```go
package main

import "github.com/jht5945/encfs-afero/encfs"

func main() {
	fs := encfs.NewEncFs(encfs.NewEncryptionMasterKey(make([]byte, 32)))
	f, err := fs.Create("aa")
	if err != nil {
		println("Error: ", err)
		return
	}
	f.WriteString("hello world")
}
```


# encfs-afero


Used encryption algorithm AES-CTR.

File format:
* content.txt - Original file(Encrypted with AES/CTR)
* content.txt.__encfile - Meta file(original file name and IV)


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

Sample code will generate fiels:
```shell
-rw-r--r--  1 hatterjiang  staff     11 Dec 21 10:56 aa
-rw-r--r--  1 hatterjiang  staff     45 Dec 21 10:56 aa.__encfile
```

`aa` is encrypted file, and `aa.__encfile` is meta file.

```shell
$ cat aa.__encfile | jq .
{
  "name": "aa",
  "iv": "ue0IcDegDuwZjNgND1vUIQ=="
}
```


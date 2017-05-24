# aespro

## Usage:
`go get github.com/XuefengHuang/aespro`
## Example:
```
import (
    "github.com/XuefengHuang/aespro"
    "fmt"
)

func main() {
    /*
    *src encrypt_text
    *key length(128bit、192bit、256bit)
    *the length of key is 16 = 128bit
     */
    src := "exampleplaintext"
    key := "example key 1234"

    crypted := aes.CFBEncrypt(src, key)
    fmt.Println("crypted is: ", crypted)
    plain := aes.CFBDecrypt(crypted, key)
    fmt.Println("plain is: ", plain)
}
```
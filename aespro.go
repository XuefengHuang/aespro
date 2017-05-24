package aespro

import (
    "bytes"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "io"
    "strings"
)

func ECBDecrypt(crypted, key string) string {
    ciphertext, _ := base64.StdEncoding.DecodeString(crypted)
    block, err := aes.NewCipher([]byte(key))
    if err != nil {
        fmt.Println("err is:", err)
    }
    blockMode := NewECBDecrypter(block)
    origData := make([]byte, len(ciphertext))
    blockMode.CryptBlocks(origData, []byte(ciphertext))
    origData = PKCS5UnPadding(origData)
    return fmt.Sprintf("%s", origData)
}

func ECBEncrypt(src, key string) string {
    block, err := aes.NewCipher([]byte(key))
    if err != nil {
        fmt.Println("key error1", err)
    }
    if src == "" {
        fmt.Println("plain content empty")
    }
    ecb := NewECBEncrypter(block)
    content := []byte(src)
    content = PKCS5Padding(content, block.BlockSize())
    crypted := make([]byte, len(content))
    ecb.CryptBlocks(crypted, content)

    return base64.StdEncoding.EncodeToString(crypted)
}

func CBCDecrypt(crypted, key string) string {
    ciphertext, _ := base64.StdEncoding.DecodeString(crypted)

    block, err := aes.NewCipher([]byte(key))
    if err != nil {
        panic(err)
    }

    if len(ciphertext) < aes.BlockSize {
        panic("ciphertext too short")
    }
    iv := ciphertext[:aes.BlockSize]
    ciphertext = ciphertext[aes.BlockSize:]

    // CBC mode always works in whole blocks.
    if len(ciphertext)%aes.BlockSize != 0 {
        panic("ciphertext is not a multiple of the block size")
    }

    mode := cipher.NewCBCDecrypter(block, iv)

    // CryptBlocks can work in-place if the two arguments are the same.
    mode.CryptBlocks(ciphertext, ciphertext)

    return fmt.Sprintf("%s", ciphertext)
}
  
func CBCEncrypt(src, key string) string {
    plaintext := []byte(src)

    if len(plaintext)%aes.BlockSize != 0 {
      panic("plaintext is not a multiple of the block size")
    }

    block, err := aes.NewCipher([]byte(key))
    if err != nil {
      panic(err)
    }

    // The IV needs to be unique, but not secure. Therefore it's common to
    // include it at the beginning of the ciphertext.
    ciphertext := make([]byte, aes.BlockSize+len(plaintext))
    iv := ciphertext[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
      panic(err)
    }

    mode := cipher.NewCBCEncrypter(block, iv)
    mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

    return base64.StdEncoding.EncodeToString(ciphertext)
}

func CFBDecrypt(crypted, key string) string {
    ciphertext, _ := base64.StdEncoding.DecodeString(crypted)

    block, err := aes.NewCipher([]byte(key))
    if err != nil {
      panic(err)
    }

    // The IV needs to be unique, but not secure. Therefore it's common to
    // include it at the beginning of the ciphertext.
    if len(ciphertext) < aes.BlockSize {
      panic("ciphertext too short")
    }
    iv := ciphertext[:aes.BlockSize]
    ciphertext = ciphertext[aes.BlockSize:]

    stream := cipher.NewCFBDecrypter(block, iv)

    // XORKeyStream can work in-place if the two arguments are the same.
    stream.XORKeyStream(ciphertext, ciphertext)
    return fmt.Sprintf("%s", ciphertext)
}
  
func CFBEncrypt(src, key string) string {
    plaintext := []byte(src)

    block, err := aes.NewCipher([]byte(key))
    if err != nil {
      panic(err)
    }

    // The IV needs to be unique, but not secure. Therefore it's common to
    // include it at the beginning of the ciphertext.
    ciphertext := make([]byte, aes.BlockSize+len(plaintext))
    iv := ciphertext[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
      panic(err)
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

    return base64.StdEncoding.EncodeToString(ciphertext)
}

func Base64URLDecode(data string) ([]byte, error) {
    var missing = (4 - len(data)%4) % 4
    data += strings.Repeat("=", missing)
    res, err := base64.URLEncoding.DecodeString(data)
    fmt.Println("  decodebase64urlsafe is :", string(res), err)
    return base64.URLEncoding.DecodeString(data)
}

func Base64UrlSafeEncode(source []byte) string {
    // Base64 Url Safe is the same as Base64 but does not contain '/' and '+' (replaced by '_' and '-') and trailing '=' are removed.
    bytearr := base64.StdEncoding.EncodeToString(source)
    safeurl := strings.Replace(string(bytearr), "/", "_", -1)
    safeurl = strings.Replace(safeurl, "+", "-", -1)
    safeurl = strings.Replace(safeurl, "=", "", -1)
    return safeurl
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
    padding := blockSize - len(ciphertext)%blockSize
    padtext := bytes.Repeat([]byte{byte(padding)}, padding)
    return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
    length := len(origData)
    // 去掉最后一个字节 unpadding 次
    unpadding := int(origData[length-1])
    return origData[:(length - unpadding)]
}

type ecb struct {
    b         cipher.Block
    blockSize int
}

func newECB(b cipher.Block) *ecb {
    return &ecb{
        b:         b,
        blockSize: b.BlockSize(),
    }
}

type ecbEncrypter ecb

// NewECBEncrypter returns a BlockMode which encrypts in electronic code book
// mode, using the given Block.
func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
    return (*ecbEncrypter)(newECB(b))
}

func (x *ecbEncrypter) BlockSize() int { 
    return x.blockSize 
}

func (x *ecbEncrypter) CryptBlocks(dst, src []byte) {
    if len(src)%x.blockSize != 0 {
        panic("crypto/cipher: input not full blocks")
    }
    if len(dst) < len(src) {
        panic("crypto/cipher: output smaller than input")
    }
    for len(src) > 0 {
        x.b.Encrypt(dst, src[:x.blockSize])
        src = src[x.blockSize:]
        dst = dst[x.blockSize:]
    }
}

type ecbDecrypter ecb

// NewECBDecrypter returns a BlockMode which decrypts in electronic code book
// mode, using the given Block.
func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
    return (*ecbDecrypter)(newECB(b))
}

func (x *ecbDecrypter) BlockSize() int { 
    return x.blockSize 
}

func (x *ecbDecrypter) CryptBlocks(dst, src []byte) {
    if len(src)%x.blockSize != 0 {
        panic("crypto/cipher: input not full blocks")
    }
    if len(dst) < len(src) {
        panic("crypto/cipher: output smaller than input")
    }
    for len(src) > 0 {
        x.b.Decrypt(dst, src[:x.blockSize])
        src = src[x.blockSize:]
        dst = dst[x.blockSize:]
    }
}

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"

	"github.com/xdg-go/pbkdf2"
)

type Crypto struct {
	PassPhrase string
}

func (this Crypto) derivationKey(salt []byte) (key []byte, newSalt []byte) {
	if salt == nil {
		salt = make([]byte, aes.BlockSize)
		// http://www.ietf.org/rfc/rfc2898.txt
		if _, err := rand.Read(salt); err != nil {
			log.Println(err)
		}
	}

	key = pbkdf2.Key([]byte(this.PassPhrase), salt, 1000, 32, sha256.New)
	newSalt = salt
	return
}

func (this Crypto) CompareEncrypt(cipherRaw, saltRaw, data string) (equal bool) {
	salt, err := hex.DecodeString(saltRaw)
	if err != nil {
		log.Println(err)
		return
	}
	cipherText, err := hex.DecodeString(cipherRaw)
	if err != nil {
		log.Println(err)
		return
	}

	enc, _ := this.encryptBase([]byte(data), salt, cipherText)
	equal = enc == cipherRaw
	return
}
func (this Crypto) encryptBase(data, saltRaw, cipherRaw []byte) (res string, saltNew string) {
	key, salt := this.derivationKey(saltRaw)

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Println(err)
		return
	}

	cipherTextNew := make([]byte, aes.BlockSize+len(data))
	iv := cipherTextNew[:aes.BlockSize]
	if cipherRaw == nil {
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			log.Println(err)
			return
		}
	} else {
		copy(iv, cipherRaw[:aes.BlockSize])
	}

	cipher.NewOFB(block, iv).XORKeyStream(cipherTextNew[aes.BlockSize:], data)

	res = hex.EncodeToString(cipherTextNew)
	saltNew = hex.EncodeToString(salt)
	return
}
func (this Crypto) Encrypt(data []byte) (res string, salt string) {
	res, salt = this.encryptBase(data, nil, nil)
	return
}
func (this Crypto) Decrypt(saltRaw string, cipherRaw string) (res string) {
	salt, err := hex.DecodeString(saltRaw)
	if err != nil {
		log.Println(err)
		return
	}
	cipherText, err := hex.DecodeString(cipherRaw)
	if err != nil {
		log.Println(err)
		return
	}

	key, _ := this.derivationKey(salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Println(err)
	}

	dec := make([]byte, aes.BlockSize+len(cipherRaw))
	cipher.NewOFB(block, cipherText[:aes.BlockSize]).XORKeyStream(dec, cipherText[aes.BlockSize:])

	res = string(dec)
	return
}

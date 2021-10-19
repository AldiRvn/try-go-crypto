package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"io"
	"log"

	"github.com/xdg-go/pbkdf2"
)

type Crypto struct {
	PassPhrase string
	IvSize     int
	//? PBKDF2
	IterCount int
	KeyLen    int
	Hash      func() hash.Hash
}

func NewWithDefaultConfig(passPhrase string) Crypto {
	return Crypto{
		PassPhrase: passPhrase,
		IvSize:     aes.BlockSize,
		IterCount:  1000,
		KeyLen:     32,
		Hash:       sha512.New,
	}
}

func (this Crypto) derivationKey(salt []byte) (key []byte, newSalt []byte) {
	if salt == nil {
		salt = make([]byte, this.IvSize)
		// http://www.ietf.org/rfc/rfc2898.txt
		if _, err := rand.Read(salt); err != nil {
			log.Println(err)
		}
	}

	key = pbkdf2.Key([]byte(this.PassPhrase), salt, this.IterCount, this.KeyLen, this.Hash)
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

	cipherTextNew := make([]byte, this.IvSize+len(data))
	iv := cipherTextNew[:this.IvSize]
	if cipherRaw == nil {
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			log.Println(err)
			return
		}
	} else {
		copy(iv, cipherRaw[:this.IvSize])
	}

	cipher.NewOFB(block, iv).XORKeyStream(cipherTextNew[this.IvSize:], data)

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

	dec := make([]byte, this.IvSize+len(cipherRaw))
	cipher.NewOFB(block, cipherText[:this.IvSize]).XORKeyStream(dec, cipherText[this.IvSize:])

	res = string(dec)
	return
}

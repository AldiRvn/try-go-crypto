package main

import "log"

func main() {
	crypto := Crypto{PassPhrase: "76b8e2c3f7c84de0b83eace56d36ae93"}

	enc, salt := crypto.Encrypt([]byte("test-ws"))
	log.Println("Encrypt:\t", enc)
	log.Println("Salt:\t", salt)

	dec := crypto.Decrypt(salt, enc)
	log.Println("Dec:\t", dec)

	log.Println("Compare:\t", crypto.CompareEncrypt(enc, salt, "test-ws"))
}

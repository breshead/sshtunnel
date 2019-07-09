package sshtunnel

import (
	"golang.org/x/crypto/ssh"
	"io/ioutil"
)

func PrivateKeyFile(file string) ssh.AuthMethod {
	buffer, err := ioutil.ReadFile(file)
	if err != nil {
		return nil
	}

	key, err := ssh.ParsePrivateKey(buffer)
	if err != nil {
		return nil
	}

	return ssh.PublicKeys(key)
}

// Allow the user to get the keyfile contents in whatever manner they
// want. e.g. go-bindata for embedded assets
func PrivateKey(key_buffer []byte) ssh.AuthMethod {
	key, err := ssh.ParsePrivateKey(key_buffer)
	if err != nil {
		return nil
	}

	return ssh.PublicKeys(key)
}

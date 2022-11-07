package device

import (
	"encoding/hex"
	"fmt"

	"github.com/tjfoc/gmsm/sm4"
)

type Cipher interface {
	Encrypt(dst, src []byte) error
	Decrypt(dst, src []byte) error
}

type Sm4Cipher struct {
	key [sm4.BlockSize]byte
}

func (c *Sm4Cipher) Encrypt(dst, src []byte) error {
	if src == nil {
		return nil
	}

	d, err := sm4.Sm4Ecb(c.key[:], src, true)
	if err == nil {
		copy(dst, d)
	}

	return err
}

func (c *Sm4Cipher) Decrypt(dst, src []byte) error {
	d, err := sm4.Sm4Ecb(c.key[:], src, false)
	fmt.Printf("Decrypt: src=%s, d= %s\n",
		hex.EncodeToString(src[:]),
		hex.EncodeToString(d[:]))
	if err == nil {
		copy(dst, d)
	}
	return err
}

func NewSm4Cipher(key []byte) Cipher {
	c := new(Sm4Cipher)
	copy(c.key[:], key)
	return c
}

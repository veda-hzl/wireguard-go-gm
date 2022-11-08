package device

import (
	"encoding/hex"

	"github.com/tjfoc/gmsm/sm4"
)

type Cipher interface {
	Encrypt(dst, src []byte) (int, error)
	Decrypt(dst, src []byte) (int, error)
	GetKeyString() string
}

type Sm4Cipher struct {
	key [sm4.BlockSize]byte
}

func (c *Sm4Cipher) Encrypt(dst, src []byte) (int, error) {
	if src == nil {
		return 0, nil
	}
	d, err := sm4.Sm4Ecb(c.key[:], src, true)
	l := len(d)
	if err == nil {
		dst = append(dst, d...)
	}
	return l, err
}

func (c *Sm4Cipher) Decrypt(dst, src []byte) (int, error) {
	d, err := sm4.Sm4Ecb(c.key[:], src, false)
	l := len(d)
	if err == nil {
		dst = append(dst, d...)
	}
	return l, err
}

func (c *Sm4Cipher) GetKeyString() string {
	return hex.EncodeToString(c.key[:])
}

func NewSm4Cipher(key []byte) Cipher {
	c := new(Sm4Cipher)
	copy(c.key[:], key)
	return c
}

package random

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateRandomHex(t *testing.T) {
	// automatic genertae 16 bytes
	for i := 0; i < 5; i++ {
		randomStr, err := RandomHex(16)
		assert.NoError(t, err, "random hex faild")
		assert.NotEmpty(t, randomStr, "random hex string is empty")
	}

	// automatic genertae 24 bytes
	for i := 0; i < 5; i++ {
		randomStr, err := RandomHex(24)
		assert.NoError(t, err, "random hex faild")
		assert.NotEmpty(t, randomStr, "random hex string is empty")
	}

	// automatic genertae 32 bytes
	for i := 0; i < 5; i++ {
		randomStr, err := RandomHex(32)
		assert.NoError(t, err, "random hex faild")
		assert.NotEmpty(t, randomStr, "random hex string is empty")
	}
}

func TestGenerateRandomBytes(t *testing.T) {
	// automatic genertae 16 bytes
	for i := 0; i < 5; i++ {
		randomStr, err := RandomBytes(16)
		assert.NoError(t, err, "random bytes faild")
		assert.NotEmpty(t, randomStr, "random hex string is empty")
	}

	// automatic genertae 24 bytes
	for i := 0; i < 5; i++ {
		randomStr, err := RandomBytes(24)
		assert.NoError(t, err, "random bytes faild")
		assert.NotEmpty(t, randomStr, "random hex string is empty")
	}

	// automatic genertae 32 bytes
	for i := 0; i < 5; i++ {
		randomStr, err := RandomBytes(32)
		assert.NoError(t, err, "random bytes faild")
		assert.NotEmpty(t, randomStr, "random hex string is empty")
	}
}

func TestRandomPassword(t *testing.T) {
	password, err := RandomPassword(10)
	assert.NoError(t, err, "random password faild")
	assert.NotEqual(t, 0, password, "random password is empty")
}

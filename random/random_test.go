package random

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateRandomIntRange(t *testing.T) {
	for i := 0; i < 5; i++ {
		_, err := RandomIntRange(10, 20)
		assert.NoError(t, err, "random int range faild")
	}
}

func TestGenerateRandomInt(t *testing.T) {
	for i := 0; i < 5; i++ {
		_, err := RandomInt(100)
		assert.NoError(t, err, "random int faild")
	}
}

package random

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

var ErrN = fmt.Errorf("n must be positive")

// RandomIntRange generate an integer within the min - max range randomly
func RandomIntRange(min, max int64) (int64, error) {
	if min > max {
		return 0, fmt.Errorf("min cannot be greater than max")
	}

	if min == max {
		return min, nil
	}
	n := max - min + 1

	r, err := RandomInt(n)
	if err != nil {
		return 0, nil
	}

	return min + r, nil
}

// RandomInt generate n random integers
func RandomInt(n int64) (int64, error) {
	if n <= 0 {
		return 0, ErrN
	}

	a, _ := rand.Int(rand.Reader, big.NewInt(n))
	return a.Int64(), nil
}

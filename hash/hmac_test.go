package hash

import "testing"

func TestNewHMac(t *testing.T) {
	type args struct {
		i   hashType
		key []byte
		s   string
	}
	tests := []struct {
		name   string
		args   args
		wantSs string
	}{
		// test HMAC-MD5
		{
			name: "Test HMAC-MD5",
			args: args{
				i:   0,
				key: []byte("123456"),
				s:   "looking for funs",
			},
			wantSs: "3bd32fb8a55fa7aee35451daf62d56ae",
		},

		// test HMAC-SHA1
		{
			name: "Test HMAC-SHA1",
			args: args{
				i:   1,
				key: []byte("123456"),
				s:   "looking for funs",
			},
			wantSs: "58fcfcc2a228be74cf3a5d7f0b2010850b8e3896",
		},

		// test HMAC-SHA224
		{
			name: "Test HMAC-SHA224",
			args: args{
				i:   2,
				key: []byte("123456"),
				s:   "looking for funs",
			},
			wantSs: "2ee848321890ba9865ee7682765ebdb8c6dfdb5cf110e31bc31bf414",
		},

		// test HMAC-SHA256
		{
			name: "Test HMAC-SHA256",
			args: args{
				i:   3,
				key: []byte("123456"),
				s:   "looking for funs",
			},
			wantSs: "500ded5c0c404221f8d95ad82ec638d1fa797b8f8ab6e14b4b8830b1c16069f4",
		},

		// test HMAC-SHA384
		{
			name: "Test HMAC-SHA384",
			args: args{
				i:   4,
				key: []byte("123456"),
				s:   "looking for funs",
			},
			wantSs: "2710c6cce2170f8fc490876969f349b232e6b1581412e36815a1a6276654825b3381903284ae1e62cb34dd2c0b122659",
		},

		// test HMAC-SHA512
		{
			name: "Test HMAC-SHA512",
			args: args{
				i:   5,
				key: []byte("123456"),
				s:   "looking for funs",
			},
			wantSs: "43ea0342266ecbc692ed27b1fc784e688e1c20c7da699d2d990c5aba408d69f8f2e34b71b00d79b093b7c6a8c77e062d3572a5b435cf5f88245aa9353742b3ba",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotSs := NewHMac(tt.args.i, tt.args.key, tt.args.s); gotSs != tt.wantSs {
				t.Errorf("NewHMac() = %v, want %v", gotSs, tt.wantSs)
			}
		})
	}
}

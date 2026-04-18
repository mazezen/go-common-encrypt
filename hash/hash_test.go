package hash

import "testing"

func TestNewHash(t *testing.T) {
	type args struct {
		i hashType
		s string
	}
	tests := []struct {
		name   string
		args   args
		wantSs string
	}{
		// test md5
		{
			name: "Test MD5",
			args: args{
				i: 0,
				s: "123456",
			},
			wantSs: "e10adc3949ba59abbe56e057f20f883e",
		},
		{
			name: "Test MD5",
			args: args{
				i: 0,
				s: "The fog is getting thicker!",
			},
			wantSs: "bd009e4d93affc7c69101d2e0ec4bfde",
		},
		{
			name: "Test MD5",
			args: args{
				i: 0,
				s: "And Leon's getting laaarger!",
			},
			wantSs: "c6ebdd6560ae23b6eaa38bddb51df2bc",
		},

		// test sha1
		{
			name: "Test SHA-1",
			args: args{
				i: 1,
				s: "123456",
			},
			wantSs: "7c4a8d09ca3762af61e59520943dc26494f8941b",
		},

		// test sha224
		{
			name: "Test SHA-224",
			args: args{
				i: 2,
				s: "123456",
			},
			wantSs: "f8cdb04495ded47615258f9dc6a3f4707fd2405434fefc3cbf4ef4e6",
		},

		// test sha256
		{
			name: "Test SHA-256",
			args: args{
				i: 3,
				s: "123456",
			},
			wantSs: "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92",
		},

		// test sha384
		{
			name: "Test SHA-384",
			args: args{
				i: 4,
				s: "123456",
			},
			wantSs: "0a989ebc4a77b56a6e2bb7b19d995d185ce44090c13e2984b7ecc6d446d4b61ea9991b76a4c2f04b1b4d244841449454",
		},

		// test sha512
		{
			name: "Test SHA-512",
			args: args{
				i: 5,
				s: "123456",
			},
			wantSs: "ba3253876aed6bc22d4a6ff53d8406c6ad864195ed144ab5c87621b6c233b548baeae6956df346ec8c17f5ea10f35ee3cbc514797ed7ddd3145464e2a0bab413",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotSs := NewHash(tt.args.i, tt.args.s); gotSs != tt.wantSs {
				t.Errorf("NewHash() = %v, want %v", gotSs, tt.wantSs)
			}
		})
	}
}

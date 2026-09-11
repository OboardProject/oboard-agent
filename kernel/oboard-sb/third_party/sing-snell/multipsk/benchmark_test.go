package multipsk_test

import (
	"crypto/rand"
	"fmt"
	snell "github.com/sagernet/sing-snell"
	"testing"
)

// Above 64 candidates this measures protocol cost only, not product capacity.
// A fresh salt per iteration prevents connection-key reuse from hiding KDF cost.
func BenchmarkSnellCandidateAuthentication(b *testing.B) {
	for _, size := range []int{1, 10, 50, 100, 500} {
		for _, warm := range []bool{false, true} {
			b.Run(fmt.Sprintf("credentials_%d/warm_%t", size, warm), func(b *testing.B) {
				keys := make([][]byte, size)
				for i := range keys {
					keys[i] = []byte(fmt.Sprintf("independent-credential-%08d", i))
				}
				salt := make([]byte, snell.SaltLen)
				nonce := make([]byte, snell.NonceLen)
				payload := []byte{snell.HeaderVersion, 0, 0, 0, 0, 0, 0}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					b.StopTimer()
					if _, e := rand.Read(salt); e != nil {
						b.Fatal(e)
					}
					writer, e := snell.NewAEAD(snell.DeriveKey(keys[size-1], salt))
					if e != nil {
						b.Fatal(e)
					}
					header := writer.Seal(nil, nonce, payload, nil)
					b.StartTimer()
					start := 0
					if warm {
						start = size - 1
					}
					matched := false
					for j := start; j < size; j++ {
						aead, e := snell.NewAEAD(snell.DeriveKey(keys[j], salt))
						if e != nil {
							b.Fatal(e)
						}
						if _, e = aead.Open(nil, nonce, header, nil); e == nil {
							matched = true
							break
						}
					}
					if !matched {
						b.Fatal("matching credential not found")
					}
				}
			})
		}
	}
}

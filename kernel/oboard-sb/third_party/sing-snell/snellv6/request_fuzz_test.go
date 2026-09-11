package snellv6

import (
	"github.com/sagernet/sing/common/buf"
	"testing"
)

func FuzzFirstRequest(f *testing.F) {
	for _, seed := range [][]byte{{}, {1}, {0, 5, 0, 0}, {0, 1, 255}, {0, 6, 0}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65535 {
			t.Skip()
		}
		b := buf.NewSize(len(data))
		defer b.Release()
		_, _ = b.Write(data)
		s := &Service{}
		_, _ = s.readRequest(b)
	})
}

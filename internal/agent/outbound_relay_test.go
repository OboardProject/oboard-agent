package agent

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"testing"
)

func TestFramedRelayPacketConnWritePayloadBounds(t *testing.T) {
	for _, payload := range [][]byte{nil, make([]byte, 65536)} {
		conn := &framedRelayPacketConn{}
		if _, err := conn.Write(payload); err == nil {
			t.Fatalf("payload length %d was accepted", len(payload))
		}
	}

	writer, reader := net.Pipe()
	defer writer.Close()
	defer reader.Close()
	payload := make([]byte, 65535)
	readResult := make(chan error, 1)
	go func() {
		frame := make([]byte, len(payload)+2)
		if _, err := io.ReadFull(reader, frame); err != nil {
			readResult <- err
			return
		}
		if got := binary.BigEndian.Uint16(frame[:2]); got != math.MaxUint16 {
			readResult <- fmt.Errorf("relay frame size = %d, want %d", got, math.MaxUint16)
			return
		}
		readResult <- nil
	}()
	conn := &framedRelayPacketConn{Conn: writer}
	if n, err := conn.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("write max payload = %d, %v", n, err)
	}
	if err := <-readResult; err != nil {
		t.Fatal(err)
	}
}

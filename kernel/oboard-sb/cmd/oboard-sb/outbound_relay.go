package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	box "github.com/sagernet/sing-box"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var relayOutboundTagPattern = regexp.MustCompile(`^(?:path-[1-9][0-9]*-step-[1-9][0-9]*|warp-[1-9][0-9]*)$`)

type outboundRelayLookup func(tag string) (N.Dialer, bool)

func registerOutboundRelayHandlers(mux *http.ServeMux, listen string, instance *box.Box) {
	if !strings.HasPrefix(listen, "unix:") {
		return
	}
	lookup := func(tag string) (N.Dialer, bool) {
		if instance == nil {
			return nil, false
		}
		outbound, loaded := instance.Outbound().Outbound(tag)
		if !loaded {
			return nil, false
		}
		return outbound, true
	}
	mux.Handle("/outbounds/relay/tcp", newOutboundRelayHandler("tcp", lookup))
	mux.Handle("/outbounds/relay/udp", newOutboundRelayHandler("udp", lookup))
}

func newOutboundRelayHandler(network string, lookup outboundRelayLookup) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		tag := strings.TrimSpace(r.Header.Get("X-OBoard-Outbound-Tag"))
		if !relayOutboundTagPattern.MatchString(tag) {
			http.Error(w, "outbound tag is not relayable", http.StatusBadRequest)
			return
		}
		destination := M.ParseSocksaddr(strings.TrimSpace(r.Header.Get("X-OBoard-Destination")))
		if !destination.IsValid() || destination.Port == 0 {
			http.Error(w, "invalid destination", http.StatusBadRequest)
			return
		}
		dialer, loaded := lookup(tag)
		if !loaded || dialer == nil {
			http.Error(w, "outbound not found", http.StatusNotFound)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		target, err := dialer.DialContext(ctx, network, destination)
		cancel()
		if err != nil {
			http.Error(w, "destination connection failed", http.StatusBadGateway)
			return
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			_ = target.Close()
			http.Error(w, "connection hijacking unavailable", http.StatusInternalServerError)
			return
		}
		client, buffered, err := hijacker.Hijack()
		if err != nil {
			_ = target.Close()
			return
		}
		_, _ = buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		if err := buffered.Flush(); err != nil {
			_ = client.Close()
			_ = target.Close()
			return
		}
		if network == "udp" {
			go relayFramedUDP(client, buffered.Reader, target)
			return
		}
		go relayTCPStream(client, buffered.Reader, target)
	})
}

func relayTCPStream(client net.Conn, reader *bufio.Reader, target net.Conn) {
	defer client.Close()
	defer target.Close()
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(target, reader)
		_ = target.Close()
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, target)
		_ = client.Close()
		done <- struct{}{}
	}()
	<-done
	<-done
}

func relayFramedUDP(client net.Conn, reader *bufio.Reader, target net.Conn) {
	defer client.Close()
	defer target.Close()
	done := make(chan struct{}, 2)
	go func() {
		var size [2]byte
		for {
			if _, err := io.ReadFull(reader, size[:]); err != nil {
				break
			}
			length := int(binary.BigEndian.Uint16(size[:]))
			if length == 0 {
				continue
			}
			payload := make([]byte, length)
			if _, err := io.ReadFull(reader, payload); err != nil {
				break
			}
			if written, err := target.Write(payload); err != nil || written != len(payload) {
				break
			}
		}
		_ = target.Close()
		done <- struct{}{}
	}()
	go func() {
		payload := make([]byte, math.MaxUint16)
		var size [2]byte
		for {
			n, err := target.Read(payload)
			if err != nil {
				break
			}
			if n == 0 {
				continue
			}
			binary.BigEndian.PutUint16(size[:], uint16(n)) // #nosec G115 -- n cannot exceed the payload buffer length.
			if err := writeRelayParts(client, size[:], payload[:n]); err != nil {
				break
			}
		}
		_ = client.Close()
		done <- struct{}{}
	}()
	<-done
	<-done
}

func writeRelayParts(writer io.Writer, parts ...[]byte) error {
	for _, part := range parts {
		for len(part) > 0 {
			n, err := writer.Write(part)
			if err != nil {
				return err
			}
			if n == 0 {
				return errors.New("short relay write")
			}
			part = part[n:]
		}
	}
	return nil
}

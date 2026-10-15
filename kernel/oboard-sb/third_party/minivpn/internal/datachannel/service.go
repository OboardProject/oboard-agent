package datachannel

//
// OpenVPN data channel
//

import (
	"bytes"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/internal/workers"
	"github.com/ooni/minivpn/pkg/config"
)

var (
	serviceName = "datachannel"
)

// pingPayload is the OpenVPN keepalive magic carried inside a data packet.
var pingPayload = []byte{0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48}

const (
	defaultPingSeconds        = 10
	defaultPingRestartSeconds = 60
	minPingRestartSeconds     = 5
)

// keepaliveTimers derives the ping interval and the inactivity timeout from
// the server-pushed values, falling back to bounded defaults.
func keepaliveTimers(info model.TunnelInfo) (time.Duration, time.Duration) {
	ping := info.PingSeconds
	if ping <= 0 {
		ping = defaultPingSeconds
	}
	restart := info.PingRestartSeconds
	if restart <= 0 {
		restart = defaultPingRestartSeconds
	}
	if restart < minPingRestartSeconds {
		restart = minPingRestartSeconds
	}
	if ping >= restart {
		ping = restart / 2
	}
	return time.Duration(ping) * time.Second, time.Duration(restart) * time.Second
}

// Service is the datachannel service. Make sure you initialize
// the channels before invoking [Service.StartWorkers].
type Service struct {
	// MuxerToData moves packets up to us
	MuxerToData chan *model.Packet

	// DataOrControlToMuxer is a shared channel to write packets to the muxer layer below
	DataOrControlToMuxer *chan *model.Packet

	// TUNToData moves bytes down from the TUN layer above
	TUNToData chan []byte

	// DataToTUN moves bytes up from us to the TUN layer above us
	DataToTUN chan []byte

	// KeyReady is where the TLSState layer passes us any new keys
	KeyReady chan *session.DataChannelKey
}

// StartWorkers starts the data-channel workers.
//
// We start three workers:
//
// 1. moveUpWorker BLOCKS on dataPacketUp to read a packet coming from the muxer and
// eventually BLOCKS on tunUp to deliver it;
//
// 2. moveDownWorker BLOCKS on tunDown to read a packet and
// eventually BLOCKS on dataOrControlToMuxer to deliver it;
//
// 3. keyWorker BLOCKS on keyUp to read a dataChannelKey and
// initializes the internal state with the resulting key;
func (s *Service) StartWorkers(
	config *config.Config,
	workersManager *workers.Manager,
	sessionManager *session.Manager,
) {
	dc, err := NewDataChannelFromOptions(config.Logger(), config.OpenVPNOptions(), sessionManager)
	if err != nil {
		config.Logger().Warnf("cannot initialize channel %v", err)
		return
	}
	ws := &workersState{
		dataChannel:          dc,
		dataOrControlToMuxer: *s.DataOrControlToMuxer,
		dataToTUN:            s.DataToTUN,
		keyReady:             s.KeyReady,
		logger:               config.Logger(),
		muxerToData:          s.MuxerToData,
		sessionManager:       sessionManager,
		tunToData:            s.TUNToData,
		workersManager:       workersManager,
	}

	firstKeyReady := make(chan any)

	workersManager.StartWorker(ws.moveUpWorker)
	workersManager.StartWorker(func() { ws.moveDownWorker(firstKeyReady) })
	workersManager.StartWorker(func() { ws.keyWorker(firstKeyReady) })
}

// workersState contains the data channel state.
type workersState struct {
	dataChannel          *DataChannel
	dataOrControlToMuxer chan<- *model.Packet
	dataToTUN            chan<- []byte
	keyReady             <-chan *session.DataChannelKey
	logger               model.Logger
	muxerToData          <-chan *model.Packet
	sessionManager       *session.Manager
	tunToData            <-chan []byte
	workersManager       *workers.Manager

	// lastReceived is the unix nano time of the last authenticated data packet.
	lastReceived atomic.Int64
}

// moveDownWorker moves packets down the stack. It will BLOCK on PacketDown
func (ws *workersState) moveDownWorker(firstKeyReady <-chan any) {
	workerName := serviceName + ":moveDownWorker"
	defer func() {
		ws.workersManager.OnWorkerDone(workerName)
		ws.workersManager.StartShutdown()
	}()

	ws.logger.Debugf("%s: started", workerName)

	select {
	// wait for the first key to be ready
	case <-firstKeyReady:
		pingEvery, restartAfter := keepaliveTimers(ws.sessionManager.TunnelInfo())
		ws.lastReceived.Store(time.Now().UnixNano())
		ticker := time.NewTicker(pingEvery)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				// Sending and encrypting stay on this goroutine: the HMAC state is
				// not safe for concurrent use.
				if time.Since(time.Unix(0, ws.lastReceived.Load())) > restartAfter {
					ws.logger.Warnf("%s: no data from server for %s, closing tunnel", workerName, restartAfter)
					return
				}
				packet, err := ws.dataChannel.writePacket(pingPayload)
				if err != nil {
					ws.logger.Warnf("error encrypting keepalive: %v", err)
					continue
				}
				select {
				case ws.dataOrControlToMuxer <- packet:
				case <-ws.workersManager.ShouldShutdown():
					return
				}
			case data := <-ws.tunToData:
				// TODO: writePacket should get the ACTIVE KEY (verify this)
				packet, err := ws.dataChannel.writePacket(data)
				if err != nil {
					ws.logger.Warnf("error encrypting: %v", err)
					continue
				}

				select {
				case ws.dataOrControlToMuxer <- packet:
				case <-ws.workersManager.ShouldShutdown():
					return
				}

			case <-ws.workersManager.ShouldShutdown():
				return
			}
		}
	case <-ws.workersManager.ShouldShutdown():
		return
	}
}

// moveUpWorker moves packets up the stack
func (ws *workersState) moveUpWorker() {
	workerName := fmt.Sprintf("%s: moveUpWorker", serviceName)

	defer func() {

		ws.workersManager.OnWorkerDone(workerName)
		ws.workersManager.StartShutdown()
	}()
	ws.logger.Debugf("%s: started", workerName)

	for {
		select {
		// TODO: opportunistically try to kill lame duck

		case pkt := <-ws.muxerToData:
			// TODO(ainghazal): factor out as handler function
			decrypted, err := ws.dataChannel.readPacket(pkt)
			if err != nil {
				ws.logger.Warnf("error decrypting: %v", err)
				continue
			}

			ws.lastReceived.Store(time.Now().UnixNano())
			if bytes.Equal(decrypted, pingPayload) {
				continue
			}

			select {
			case ws.dataToTUN <- decrypted:
			case <-ws.workersManager.ShouldShutdown():
				return
			}
		case <-ws.workersManager.ShouldShutdown():
			return
		}
	}
}

// keyWorker receives notifications from key ready
func (ws *workersState) keyWorker(firstKeyReady chan<- any) {
	workerName := fmt.Sprintf("%s: keyWorker", serviceName)

	defer func() {
		ws.workersManager.OnWorkerDone(workerName)
		ws.workersManager.StartShutdown()
	}()

	ws.logger.Debugf("%s: started", workerName)
	once := &sync.Once{}

	for {
		select {
		case key := <-ws.keyReady:
			// TODO(ainghazal): thread safety here - need to lock.
			// When we actually get to key rotation, we need to add locks.
			// Use RW lock, reader locks.

			err := ws.dataChannel.setupKeys(key)
			if err != nil {
				ws.logger.Warnf("error on key derivation: %v", err)
				continue
			}
			ws.sessionManager.SetNegotiationState(model.S_GENERATED_KEYS)
			once.Do(func() {
				close(firstKeyReady)
			})

		case <-ws.workersManager.ShouldShutdown():
			return
		}
	}
}

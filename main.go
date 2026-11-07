// Relay server: peers join a room and exchange messages (broadcast to the room or send to one peer).
//
// Protocol (TCP):
//
//  1. Registration — a single JSON line ending with '\n':
//     client -> {"room_id": 1}\n
//     server -> {"peer_id": "<32 hex>", "room_id": 1}\n
//     peer_id is 16 bytes in hex; the client decodes it back to 16 bytes for the addr field.
//
//  2. After that, binary frames in both directions:
//     [LEN uint32 BE][MSG_TYPE 1 byte][ADDR 16 bytes][payload]
//     LEN = length of everything after it (1 + 16 + len(payload)).
//     client -> server: ADDR = recipient for SEND, ignored for BROADCAST (send zeros).
//     server -> client: ADDR = sender, so the receiver knows who the message is from.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

const (
	listenAddr = "0.0.0.0:8080"

	MsgBroadcast byte = 1
	MsgSend      byte = 2

	MsgTypeLen = 1
	AddrLen    = 16
	HeaderLen  = MsgTypeLen + AddrLen

	maxFrame        = 64 * 1024 // max LEN; larger frames drop the connection
	registerTimeout = 10 * time.Second
	writeTimeout    = 5 * time.Second
	shutdownTimeout = 10 * time.Second
)

// ---------- types ----------

type PeerID [AddrLen]byte

func (id PeerID) String() string { return hex.EncodeToString(id[:]) }

func newPeerID() (PeerID, error) {
	var id PeerID
	if _, err := rand.Read(id[:]); err != nil {
		return id, err
	}
	id[6] = (id[6] & 0x0f) | 0x40 // UUID v4
	id[8] = (id[8] & 0x3f) | 0x80 // RFC 4122 variant
	return id, nil
}

type RegisterRequest struct {
	RoomID int64 `json:"room_id"`
}

type RegisterResponse struct {
	PeerID string `json:"peer_id"`
	RoomID int64  `json:"room_id"`
}

type PeerInfo struct {
	PeerID      PeerID
	RoomID      int64
	ConnectedAt time.Time
}

type Peer struct {
	Info    PeerInfo
	conn    net.Conn
	r       *bufio.Reader
	writeMu sync.Mutex // several goroutines may write to one conn — frames must not interleave
}

func (p *Peer) writeFrame(typ byte, addr PeerID, payload []byte) error {
	frame := make([]byte, 4+HeaderLen+len(payload))
	binary.BigEndian.PutUint32(frame[0:4], uint32(HeaderLen+len(payload)))
	frame[4] = typ
	copy(frame[4+MsgTypeLen:4+HeaderLen], addr[:])
	copy(frame[4+HeaderLen:], payload)

	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	p.conn.SetWriteDeadline(time.Now().Add(writeTimeout)) // a stuck client must not block the others
	_, err := p.conn.Write(frame)
	return err
}

func readFrame(r *bufio.Reader) (typ byte, addr PeerID, payload []byte, err error) {
	var hdr [4]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n < HeaderLen || n > maxFrame {
		err = fmt.Errorf("bad frame length %d", n)
		return
	}
	buf := make([]byte, n)
	if _, err = io.ReadFull(r, buf); err != nil {
		return
	}
	typ = buf[0]
	copy(addr[:], buf[MsgTypeLen:HeaderLen])
	payload = buf[HeaderLen:]
	return
}

// ---------- hub: registry of peers and rooms behind one mutex ----------

type Hub struct {
	mu    sync.Mutex
	peers map[PeerID]*Peer
	rooms map[int64]map[PeerID]*Peer
}

func NewHub() *Hub {
	return &Hub{peers: make(map[PeerID]*Peer), rooms: make(map[int64]map[PeerID]*Peer)}
}

func (h *Hub) add(p *Peer) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.peers[p.Info.PeerID] = p
	room, ok := h.rooms[p.Info.RoomID]
	if !ok {
		room = make(map[PeerID]*Peer)
		h.rooms[p.Info.RoomID] = room
	}
	room[p.Info.PeerID] = p
}

func (h *Hub) remove(p *Peer) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.peers, p.Info.PeerID)
	if room, ok := h.rooms[p.Info.RoomID]; ok {
		delete(room, p.Info.PeerID)
		if len(room) == 0 {
			delete(h.rooms, p.Info.RoomID)
		}
	}
}

func (h *Hub) get(id PeerID) (*Peer, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	p, ok := h.peers[id]
	return p, ok
}

// roomPeers returns a copy of the room's peer list so writes can happen without holding the lock.
func (h *Hub) roomPeers(roomID int64) []*Peer {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]*Peer, 0, len(h.rooms[roomID]))
	for _, p := range h.rooms[roomID] {
		out = append(out, p)
	}
	return out
}

// ---------- message handling ----------

func (h *Hub) broadcast(from *Peer, payload []byte) {
	for _, other := range h.roomPeers(from.Info.RoomID) {
		if other == from {
			continue
		}
		if err := other.writeFrame(MsgBroadcast, from.Info.PeerID, payload); err != nil {
			log.Printf("broadcast to %s: %v", other.Info.PeerID, err)
			other.conn.Close() // its handlePeer will exit and remove it from the hub
		}
	}
}

func (h *Hub) send(from *Peer, to PeerID, payload []byte) {
	target, ok := h.get(to)
	if !ok || target.Info.RoomID != from.Info.RoomID {
		log.Printf("send from %s: peer %s not found in room %d", from.Info.PeerID, to, from.Info.RoomID)
		return
	}
	if err := target.writeFrame(MsgSend, from.Info.PeerID, payload); err != nil {
		log.Printf("send to %s: %v", to, err)
		target.conn.Close()
	}
}

func (h *Hub) handlePeer(p *Peer) {
	for {
		typ, addr, payload, err := readFrame(p.r)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				log.Printf("peer %s: %v", p.Info.PeerID, err)
			}
			return
		}
		switch typ {
		case MsgBroadcast:
			h.broadcast(p, payload)
		case MsgSend:
			h.send(p, addr, payload)
		default:
			log.Printf("peer %s: unknown msg type %d", p.Info.PeerID, typ)
		}
	}
}

// register reads the JSON registration line and creates the peer.
func register(conn net.Conn, r *bufio.Reader) (*Peer, error) {
	conn.SetReadDeadline(time.Now().Add(registerTimeout))
	line, err := r.ReadSlice('\n') // capped at the bufio buffer size (4 KB)
	if err != nil {
		return nil, fmt.Errorf("read register: %w", err)
	}
	conn.SetReadDeadline(time.Time{})

	var req RegisterRequest
	if err := json.Unmarshal(line, &req); err != nil {
		return nil, fmt.Errorf("bad register json: %w", err)
	}
	id, err := newPeerID()
	if err != nil {
		return nil, err
	}
	p := &Peer{
		Info: PeerInfo{PeerID: id, RoomID: req.RoomID, ConnectedAt: time.Now()},
		conn: conn,
		r:    r,
	}

	resp, _ := json.Marshal(RegisterResponse{PeerID: id.String(), RoomID: req.RoomID})
	conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if _, err := conn.Write(append(resp, '\n')); err != nil {
		return nil, err
	}
	return p, nil
}

func (h *Hub) serveConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() }) // on shutdown, break the blocking Read
	defer stop()

	r := bufio.NewReaderSize(conn, 4096)
	p, err := register(conn, r)
	if err != nil {
		log.Printf("%s: %v", conn.RemoteAddr(), err)
		return
	}
	// add to the hub only after the response is sent, so the client never gets a frame before its peer_id
	h.add(p)
	defer h.remove(p)
	log.Printf("peer %s joined room %d from %s", p.Info.PeerID, p.Info.RoomID, conn.RemoteAddr())
	defer log.Printf("peer %s left room %d", p.Info.PeerID, p.Info.RoomID)

	h.handlePeer(p)
}

// ---------- main + graceful shutdown ----------

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on %s", ln.Addr())
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	hub := NewHub()
	var wg sync.WaitGroup
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break // normal shutdown
			}
			log.Printf("accept: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			hub.serveConn(ctx, conn)
		}()
	}

	log.Print("shutting down...")
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		log.Print("bye")
	case <-time.After(shutdownTimeout):
		log.Print("shutdown timeout, exiting anyway")
	}
}

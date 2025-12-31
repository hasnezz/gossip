package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

const (
	MessageHeartbeat MessageType = iota
	MessageStateMachineCommand
)

type Node struct {
	id        NodeID
	addr      string
	conn      net.PacketConn
	blacklist map[string]int // addr -> illgeal tries
	debug     bool
	sm        StateMachine

	peers   map[NodeID]*Peer
	peersMu sync.Mutex
}

var _ GossipNode = (*Node)(nil)

func NewNode(id NodeID, addr string, sm StateMachine, debug bool) *Node {
	return &Node{
		id:        id,
		addr:      addr,
		blacklist: map[string]int{},
		peers:     map[NodeID]*Peer{},
		sm:        sm,
		debug:     debug,
	}
}

func (n *Node) Init(seed []string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", n.addr)
	if err != nil {
		log.Warn("invalid address", zap.String("addr", n.addr), zap.Error(err))
		return err
	}

	n.conn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	log.Info("node up and running", zap.String("id", string(n.id)), zap.String("addr", n.addr))

	// send HB's to seed nodes
	for _, s := range seed {
		if len(s) == 0 {
			continue
		}

		addr, err := net.ResolveUDPAddr("udp", s)
		if err != nil {
			log.Warn("invalid seed address", zap.String("addr", s), zap.Error(err))
			continue
		}

		payload := HBDetails{
			ID:    n.id,
			Addr:  n.addr,
			Peers: []Peer{},
		}

		n.heartbeatTo(payload, addr)
	}

	go n.heartbeat()
	n.recvloop()

	return nil
}

func (n *Node) Stop() error {
	return n.conn.Close()
}

func (n *Node) Peers() []Peer {
	return mapValues(n.peers)
}

func (n *Node) Broadcast(m Message) error {
	n.peersMu.Lock()
	defer n.peersMu.Unlock()

	encodedMsg, err := json.Marshal(m)
	if err != nil {
		return err
	}

	for _, peer := range n.peers {
		udpAddr, err := net.ResolveUDPAddr("udp", peer.Addr)
		if err != nil {
			log.Warn("invalid address", zap.String("addr", peer.Addr), zap.Error(err))
			continue
		}

		n.conn.WriteTo(encodedMsg, udpAddr) // TODO: collect errors
	}

	return nil
}

func (n *Node) recvloop() {
	buff := make([]byte, 1024*4)
	for {
		l, addr, err := n.conn.ReadFrom(buff)
		if err != nil {
			log.Debug("failed to receive message", zap.String("toAddr", n.addr), zap.Error(err))
			continue
		}
		log.Debug("received a message", zap.Int("length", l), zap.String("addr", addr.String()))

		if n.blacklist[addr.String()] >= BlacklistThreshold {
			log.Warn("ignoring a blacklisted member", zap.String("addr", n.addr))
			continue // ignore messages coming from blacklist members
		}

		var msg Message
		if err := json.Unmarshal(buff[:l], &msg); err != nil {
			log.Debug("error unmarshaling json message", zap.String("addr", addr.String()), zap.Error(err), zap.Int("length", l))
			continue
		}

		n.handleMessage(msg, addr)
	}
}

func (n *Node) heartbeat() {
	// TODO: handle routine cancellation
	for {
		n.peersMu.Lock()
		n.displayPeers()
		for id, peer := range n.peers {
			if id == n.id {
				continue
			}

			log.Debug("sending hearbeat", zap.String("toPeerId", string(id)))

			udpAddr, err := net.ResolveUDPAddr("udp", peer.Addr)
			if err != nil {
				log.Warn("invalid address", zap.String("addr", peer.Addr), zap.Error(err))
				continue
			}

			payload := HBDetails{
				ID:    n.id,
				Addr:  n.addr,
				Peers: mapValues(n.peers),
			}

			n.heartbeatTo(payload, udpAddr)
		}
		n.peersMu.Unlock()

		time.Sleep(HearbeatTick)
	}
}

func (n *Node) heartbeatTo(payload HBDetails, addr net.Addr) {
	encodedPayload, err := json.Marshal(payload)
	if err != nil {
		log.Error("failed to serialize heartbeat payload", zap.Error(err))
		return
	}

	msg := Message{
		Type: MessageHeartbeat,
		Raw:  hex.EncodeToString(encodedPayload),
		Sig:  hex.EncodeToString(signMessage(encodedPayload)),
	}

	var encodedMessage []byte
	if encodedMessage, err = json.Marshal(msg); err != nil {
		log.Error("failed to serialize heartbeat message", zap.Error(err))
		return
	}

	if _, err := n.conn.WriteTo(encodedMessage, addr); err != nil {
		log.Error("failed to send heartbeat", zap.Error(err))
		return
	}
}

func (n *Node) handleMessage(msg Message, senderAddr net.Addr) {
	sig, err := hex.DecodeString(msg.Sig)
	if err != nil {
		log.Debug("received a bad hex value", zap.String("addr", senderAddr.String()), zap.Error(err))
	}

	data, err := hex.DecodeString(msg.Raw)
	if err != nil {
		log.Debug("received a bad hex value", zap.String("addr", senderAddr.String()), zap.Error(err))
	}

	if !verifyMessage(sig, data) {
		n.blacklist[senderAddr.String()]++
		log.Warn("receoived invalid sig", zap.String("addr", senderAddr.String()))
		return
	}

	switch msg.Type {
	case MessageHeartbeat:
		log.Debug("received a hearbeat", zap.String("addr", senderAddr.String()))

		var hb HBDetails
		if err := json.Unmarshal(data, &hb); err != nil {
			log.Debug("received a hearbeat", zap.String("addr", senderAddr.String()))
		}

		now := uint64(time.Now().UnixNano())
		n.peersMu.Lock()
		defer n.peersMu.Unlock()

		peer, ok := n.peers[hb.ID]
		if !ok {
			peer = &Peer{
				ID:       hb.ID,
				Addr:     hb.Addr,
				Lastseen: now,
			}
			n.peers[hb.ID] = peer
		}

		peer.Lastseen = now

		for _, p := range hb.Peers {
			if _, ok := n.peers[p.ID]; !ok && p.ID != n.id {
				n.peers[p.ID] = &p
			}
		}
	}
}

func (n *Node) displayPeers() {
	if !n.debug {
		return
	}

	print("\033[2J\033[H")

	// Header
	fmt.Printf(
		"%-20s %-22s %-10s %-12s\n",
		"ID", "ADDR", "STATE", "LAST SEEN",
	)
	fmt.Println(strings.Repeat("-", 70))

	now := time.Now()

	for id, peer := range n.peers {
		state := "DEAD"
		if isPeerAlive(peer) {
			state = "ALIVE"
		}

		lastSeenAgo := time.Duration(
			now.UnixNano() - int64(peer.Lastseen),
		).Truncate(time.Millisecond)

		fmt.Printf(
			"%-20s %-22s %-10s %-12s\n",
			id,
			peer.Addr,
			state,
			lastSeenAgo,
		)
	}
}

type Message struct {
	Type MessageType `json:"type"`
	Raw  string      `json:"raw"`
	Sig  string      `json:"sig"`
}

type HBDetails struct {
	ID    NodeID `json:"id"`
	Addr  string `json:"addr"`
	Peers []Peer `json:"peers"`
}

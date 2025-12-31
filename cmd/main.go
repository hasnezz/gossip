package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

const (
	HearbeatTick       = time.Second * 1
	DeadPeerThreshold  = 5 // missed HB's to consider peer dead
	BlacklistThreshold = 3 // three illegal signatures mark the node in the blacklist
)

const (
	NodeFollower  = "NodeFollower"
	NodeCandidate = "NodeCandidate"
	NodeLeader    = "NodeLeader"
)

const (
	MessageHeartbeat MessageType = iota
)

const (
	OpUpdate OpType = iota
	OpDelete
)

var ClusterSecret []byte
var log *zap.Logger

type (
	NodeID      string
	MessageType uint32
	OpType      uint32
)

type Peer struct {
	ID       NodeID `json:"id"`
	Addr     string `json:"addr"`
	Lastseen uint64 `json:"lastseen"`
}

type GossipNode interface {
	Init() error
	Peers() []Peer
	Broadcast(Message) error
	Stop() error
}

type Node struct {
	id        NodeID
	addr      string
	role      string
	conn      net.PacketConn
	blacklist map[string]int // addr -> illgeal tries

	peers   map[NodeID]*Peer
	peersMu sync.Mutex
}

var _ GossipNode = (*Node)(nil)

func NewNode(id NodeID, addr string, seed map[NodeID]*Peer) *Node {
	return &Node{
		id:        NodeID(addr),
		addr:      addr,
		peers:     seed,
		role:      NodeFollower,
		blacklist: map[string]int{},
	}
}

func (n *Node) Init() error {
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

	go n.hearbeat()
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

func (n *Node) hearbeat() {
	// TODO: handle routine cancellation
	for {
		time.Sleep(HearbeatTick)

		n.peersMu.Lock()
		for id, peer := range n.peers {
			if len(id) < 3 || id == n.id {
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
				Role:  n.role,
				Peers: mapValues(n.peers),
			}

			var encodedPayload []byte
			if encodedPayload, err = json.Marshal(payload); err != nil {
				log.Error("failed to serialize heartbeat payload", zap.Error(err))
			}

			msg := Message{
				Type: MessageHeartbeat,
				Raw:  hex.EncodeToString(encodedPayload),
				Sig:  hex.EncodeToString(signMessage(encodedPayload)),
			}

			var encodedMessage []byte
			if encodedMessage, err = json.Marshal(msg); err != nil {
				log.Error("failed to serialize heartbeat message", zap.Error(err))
			}

			if _, err := n.conn.WriteTo(encodedMessage, udpAddr); err != nil {
				log.Error("failed to send heartbeat", zap.Error(err))
			}
		}
		n.displayPeers()
		n.peersMu.Unlock()
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
	if !strings.Contains(n.addr, ":") {
		print("\033[2J\033[H")
	}

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
	Role  string `json:"role"`
	Peers []Peer `json:"peers"`
}

func signMessage(data []byte) []byte {
	h := hmac.New(sha256.New, ClusterSecret)
	h.Write(data)
	return h.Sum(nil)
}

func verifyMessage(sig []byte, data []byte) bool {
	mac := hmac.New(sha256.New, ClusterSecret)
	mac.Write(data)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(expectedMAC, sig)
}

func mapValues(m map[NodeID]*Peer) []Peer {
	l := make([]Peer, 0, 100)
	for _, value := range m {
		l = append(l, *value)
	}
	return l
}

func isPeerAlive(peer *Peer) bool {
	return time.Now().UnixNano()-int64(peer.Lastseen) <= HearbeatTick.Nanoseconds()*DeadPeerThreshold
}

type Command struct {
	Op    OpType
	Key   string
	Value []byte
}

type StateMachine interface {
	Apply(Command) error
	Get(key string) ([]byte, bool)
}

func main() {
	id := flag.String("id", "", "Node ID")
	addr := flag.String("addr", "127.0.0.1:4100", "Listen address")
	seeds := flag.String("seed", "", "List of peer addresses")
	secret := flag.String("secret", "123", "Cluster HMAC address")
	flag.Parse()

	var err error
	log, err = zap.NewProduction()
	if err != nil {
		panic(err)
	}
	defer log.Sync()

	ClusterSecret = []byte(*secret)

	seedMap := map[NodeID]*Peer{}
	for s := range strings.SplitSeq(*seeds, ",") {
		if len(s) > 0 {
			seedMap[NodeID(s)] = &Peer{
				ID:   NodeID(s),
				Addr: s,
			}
		}
	}

	if *id == "" {
		id = addr
	}

	n := NewNode(NodeID(*id), *addr, seedMap)
	if err := n.Init(); err != nil {
		panic(err)
	}
}

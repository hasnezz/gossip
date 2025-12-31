package main

import (
	"flag"
	"net"
	"strings"
	"time"

	"go.uber.org/zap"
)

/*
	Leaderless invariants:
	1. Clients talk to one node
	2. Nodes talk to nodes
	3. Quorums live in nodes
*/

const (
	HearbeatTick       = time.Second * 1
	DeadPeerThreshold  = 5 // missed HB's to consider peer dead
	BlacklistThreshold = 3 // how many illegal signatures received to mark node as a blacklist member
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

type Command struct {
	Op    OpType
	Key   string
	Value []byte
}

type APIServer struct {
	addr net.Addr
	node GossipNode
}

func NewAPIServer(n *Node, sm StateMachine) *APIServer {
	return &APIServer{
		node: n,
	}
}

func main() {
	id := flag.String("id", "", "Node ID")
	addr := flag.String("addr", "127.0.0.1:4100", "Listen address")
	seeds := flag.String("seed", "", "List of peer addresses")
	secret := flag.String("secret", "123", "Cluster HMAC address")
	debug := flag.Bool("debug", true, "Debug mode")
	flag.Parse()

	var err error
	log, err = zap.NewProduction()
	if err != nil {
		panic(err)
	}
	defer log.Sync()

	ClusterSecret = []byte(*secret)

	if *id == "" {
		id = addr
	}

	n := NewNode(NodeID(*id), *addr, nil, *debug)
	if err := n.Init(strings.Split(*seeds, ",")); err != nil {
		panic(err)
	}
}

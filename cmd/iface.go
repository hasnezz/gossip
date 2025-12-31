package main

type GossipNode interface {
	Init(seed []string) error
	Peers() []Peer
	Broadcast(Message) error
	Stop() error
}

type StateMachine interface {
	Apply(Command) error
	Get(key string) ([]byte, bool)
}

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"time"
)

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

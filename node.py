import sys
import socket
import threading
import time
import cbor2 as cbor
import datetime
import logging
import hashlib
import hmac

from dataclasses import dataclass, asdict
from enum import Enum


BUFF_SIZE = 1024 * 4
HB_SLEEP = 2
ALLOWED_PEER_LATENCY = 5
MSG_ACCECPTED_DELAY = 5
CLUSTER_SECRET = b"123"
HOST = "0.0.0.0"

Addr = tuple[str, int]


class Role(Enum):
    FOLLOWER = "FOLLOWER"
    CANDIDATE = "CANDIDATE"
    LEADER = "LEADER"


@dataclass
class Peer:
    id: str
    addr: Addr
    lastseen_ts: int = 0

    @staticmethod
    def from_dict(d: dict):
        a = None
        if isinstance(d['addr'], list):
            a = tuple(d['addr'])
        elif isinstance(d['addr'], str):
            host, port = d["addr"].split(":")
            a =  (host, int(port))
        return Peer(
            id=d["id"],
            addr=a,
            lastseen_ts=d.get("lastseen_ts")
        )
    


class Node:
    def __init__(self, addr: Addr, peers: list[Peer]) -> None:
        self.id = f"node-{addr[1]}"
        self.addr = addr
        self.peers = {p.id: p for p in peers}
        self.role = Role.FOLLOWER
        self.peer = Peer(id=self.id, addr=self.addr)

        self.stop_event = threading.Event()
        self.sock = self._start_socket()

        self.heartbeat_thread = threading.Thread(
            target=self._heartbeat,
            name=f"{self.id}-hb",
            daemon=True,
        )
        self.heartbeat_thread.start()

        self.recv_thread = threading.Thread(
            target=self._recvloop,
            name=f"{self.id}-recv",
            daemon=True,
        )
        self.recv_thread.start()

    def _log(self, msg: str, level=logging.DEBUG):
        if level == logging.DEBUG:
            logging.debug(msg)
        elif level == logging.INFO:
            logging.info(msg)

    def _start_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(self.addr)
        sock.settimeout(1)
        self._log("up and listening", logging.INFO)
        return sock

    def _is_alive(self, id: str) -> bool:
        now = datetime.datetime.now(datetime.UTC).timestamp()
        return now - self.peers[id].lastseen_ts <= ALLOWED_PEER_LATENCY

    def _recvloop(self):
        self._log("recv loop running", logging.INFO)
        while not self.stop_event.is_set():
            try:
                data, addr = self.sock.recvfrom(BUFF_SIZE)
                decoded = cbor.loads(data)

                if isinstance(decoded, dict) and \
                    "sig" in decoded and \
                    verify_message(decoded) and \
                    abs(time.time() - decoded.get("ts", 0)) <= MSG_ACCECPTED_DELAY:
                        self._handle_message(decoded)

            except (socket.timeout, ValueError):
                continue
            except OSError:
                break

        self._log("recv loop stopped", logging.INFO)

    def _handle_message(self, msg: dict):
        sender = msg.get("sender", None)
        if not sender:
            print('did not found sender data')
            return
        sender = Peer.from_dict(sender)

        if sender.id not in self.peers:
            self.peers[sender.id] = sender

        if "type" in msg and msg["type"] == "HB":
            self._log(f"received a hearbeat from {sender.id}")
            self.peers[sender.id].lastseen_ts = datetime.datetime.now(
                datetime.UTC
            ).timestamp()

            for p in msg.get("peers", []):
                if p["id"] not in self.peers:
                    self.peers[p["id"]] = Peer(
                        id=p["id"],
                        addr=(p["addr"][0], int(p["addr"][1])),
                        lastseen_ts=int(p["lastseen_ts"]),
                    )
            return

        self._log(f"received validated msg from {sender}")

    def _heartbeat(self):
        while not self.stop_event.is_set():
            time.sleep(HB_SLEEP)

            for peer in self.peers.values():
                if peer.addr == self.addr:
                    continue

                msg = {
                    "sender": asdict(self.peer),
                    "type": "HB",
                    "peers": [asdict(p) for p in self.peers.values()],
                    "ts": time.time()
                }
                msg['sig'] = sign_message(msg)
                self.sock.sendto(cbor.dumps(msg), peer.addr)
                self._log(f"sent a HB to {peer.id} addr: {peer.addr}")

            self.display_peers()

    def display_peers(self):
        print("----- Peers -----")
        for p in self.peers.values():
            if p.addr == self.addr:
                continue
            status = "alive" if self._is_alive(p.id) else "dead"
            print(f"{p.id} - {status}")

    # TODO: add a background job to remove dead peers :/

    def stop(self):
        self.stop_event.set()
        self.sock.close()

    def send(self, msg: dict, addr: Addr):
        self._log(f"trying to send to {addr}")
        self.sock.sendto(cbor.dumps(msg), addr)


def parse_peers() -> list[Peer]:
    peers = [
        line[:-1] if line[-1] == "\n" else line
        for line in open("peers.txt", "r").readlines()
        if len(line) > 3
    ]
    if not peers:
        return []
    peers = {(p.split(":")[0], int(p.split(":")[1])) for p in peers}

    return [
        Peer(
            id=f"node-{p[1]}",
            addr=p,
            lastseen_ts=datetime.datetime.now(datetime.UTC).timestamp(),
        )
        for p in peers
    ]



def sign_message(msg: dict) -> bytes:
    unsigned = dict(msg)
    unsigned.pop("sig", None)
    raw = cbor.dumps(unsigned)
    return hmac.new(CLUSTER_SECRET, raw, hashlib.sha256).digest()


def verify_message(msg: dict) -> bool:
    if "sig" not in msg:
        return False
    expected = sign_message(msg)
    return hmac.compare_digest(msg["sig"], expected)


def main():
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
    )

    if len(sys.argv) < 2:
        print("please select a port")
        return

    port = int(sys.argv[1])
    seed = []
    if len(sys.argv) >= 3:
        seed_port = int(sys.argv[2])
        seed.append(Peer(f"node-{seed_port}", (HOST, seed_port)))

    Node((HOST, port), seed)

    open("peers.txt", "a+").write(HOST + ":" + str(port) + "\n")
    input()


if __name__ == "__main__":
    main()

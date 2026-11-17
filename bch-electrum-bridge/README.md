# bch-electrum-bridge

This bridge exists only for wallets that do not support the Bitcoin Cash P2P
protocol. A wallet that does should be a P2P light client itself, through the
`bch-light-client` library, and talk to nodes directly.

It answers the Electrum protocol (newline-delimited JSON-RPC over TCP) for
such wallets. Every answer comes from the library: block headers, script
filters (type 1), input prefix filters (type 2) and whole blocks read from
Bitcoin Cash nodes over P2P, the mempool from ordinary transaction relay, and
double-spend proofs from relay. The bridge adds only the protocol framing,
the subscriptions and the answer shapes; it keeps no index of addresses,
transactions or histories.

Run it beside the wallet, on the same machine, and point the wallet at it:

    bch-electrum-bridge --network mainnet --datadir ~/.bch-bridge \
        --peer node1.example:8333 --peer node2.example:8333 \
        [--proxy 127.0.0.1:9050] [--birthday HEIGHT] --listen 127.0.0.1:50001

The nodes must serve script filters (filter type 1); for `blockchain.rpa.*`
they must also serve input prefix filters (type 2). With `--proxy`, every
block is fetched over a Tor circuit of its own; see the library's
documentation for what peers can and cannot learn.

`blockchain.rpa.*` follows Fulcrum's limits: prefixes of 8 to 16 bits, at most
60 blocks per call. Lookups by transaction ID alone need filters with
transaction keys; until the nodes serve them, such lookups work for
transactions in the mempool and in histories the wallet asked for.
`daemon.passthrough` is not available: there is no node RPC behind the bridge.

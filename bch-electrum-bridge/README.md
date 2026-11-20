# bch-electrum-bridge

This bridge exists only for wallets that do not support the Bitcoin Cash P2P
protocol. A wallet that does should be a P2P light client itself, through the
`bch-light-client` library, and talk to nodes directly.

It answers the Electrum protocol (newline-delimited JSON-RPC over TCP) for
such wallets. Every answer comes from the library: block headers, script
filters (type 1) and whole blocks read from Bitcoin Cash nodes over P2P, the mempool from ordinary transaction relay, and
double-spend proofs from relay. The bridge adds only the protocol framing,
the subscriptions and the answer shapes; it keeps no index of addresses,
transactions or histories.

Run it beside the wallet, on the same machine, and point the wallet at it:

    bch-electrum-bridge --network mainnet --datadir ~/.bch-bridge \
        --peer node1.example:8333 --peer node2.example:8333 \
        [--proxy 127.0.0.1:9050] [--birthday HEIGHT] --listen 127.0.0.1:50001

It listens on a loopback address only, and refuses any other `--listen`:
it serves wallets on this machine, never a network.

At least one node must serve script filters (filter type 1).
`blockchain.rpa.*` needs no input prefix filters: each search reads every
block of its range, which names no prefix. Only with `--rpa-filters` does it
read the blocks a node's input prefix filters (type 2) point to. Every
`--peer` is connected. A node that serves no filters, such as BCHN, is kept
for headers, blocks, transaction relay, its mempool and double-spend proofs,
and is never asked for filters. A node that offers no bloom filters (kth
today) does not answer the mempool message, so the transactions already in
its mempool when the bridge connects are missed, and kth relays no
double-spend proofs: give a BCHN node beside it for those.

The library's protections are on by default:
- Every block, and every broadcast, comes over a connection of its own. With
  `--proxy`, that is a Tor circuit of its own.
- Each block a lookup needs brings three decoys from its bucket of 144
  heights. The decoys are the same in every session.
- A transaction found once is not downloaded again.
- The bridge introduces itself to nodes with Bitcoin Cash Node's user
  agent, not a name of its own.

`--no-block-isolation`, `--decoy-blocks`, `--rpa-filters` and `--user-agent`
change these. See the library's documentation for what peers can and cannot
learn, and what the protections cost.

`blockchain.transaction.get` with `verbose` answers as BCHN's
`getrawtransaction` does, which Fulcrum passes on: `asm`, output types,
required signatures and addresses come from the library's own reading of the
scripts, as BCHN 29 writes them.

`blockchain.rpa.*` follows Fulcrum's limits: prefixes of 8 to 16 bits, at most
60 blocks per call. Lookups by transaction ID alone need filters with
transaction keys; until the nodes serve them, such lookups work for
transactions in the mempool and in histories the wallet asked for.
`daemon.passthrough` is not available: there is no node RPC behind the bridge.

Mempool rows of `blockchain.scripthash.*` and `blockchain.rpa.get_mempool`
carry a `fee` only when the bridge holds the value of every output the
transaction spends (outputs of other mempool transactions, of the last 24
blocks, or of the scripts wallets asked for). It never downloads a block to
learn a fee: that would show a peer which payment the wallet looks at.
Fulcrum, which has the whole UTXO set, always gives the fee.

`mempool.get_fee_histogram` reads the bridge's copy of the mempool, which
holds what peers relay. A transaction counts only when the value of every
input it spends is known: outputs of other mempool transactions, of the last
24 blocks, or of the scripts wallets asked for. With no UTXO set behind it,
the bridge knows no fee for the rest, so the histogram leaves out mostly
transactions that spend older coins. `blockchain.estimatefee` takes the
median of those fee rates and of the last 24 blocks' known ones, and never
less than the relay fee the peers ask.

## Methods of this bridge, not Fulcrum's

Fulcrum's methods keep Fulcrum's names and answers, token data and
`token_filter` included. Tokens and identities beyond them are answered
under the `light_client.` prefix, which no Electrum server has; wallets
that use them know they talk to this bridge. Every answer comes from the
library without an index: a category's outputs from its filter keys, an
identity's authchain from the filter keys of each identity output's script,
with the blocks downloaded as for histories: with their decoys, each over
a connection of its own.

| Method | Parameters | Answer |
|---|---|---|
| `light_client.token.balances` | scripthash | per category: `category`, `amount` (fungible, a string), `nfts` |
| `light_client.token.supply` | category | `total`, `reserved` (in minting or mutable outputs), `circulating` (strings), NFT counts by capability, `holders` by scripthash, and the `height` counted to; the category is watched from then on |
| `light_client.token.genesis` | category | the genesis transaction's `tx_hash`, `height` (0 in the mempool) and `block_hash` |
| `light_client.bcmr.resolve` | authbase, [authbase height], [track] | the authchain's `authhead`, its `height`, `identity_output`, `burned`, `publication` (`hash` and `uris`), other `claims`, and the `steps` followed; resumes from the last identity transaction found; with `track`, the identity output is watched, so an update notifies its script's subscribers |
| `light_client.bcmr.resolve_extension` | authbase, [hex transactions of a registry's `authchain` extension], [track] | as above, after checking the extension starts at the authbase, follows output 0, and ends on the chain |
| `light_client.bcmr.verify_registry` | registry bytes (hex), published hash (hex) | whether the registry hashes to what its publication output commits to |

The bridge never fetches a registry: the wallet downloads it from the
publication's URIs (HTTPS or IPFS) and checks it with
`light_client.bcmr.verify_registry`. A category's genesis and an identity's
authchain are found only from the filters' start height (`--birthday`) on.

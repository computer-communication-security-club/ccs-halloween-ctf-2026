# HYDRA-SVC/1.0 wire protocol

Line-based protocol over TCP. All lines are ASCII, terminated by `\n`
(a trailing `\r` is tolerated and ignored). Maximum line length is 128 bytes.
The server speaks first.

## Handshake

    S: HYDRA-SVC/1.0 AUTH-REQUIRED
    S: NONCE <32-hex>
    C: AUTH <32-hex>
    S: AUTH-OK
    S: FLAG <flag>
    (connection closed)

Or, on failure:

    S: AUTH-FAIL
    (connection closed)

Protocol errors receive `ERR BAD-REQUEST` (or `ERR BUSY` / `ERR INTERNAL`)
and the connection is closed. Exactly one `AUTH` attempt is accepted per
connection. A fresh 16-byte nonce is issued for every connection, so proofs
are single-use and cannot be replayed.

## Semantics

The nonce selects a nonce-dependent verification instance inside the encrypted
firmware. The client submits a 16-byte **candidate proof**. The server runs the
firmware in the HYDRA VM; the firmware checks the candidate against constraints
derived from the nonce and writes a single accept/reject byte. The flag is
released only when the VM accepts.

The VM does not return a proof, a tag, or any intermediate result over the
wire. A valid proof cannot be obtained by replaying an earlier response because
every connection uses a fresh nonce.

Hex fields are exactly 32 characters (16 bytes). Anything else is
`ERR BAD-REQUEST`.

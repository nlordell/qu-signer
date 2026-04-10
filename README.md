> [!WARNING]
> Code in this repository is not audited and may contain serious security holes. It is provided as-is, use at your own risk.

# quSigner

Quantum-secure signer for the Safe smart account.

## Rolling One-Time Signatures (ROTS)

Quantum-secure hash-based signatures have existed for a [long time](https://en.wikipedia.org/wiki/Lamport_signature). Additionally, they are easy to implement and have very few cryptographic assumptions. The issue with this type of hash-based signature schemes is that each private key can only be used exactly once (using it more than once allows anyone for forge signatures for different messages).

The solution is to leverage the EVM to store the **current** public key, and with every signature additionally specify what the **next** public key is. This ensures that each private key is used only once, but that the signer can be used arbitrarily many times. The signer just needs to manage their keys in a way that they can keep track of their rolling secret key by deterministically expanding secret keys from a secret seed.

### Two-Step Signing Process

The rolling signature scheme in this repository uses a two-step signing process. First, `sign` is called with a valid signature in order to flag a particular message as signed and roll over the public key to the next one. Then the standard [ERC-1271](https://ercs.ethereum.org/ERCS/erc-1271) `isValidSignature` is implemented that checks whether or not a particular message is signed by looking it up in the account storage (we also provide a legacy ERC-1271 implementation for compatibility with older Safe smart accounts). This is done because ERC-1271 specifies that `isValidSignature` must be a `view` function (i.e. called with the `STATICCALL` opcode). This prevents any storage updates on the contract, thus preventing us from rolling over the public key. While you could technically implement a `isValidSignature` that verifies the signature without rolling over the public key, we don't want to do this as it opens up the signer for key reuse.

Another option would be to implement an eXtended Merkle Signature Scheme (XMSS) in quSigner. This has the advantage that you don't always need to roll over keys (in fact, you can create a Merkle tree of keys and then sign with them). This does require state to be tracked by the signer, however, as they MUST NOT ever reuse a leaf secret key to sign more than one thing.

## Winternitz One-Time Signature Plus (WOTS+)

WOTS+ is a one-time signature (OTS) hash-based scheme. This is used as the underlying primitive OTS scheme behind the ROTS scheme implemented in this repository. It has the advantage of **only** relying on the second-preimage resistance of the underlying hash function (here, SHA-256) instead of stronger cryptographic assumptions (such as collision resistance).

This repository implements the WOTS+ specification from [RFC-8391](https://datatracker.ietf.org/doc/html/rfc8391), with the key expansion algorithm taken from the [XMSS reference implementation](https://github.com/XMSS/xmss-reference).

## Signature Efficiency

These signatures are, unfortunately, **space and time inefficient** compared to elliptic curve signature schemes (RIP). The WOTS+ signature scheme used in this repository can be parameterized on a Winternitz parameter $w$ with different space and time trade-offs.

| $w$ | Signature Size (bytes) | Verification Cost (gas) |
| --- | ---------------------- | ----------------------- |
| 4   | 4256                   | ~575.000                |
| 16  | 2144                   | ~740.000                |

> Note that verification costs are approximate, as they vary with the signed message and depth of the hash chain that needs to be computed.

## Safe Compatibility

This signer is compatible with the Safe smart account. It expects `sign` to be called to first pre-approve a message with the actual signature data and roll over. This repository contains an example Safe transaction controlled by a quantum-secure signer:

```sh
QUSIGNER_PASSWORD="hello" forge script SafeTransactionScript
```

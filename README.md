> [!WARNING]
> Code in this repository is not audited and may contain serious security holes. It is provided as-is, use at your own risk.

# quSigner

Quantum-secure signer for the Safe smart account, I implemented this for fun and to learn a little about how hash-based signatures work.

## Rolling One-Time Signatures

Quantum-secure hash-based signatures have existed for a [long time](https://en.wikipedia.org/wiki/Lamport_signature). Additionally, they are very easy to implement and have very few cryptographic assumptions (namely, it only requires a hash function that is second-preimage resistant). The issue with this signature scheme is that each private key can only be used exactly once (using it more than once allows anyone for forge signatures for different messages).

The solution is to leverage the EVM to store the **current** public key, and with every signature additionally specify what the **next** public key is. This ensures that each private key is used only once, but that the signer can be used arbitrarily many times. The signer just needs to manage their keys in a way that they can keep track of their rolling secret key (for example, by deterministically computing secret keys from a secret seed). Note that the signer does not enforce that the `nextPublicKeyDigest` has not been used before, it is up to the key management software to do that. Reusing a key for a different message is catastrophic and would allow anyone to forge new signatures.

## Signature Efficiency

These signatures are, unfortunately, **extremely space inefficient**. The Lamport signature scheme used in this repository produces signatures that are 16 kB large! In the future, we can modify the signer to use Winternitz signatures, which provide a significant reduction to the signature size. **Verifying a signature costs approximately 700.000 gas** (including calldata costs for including such a 16 kB signature onchain), so it is by no means practical at the moment.

## Safe Compatibility

This signer is compatible with the Safe smart account. It expects `sign` to be called to first pre-approve a message with the actual signature data and roll over. This repository contains an example Safe transaction controlled by a quantum-secure signer:

```sh
PASSWORD="hello" SEQUENCE=2 forge script SafeTransactionScript
```

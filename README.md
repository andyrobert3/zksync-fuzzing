## Deploy & Fuzz EIP-712 Verification on zkSync Sepolia

Minimal repo to deploy an EIP-712 verifier and fuzz it live against zkSync Era Sepolia via eth_call (positive + negative cases).

### .env
Create a `.env` at the repo root with:
```
# RPC + deploy key
ZKSYNC_SEPOLIA_RPC_URL=https://...
PRIVATE_KEY=0x...

# Optional: customize domain
EIP712_NAME=EIP712Verifier
EIP712_VERSION=1

# After deploy, set the contract address
VERIFIER_ADDRESS=0x...

# Optional: used for the "wrong signer" negative test
ALT_PRIVATE_KEY=0x...
```

### Deploy
Deploy `src/EIP712Verifier.sol` to zkSync Sepolia using Foundry:
```bash
forge script script/DeployEIP712Verifier.s.sol:DeployEIP712Verifier \
  --rpc-url zksync_sepolia \
  --broadcast
```
After completion, export `VERIFIER_ADDRESS` in your `.env`.

### Fuzz testing (Rust)
The `fuzz/` crate calls the live verifier with manual ABI-encoded eth_call (mirrors cast) for robust tuple handling.

Run:
```bash
cd fuzz
cargo run --release
```

What it does:
- Positive baseline: build valid Permit, sign `calculateDigest`, `verify` must be true.
- Positive fuzz (N runs): random `spender`, `value`, `deadline ≥ now+buffer` with same nonce (stateless) must be true.
- Negative fuzz (N runs): one-at-a-time mutations (value/nonce/deadline), wrong signer, empty/short signatures must be false.
- Additional negatives: domain mismatches (chainId, verifyingContract, name, version) and invalid signature sizes or v must be false.

Notes:
- The fuzz tool snapshots the latest block timestamp once per batch and sleeps briefly per iteration to reduce RPC 429s.
- Adjust runs/sleep in `fuzz/src/main.rs` if needed.
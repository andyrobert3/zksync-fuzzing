## Foundry

**Foundry is a blazing fast, portable and modular toolkit for Ethereum application development written in Rust.**

Foundry consists of:

- **Forge**: Ethereum testing framework (like Truffle, Hardhat and DappTools).
- **Cast**: Swiss army knife for interacting with EVM smart contracts, sending transactions and getting chain data.
- **Anvil**: Local Ethereum node, akin to Ganache, Hardhat Network.
- **Chisel**: Fast, utilitarian, and verbose solidity REPL.

## Documentation

https://book.getfoundry.sh/

## Usage

### Build

```shell
$ forge build
```

### Test

```shell
$ forge test
```

### Format

```shell
$ forge fmt
```

### Gas Snapshots

```shell
$ forge snapshot
```

### Anvil

```shell
$ anvil
```

### EIP-712 on zkSync Sepolia

This repo verifies EIP-712 signatures on zkSync Sepolia and includes live positive/negative fuzzing.

Contract:
- `src/EIP712Verifier.sol` using OpenZeppelin `EIP712` and `SignatureChecker`
- Exposes `calculateDigest(Permit)`, `verify(Permit, bytes)`, `verifyAndConsume(Permit, bytes)`

Permit type:
```
Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)
```

#### Deploy

```shell
export ZKSYNC_SEPOLIA_RPC_URL=<your_zksync_sepolia_rpc>
export PRIVATE_KEY=0x...
forge script script/DeployEIP712Verifier.s.sol:DeployEIP712Verifier \
  --rpc-url zksync_sepolia \
  --broadcast
```
Optional envs: `EIP712_NAME`, `EIP712_VERSION`.

After deploy:

```shell
export VERIFIER_ADDRESS=0xDeployedAddress
```

#### Sanity via cast

```shell
cast call $VERIFIER_ADDRESS \
  'calculateDigest((address,address,uint256,uint256,uint256))' \
  "($OWNER,$SPENDER,0,0,0)" \
  --rpc-url $ZKSYNC_SEPOLIA_RPC_URL
```

#### Rust fuzzing (eth_call)

The `fuzz/` crate drives positive and negative tests against the live verifier using manual ABI encoding (mirrors cast).

Env setup:
```shell
export ZKSYNC_SEPOLIA_RPC_URL=...
export VERIFIER_ADDRESS=0x...
export PRIVATE_KEY=0x...
# optional for wrong-signer negative
export ALT_PRIVATE_KEY=0x...
```

Run fuzz:
```shell
cd fuzz
cargo run --release
```

What runs:
- Positive baseline: valid Permit, sign on-chain `calculateDigest`, `verify` => true
- Positive fuzz (N runs): random `spender`, `value`, `deadline >= now+buffer`, reuse same nonce (stateless) => all true
- Negative fuzz (N runs): mutate one field or signer, or empty signature => all false

Rate limiting: timestamp is fetched once per batch and a small sleep is added per iteration to reduce 429s.

#### Optional: Stateful replay demo

```shell
forge script script/UseVerifier.s.sol:UseVerifier \
  --rpc-url zksync_sepolia \
  --broadcast
```
Then re-run a verify with the same payload via `fuzz` or `cast` to observe replay failure.
```

### Cast

```shell
$ cast <subcommand>
```

### Help

```shell
$ forge --help
$ anvil --help
$ cast --help
```

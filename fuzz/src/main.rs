use anyhow::{anyhow, Result};
use dotenvy::dotenv;
use ethers::core::types::{Address, Bytes, Signature, U256};
use ethers::contract::Contract;
use ethers::providers::{Http, Provider, Middleware};
use ethers::abi::{Abi, Token, ParamType, encode};
use ethers::core::types::{TransactionRequest, BlockId, BlockNumber};
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::signers::{LocalWallet, Signer};

use ethers::utils::keccak256;
use rand::{rngs::SmallRng, Rng, SeedableRng};
use std::env;
use std::str::FromStr;
use tokio::time::{sleep, Duration};
use tracing::{error, info};
use tracing_subscriber::FmtSubscriber;

// Static JSON ABI (copied from the Solidity signature)
const VERIFIER_ABI_JSON: &str = r#"[
  {"inputs":[{"internalType":"address","name":"owner","type":"address"}],"name":"nonces","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},
  {"inputs":[{"components":[{"internalType":"address","name":"owner","type":"address"},{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"value","type":"uint256"},{"internalType":"uint256","name":"nonce","type":"uint256"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"internalType":"struct EIP712Verifier.Permit","name":"p","type":"tuple"}],"name":"calculateDigest","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},
  {"inputs":[{"components":[{"internalType":"address","name":"owner","type":"address"},{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"value","type":"uint256"},{"internalType":"uint256","name":"nonce","type":"uint256"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"internalType":"struct EIP712Verifier.Permit","name":"p","type":"tuple"},{"internalType":"bytes","name":"signature","type":"bytes"}],"name":"verify","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"}
]"#;

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    let subscriber = FmtSubscriber::builder().with_target(false).finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
    let mut rng = SmallRng::seed_from_u64(0xDEADBEEFCAFEBABE);

    let rpc = env::var("ZKSYNC_SEPOLIA_RPC_URL")?;
    let verifier_addr = Address::from_str(&env::var("VERIFIER_ADDRESS")?)?;
    let pk_hex = env::var("PRIVATE_KEY")?;
    let wallet: LocalWallet = pk_hex.parse()?;
    let threshold_deadline_buffer = 100;
    let owner = wallet.address();
    
    // default number of runs for fuzz testing negative mutations
    let runs = 50;

    let provider = Provider::<Http>::try_from(rpc.clone())?;
    let client = std::sync::Arc::new(provider.clone());
    let abi: Abi = serde_json::from_str(VERIFIER_ABI_JSON)?;
    let contract = Contract::new(verifier_addr, abi, client);

    // positive baseline
    let nonce: U256 = contract.method::<_, U256>("nonces", owner)?.call().await?;

    // Fuzz parameters here
    // Fuzz spender address and value
    let spender = Address::random();
    let value = U256::from(rng.random::<u64>());
    let block_time_now = provider.get_block(BlockId::Number(BlockNumber::Latest)).await?;
    if block_time_now.is_none() { return Err(anyhow!("failed to get block time")); }
    let block_time_now = block_time_now.unwrap();
    let base_deadline = block_time_now.timestamp
        + U256::from(threshold_deadline_buffer as u64)
        + U256::from(rng.random::<u64>());

    let p = (owner, spender, value, nonce, base_deadline);
    let digest: [u8;32] = call_calculate_digest_manual(&provider, verifier_addr, owner, spender, value, nonce, base_deadline).await?;
    let sig: Signature = wallet.sign_hash(digest.into()).expect("sign");
    let ok: bool = contract.method::<_, bool>("verify", (p, Bytes::from(sig.to_vec())))?.call().await?;
    if !ok { return Err(anyhow!("positive verify failed")); }

    // positive fuzz: random spender/value/deadline
    let mut pos_ok = true;
    let mut i = 0usize;
    let current_nonce: U256 = contract.method::<_, U256>("nonces", owner)?.call().await?;
    let block_opt = provider.get_block(BlockId::Number(BlockNumber::Latest)).await?;
    if block_opt.is_none() { return Err(anyhow!("failed to get block time")); }
    let ts_base = block_opt.unwrap().timestamp;

    while i < runs {
        let rand_spender = Address::random();
        let rand_value = U256::from(rng.random::<u64>());
        let deadline = ts_base + U256::from(threshold_deadline_buffer as u64) + U256::from(rng.random::<u64>());

        let pd = call_calculate_digest_manual(&provider, verifier_addr, owner, rand_spender, rand_value, current_nonce, deadline).await?;
        let ps: Signature = wallet.sign_hash(pd.into()).expect("sign_pos");
        let pok: bool = call_verify_manual(&provider, verifier_addr, owner, rand_spender, rand_value, current_nonce, deadline, Bytes::from(ps.to_vec())).await?;
        if !pok { pos_ok = false; error!("positive fuzz case failed"); break; }
        i += 1;

        // Prevent 429 rate limiting
        sleep(Duration::from_millis(50)).await;
    }
    if !pos_ok { return Err(anyhow!("positive fuzz failure")); }
    info!("positive fuzz passed");

    // negative fuzz
    let mut neg_ok = true;
    for _ in 0..runs {
        // Choose a mutation
        let choice = rng.random_range(0..5);
        let mut mutated = (owner, spender, value, nonce, base_deadline);
        let mut sig_to_use = sig.clone();
        match choice {
            0 => {
                // value mutation
                let mut new_val: U256 = U256::from(rng.random::<u64>());
                if new_val == value { new_val = new_val + U256::from(1u64); }
                mutated.2 = new_val;
            }
            1 => {
                // nonce mutation
                mutated.3 = nonce + U256::from(1u64);
            }
            2 => {
                // deadline in past
                mutated.4 = U256::from(0);
            }
            3 => {
                // wrong signer
                if let Ok(alt_pk) = env::var("ALT_PRIVATE_KEY") {
                    let alt_wallet: LocalWallet = alt_pk.parse()?;
                    let digest2: [u8;32] = contract.method::<_, [u8;32]>("calculateDigest", (owner, spender, value, nonce, base_deadline))?.call().await?; // sign original
                    sig_to_use = alt_wallet.sign_hash(digest2.into()).expect("sign2");
                } else {
                    // skip this iteration if no alt key
                    continue;
                }
            }
            _ => {
                // garbage signature
                let raw = Bytes::from(vec![]); // empty
                let bad_ok: bool = contract.method::<_, bool>("verify", (mutated, raw))?.call().await?;
                if bad_ok { neg_ok = false; error!("bad signature accepted"); }
                continue;
            }
        }

        let ok2: bool = call_verify_manual(&provider, verifier_addr, mutated.0, mutated.1, mutated.2, mutated.3, mutated.4, Bytes::from(sig_to_use.to_vec())).await?;
        if ok2 { neg_ok = false; error!("negative mutation accepted: choice={}", choice); }
        sleep(Duration::from_millis(10)).await;
    }

    if !neg_ok { return Err(anyhow!("one or more negative cases were accepted")); }
    info!("negative fuzz passed");

    // Additional negative tests: domain mismatch and signature size invalid
    let chain_id = provider.get_chainid().await?;

    // Helper: compute EIP-712 digest off-chain with custom domain
    let build_digest_offchain = |name: &str, version: &str, chain: U256, verifying: Address, perm: (Address, Address, U256, U256, U256)| -> [u8; 32] {
        // typehashes
        let typehash_domain = keccak256(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
        let typehash_permit = keccak256(b"Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
        let name_hash = keccak256(name.as_bytes());
        let version_hash = keccak256(version.as_bytes());
        // abi.encode(typehash_domain, name_hash, version_hash, chainId, verifyingContract)
        let dom = ethers::abi::encode(&[
            Token::FixedBytes(typehash_domain.to_vec()),
            Token::FixedBytes(name_hash.to_vec()),
            Token::FixedBytes(version_hash.to_vec()),
            Token::Uint(chain),
            Token::Address(verifying),
        ]);
        let domain_sep = keccak256(dom);
        // struct hash
        let struct_bytes = ethers::abi::encode(&[
            Token::FixedBytes(typehash_permit.to_vec()),
            Token::Address(perm.0),
            Token::Address(perm.1),
            Token::Uint(perm.2),
            Token::Uint(perm.3),
            Token::Uint(perm.4),
        ]);
        let struct_hash = keccak256(struct_bytes);
        // keccak256(0x1901 || domain || struct)
        let mut enc = Vec::with_capacity(2 + 32 + 32);
        enc.push(0x19);
        enc.push(0x01);
        enc.extend_from_slice(&domain_sep);
        enc.extend_from_slice(&struct_hash);
        keccak256(enc)
    };

    // Domain: wrong chainId
    let wrong_chain_digest = build_digest_offchain(
        "EIP712Verifier",
        "1",
        chain_id + U256::from(1u64),
        verifier_addr,
        (owner, spender, value, nonce, base_deadline),
    );
    let wrong_chain_sig: Signature = wallet.sign_hash(wrong_chain_digest.into()).expect("sign_wrong_chain");
    let ok_wrong_chain = call_verify_manual(&provider, verifier_addr, owner, spender, value, nonce, base_deadline, Bytes::from(wrong_chain_sig.to_vec())).await?;
    if ok_wrong_chain { return Err(anyhow!("domain mismatch (chainId) accepted")); }

    // Domain: wrong verifyingContract
    let wrong_verifying_digest = build_digest_offchain(
        "EIP712Verifier",
        "1",
        chain_id,
        Address::zero(),
        (owner, spender, value, nonce, base_deadline),
    );
    let wrong_verifying_sig: Signature = wallet.sign_hash(wrong_verifying_digest.into()).expect("sign_wrong_verifying");
    let ok_wrong_verifying = call_verify_manual(&provider, verifier_addr, owner, spender, value, nonce, base_deadline, Bytes::from(wrong_verifying_sig.to_vec())).await?;
    if ok_wrong_verifying { return Err(anyhow!("domain mismatch (verifyingContract) accepted")); }

    // Domain: wrong name
    let wrong_name_digest = build_digest_offchain(
        "EIP712VerifierX",
        "1",
        chain_id,
        verifier_addr,
        (owner, spender, value, nonce, base_deadline),
    );
    let wrong_name_sig: Signature = wallet.sign_hash(wrong_name_digest.into()).expect("sign_wrong_name");
    let ok_wrong_name = call_verify_manual(&provider, verifier_addr, owner, spender, value, nonce, base_deadline, Bytes::from(wrong_name_sig.to_vec())).await?;
    if ok_wrong_name { return Err(anyhow!("domain mismatch (name) accepted")); }

    // Domain: wrong version
    let wrong_ver_digest = build_digest_offchain(
        "EIP712Verifier",
        "2",
        chain_id,
        verifier_addr,
        (owner, spender, value, nonce, base_deadline),
    );
    let wrong_ver_sig: Signature = wallet.sign_hash(wrong_ver_digest.into()).expect("sign_wrong_version");
    let ok_wrong_ver = call_verify_manual(&provider, verifier_addr, owner, spender, value, nonce, base_deadline, Bytes::from(wrong_ver_sig.to_vec())).await?;
    if ok_wrong_ver { return Err(anyhow!("domain mismatch (version) accepted")); }

    // Invalid signature sizes
    let bad1 = Bytes::from(vec![0x01]); // 1 byte
    let ok_bad1 = call_verify_manual(&provider, verifier_addr, owner, spender, value, nonce, base_deadline, bad1).await?;
    if ok_bad1 { return Err(anyhow!("1-byte signature accepted")); }

    let bad64 = Bytes::from(vec![0xAB; 64]); // random 64 bytes
    let ok_bad64 = call_verify_manual(&provider, verifier_addr, owner, spender, value, nonce, base_deadline, bad64).await?;
    if ok_bad64 { return Err(anyhow!("random 64-byte signature accepted")); }

    // valid r,s with invalid v
    let mut raw = sig.to_vec();
    if raw.len() == 65 { raw[64] = 0u8; }
    let ok_badv = call_verify_manual(&provider, verifier_addr, owner, spender, value, nonce, base_deadline, Bytes::from(raw)).await?;
    if ok_badv { return Err(anyhow!("signature with invalid v accepted")); }

    info!("additional negative tests passed");
    Ok(())
}

async fn call_calculate_digest_manual(
    provider: &Provider<Http>,
    verifier: Address,
    owner: Address,
    spender: Address,
    value: U256,
    nonce: U256,
    deadline: U256,
) -> Result<[u8; 32]> {
    let selector = &ethers::utils::id("calculateDigest((address,address,uint256,uint256,uint256))")[..4];
    let args = Token::Tuple(vec![
        Token::Address(owner),
        Token::Address(spender),
        Token::Uint(value),
        Token::Uint(nonce),
        Token::Uint(deadline),
    ]);
    let mut data = selector.to_vec();
    data.extend(encode(&[args]));
    let mut tx = TypedTransaction::Legacy(TransactionRequest::new());
    if let TypedTransaction::Legacy(ref mut leg) = tx {
        *leg = leg.clone().to(verifier).data(Bytes::from(data));
    }
    let out: Bytes = provider.call(&tx, Some(BlockId::Number(BlockNumber::Latest))).await?;
    let token = ethers::abi::decode(&[ParamType::FixedBytes(32)], &out)?
        .remove(0)
        .into_fixed_bytes()
        .unwrap();
    Ok(<[u8; 32]>::try_from(token.as_slice()).unwrap())
}

async fn call_verify_manual(
    provider: &Provider<Http>,
    verifier: Address,
    owner: Address,
    spender: Address,
    value: U256,
    nonce: U256,
    deadline: U256,
    signature: Bytes,
) -> Result<bool> {
    let selector = &ethers::utils::id("verify((address,address,uint256,uint256,uint256),bytes)")[..4];
    let tuple = Token::Tuple(vec![
        Token::Address(owner),
        Token::Address(spender),
        Token::Uint(value),
        Token::Uint(nonce),
        Token::Uint(deadline),
    ]);
    let mut data = selector.to_vec();
    data.extend(encode(&[tuple, Token::Bytes(signature.to_vec())]));
    let mut tx = TypedTransaction::Legacy(TransactionRequest::new());
    if let TypedTransaction::Legacy(ref mut leg) = tx {
        *leg = leg.clone().to(verifier).data(Bytes::from(data));
    }
    let out: Bytes = provider.call(&tx, Some(BlockId::Number(BlockNumber::Latest))).await?;
    let ok = ethers::abi::decode(&[ParamType::Bool], &out)?
        .remove(0)
        .into_bool()
        .unwrap();
    Ok(ok)
}

// manual eth_call helpers removed in favor of fully-qualified Contract.method calls


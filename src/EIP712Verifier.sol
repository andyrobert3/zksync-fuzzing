// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

/// @title EIP712Verifier
/// @notice Verifies EIP-712 signatures and supports nonce/deadline checks; includes a view-only verifier for eth_call fuzzing.
contract EIP712Verifier is EIP712 {

    /// @dev Permit struct used for demonstration and testing.
    struct Permit {
        address owner;
        address spender;
        uint256 value;
        uint256 nonce;
        uint256 deadline;
    }

    /// @dev Custom errors for cheaper and clear reverts.
    error SignatureExpired(uint256 deadline);
    error InvalidSignature();
    error NonceAlreadyUsed(address owner, uint256 nonce);

    /// @dev Typehash for Permit struct, per EIP-712
    bytes32 public constant PERMIT_TYPEHASH = keccak256(
        "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
    );

    /// @dev Tracks the next expected nonce per owner (replay protection)
    mapping(address => uint256) public nonces;

    /// @notice Constructor sets the EIP-712 domain. You may change name/version on redeploy.
    /// @param name The user-readable name of the signing domain.
    /// @param version The current major version of the signing domain.
    constructor(string memory name, string memory version) EIP712(name, version) {}

    /// @notice Returns the next expected nonce for an owner.
    function expectedNonce(address owner) external view returns (uint256) {
        return nonces[owner];
    }

    /// @notice Compute the structHash for a Permit.
    function hashPermit(Permit calldata p) public pure returns (bytes32) {
        return keccak256(abi.encode(
            PERMIT_TYPEHASH,
            p.owner,
            p.spender,
            p.value,
            p.nonce,
            p.deadline
        ));
    }

    /// @notice Compute the EIP-712 digest for a Permit using this contract's domain.
    function calculateDigest(Permit calldata p) external view returns (bytes32) {
        return _hashTypedDataV4(hashPermit(p));
    }

    /// @notice View-only signature verification suitable for eth_call fuzzing.
    /// @dev Returns false instead of reverting for invalid cases to simplify fuzz harnesses.
    function verify(Permit calldata p, bytes calldata signature) external view returns (bool) {
        // Expiry check
        if (p.deadline < block.timestamp) {
            return false;
        }

        // Nonce must match expected next nonce
        if (p.nonce != nonces[p.owner]) {
            return false;
        }

        // Signature check (EOA or EIP-1271). EOA is sufficient per requirements.
        bytes32 digest = _hashTypedDataV4(hashPermit(p));
        bool ok = SignatureChecker.isValidSignatureNow(p.owner, digest, signature);
        return ok;
    }

    /// @notice Verifies signature and consumes nonce on success. Reverts on any failure.
    function verifyAndConsume(Permit calldata p, bytes calldata signature) external {
        if (p.deadline < block.timestamp) {
            revert SignatureExpired(p.deadline);
        }
        if (p.nonce != nonces[p.owner]) {
            revert NonceAlreadyUsed(p.owner, p.nonce);
        }
        bytes32 digest = _hashTypedDataV4(hashPermit(p));
        bool ok = SignatureChecker.isValidSignatureNow(p.owner, digest, signature);
        if (!ok) revert InvalidSignature();

        // Consume nonce after successful verification
        unchecked { nonces[p.owner] = p.nonce + 1; }
    }
}



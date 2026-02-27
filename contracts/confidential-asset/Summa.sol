// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Summa Confidential Asset & Veil PoP – Solidity interface
interface ISummaConfidentialAsset {
    function registerPublicKey(bytes32 publicKey) external;
    function transfer(address to, bytes calldata encryptedAmount, bytes calldata proof) external;
    function deposit(bytes calldata payload) external payable;
    function getEncryptedBalance(address account) external view returns (bytes memory);
    function mint(address to, bytes calldata encryptedAmount) external;
    function transferOwnership(address newOwner) external;
    function owner() external view returns (address);

    // --- Advanced Features ---
    function transferSplit(bytes calldata payload) external;
    function mintNote(bytes calldata payload) external;
    function spendNote(bytes calldata payload) external;
    function applyAffine(bytes calldata payload) external;

    // --- Veil PoP Primitives ---
    function verifyEnrollment(bytes calldata payload) external returns (bool);
    function verifyApplication(bytes calldata payload) external returns (bool);
    function verifyThreshold(bytes calldata payload) external returns (bool);
}

/// @title Veil Proof-of-Personhood Interface
interface IVeilPoP {
    /// @notice Verify a user is a unique person in a specific context
    /// @param contextId Unique ID for the action (e.g. Referendum ID)
    /// @param nullifier Contextual nullifier to prevent double-voting
    /// @param proof DLEQ proof of nullifier ownership
    function isUniquePerson(
        uint64 contextId,
        bytes32 nullifier,
        bytes calldata proof
    ) external returns (bool);
}

/// @title Summa Router
/// @notice Convenience wrapper for Summa and Veil functionality
contract SummaRouter is IVeilPoP {
    ISummaConfidentialAsset public immutable summa;

    // Nullifier registry for this router (contextId => nullifier => spent)
    mapping(uint64 => mapping(bytes32 => bool)) public isSpent;

    constructor(address summaAddress) {
        require(summaAddress != address(0), "summa addr zero");
        summa = ISummaConfidentialAsset(summaAddress);
    }

    /// @inheritdoc IVeilPoP
    function isUniquePerson(
        uint64 contextId,
        bytes32 nullifier,
        bytes calldata proof
    ) external override returns (bool) {
        require(!isSpent[contextId][nullifier], "Nullifier already spent");

        // Prepare payload for Rust contract: contextId (8b) || nullifier (32b) || proof
        bytes memory payload = abi.encodePacked(contextId, nullifier, proof);
        
        bool valid = summa.verifyApplication(payload);
        if (valid) {
            isSpent[contextId][nullifier] = true;
        }
        return valid;
    }

    function verifyEnrollment(bytes calldata payload) external returns (bool) {
        return summa.verifyEnrollment(payload);
    }

    function verifyThreshold(bytes calldata payload) external returns (bool) {
        return summa.verifyThreshold(payload);
    }

    // --- Forwarding Helpers ---

    function registerPublicKey(bytes32 pubkey) external {
        summa.registerPublicKey(pubkey);
    }

    function confidentialTransfer(address to, bytes calldata encryptedAmount, bytes calldata proof) external {
        summa.transfer(to, encryptedAmount, proof);
    }

    function depositEncrypted(bytes calldata ciphertext, bytes calldata equalityProof) external payable {
        bytes memory payload = abi.encodePacked(ciphertext, uint32(equalityProof.length), equalityProof);
        summa.deposit{value: msg.value}(payload);
    }

    function encryptedBalanceOf(address account) external view returns (bytes memory) {
        return summa.getEncryptedBalance(account);
    }

    function splitTransfer(bytes calldata payload) external {
        summa.transferSplit(payload);
    }

    function mintNote(bytes calldata payload) external {
        summa.mintNote(payload);
    }

    function applyAffine(bytes calldata payload) external {
        summa.applyAffine(payload);
    }
}

/* SPDX-License-Identifier: MIT */

pragma solidity ^0.8.28;

import {IAdminManagement} from "./interfaces/IAdminManagement.sol";
import {BLSDockBBS} from "@onematrix/bls-solidity/src/libraries/BLSDockBBS.sol";

contract EthereumDIDRegistry {

  mapping(address => address) public owners;
  mapping(address => address) public issuers;

  mapping(address => mapping(bytes32 => mapping(address => uint))) public delegates;
  mapping(address => uint) public changed;
  mapping(address => uint) public nonce;
  
  // Mapping to provide authorization context for Dual DIDs during a transaction
  mapping(address => address) private dualDIDContext;

  // Admin Management contract address
  address public adminManagement;

  // EIP-712 Domain Separator
  bytes32 public immutable DOMAIN_SEPARATOR;

  // Magic prefix for EIP-191 / EIP-712 typed data
  bytes2 internal constant EIP191_HEADER = 0x1901;

  // EIP-712 TypeHashes
  bytes32 public constant CHANGE_OWNER_TYPEHASH = keccak256("ChangeOwner(address identity,address newOwner)");
  bytes32 public constant CHANGE_OWNER_WITH_PUBKEY_TYPEHASH = keccak256("ChangeOwnerWithPubkey(address identity,address oldOwner,address newOwner)");

  modifier onlyOwner(address identity, address actor) {
    require (actor == identityOwner(identity), "bad_actor");
    _;
  }
  
  modifier onlyAdmin() {
    require(IAdminManagement(adminManagement).isAdmin(msg.sender), "only_admin");
    _;
  }

  constructor(address _adminManagement) {
    require(_adminManagement != address(0), "zero_admin_management");
    adminManagement = _adminManagement;

    // Initialize EIP-712 domain separator
    DOMAIN_SEPARATOR = keccak256(
      abi.encode(
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
        keccak256(bytes("EthereumDIDRegistry")),
        keccak256(bytes("1")),
        block.chainid,
        address(this)
      )
    );
  }

  event DIDOwnerChanged(
    address indexed identity,
    address owner,
    uint previousChange
  );

  event DIDDelegateChanged(
    address indexed identity,
    bytes32 delegateType,
    address delegate,
    uint validTo,
    uint previousChange
  );

  event DIDAttributeChanged(
    address indexed identity,
    bytes32 name,
    bytes value,
    uint validTo,
    uint previousChange
  );

  function identityOwner(address identity) public view returns(address) {
     address owner = owners[identity];
     if (owner != address(0x00)) {
       return owner;
     }

     // Fallback to transient dualDIDContext for Dual DIDs
     address contextOwner = dualDIDContext[identity];
     if (contextOwner != address(0x00)) {
       return contextOwner;
     }

     return identity;
  }

  function checkSignature(address identity, uint8 sigV, bytes32 sigR, bytes32 sigS, bytes32 hash) internal returns(address) {
    address signer = ecrecover(hash, sigV, sigR, sigS);
    require(signer == identityOwner(identity), "bad_signature");
    nonce[signer]++;
    return signer;
  }

  /**
   * @notice Derive an Ethereum address from a G2 public key (standard BLS scheme)
   * @param publicKeyBytes The G2 public key bytes (192 bytes)
   * @return The derived Ethereum address
   */
  function deriveAddressFromG2(bytes calldata publicKeyBytes) internal pure returns(address) {
    require(publicKeyBytes.length == 192, "invalid_public_key_length");
    bytes32 hash = keccak256(publicKeyBytes);
    return address(uint160(uint256(hash)));
  }

  function checkEIP712Signature(address expectedSigner, uint8 sigV, bytes32 sigR, bytes32 sigS, bytes32 structHash) internal view returns(address) {
    bytes32 hash = keccak256(abi.encodePacked(EIP191_HEADER, DOMAIN_SEPARATOR, structHash));
    address signer = ecrecover(hash, sigV, sigR, sigS);
    require(signer == expectedSigner, "bad_eip712_signature");
    return signer;
  }

  function validDelegate(address identity, bytes32 delegateType, address delegate) public view returns(bool) {
    uint validity = delegates[identity][keccak256(abi.encode(delegateType))][delegate];
    return (validity > block.timestamp);
  }
  
  /**
   * @notice Get issuer for an address-based identity
   * @dev Returns issuers[identity] if set, else returns getOwner(identity)
   * @param identity The identity address
   * @return The issuer address
   */
  function getIssuer(address identity) public view returns(address) {
    address issuer = issuers[identity];
    if (issuer != address(0x00)) {
      return issuer;
    }
    return identityOwner(identity);
  }

  function changeOwner(address identity, address actor, address newOwner) internal onlyOwner(identity, actor) {
    owners[identity] = newOwner;
    emit DIDOwnerChanged(identity, newOwner, changed[identity]);
    changed[identity] = block.number;
  }

  function changeOwner(address identity, address newOwner) public {
    changeOwner(identity, msg.sender, newOwner);
  }

  function changeOwnerSigned(address identity, uint8 sigV, bytes32 sigR, bytes32 sigS, address newOwner) public {
    bytes32 hash = keccak256(abi.encodePacked(bytes1(0x19), bytes1(0), this, nonce[identityOwner(identity)], identity, "changeOwner", newOwner));
    changeOwner(identity, checkSignature(identity, sigV, sigR, sigS, hash), newOwner);
  }
  
  // Admin function to change owner
  function adminChangeOwner(address identity, address newOwner) public onlyAdmin {
    owners[identity] = newOwner;
    emit DIDOwnerChanged(identity, newOwner, changed[identity]);
    changed[identity] = block.number;
  }
  
  // EIP-712 signature version without nonce control
  function changeOwnerEIP712(address identity, address newOwner, uint8 sigV, bytes32 sigR, bytes32 sigS) public {
    require(newOwner != address(0), "zero_owner");
    address currentOwner = identityOwner(identity);

    bytes32 structHash = keccak256(abi.encode(CHANGE_OWNER_TYPEHASH, identity, newOwner));
    checkEIP712Signature(currentOwner, sigV, sigR, sigS, structHash);

    owners[identity] = newOwner;
    emit DIDOwnerChanged(identity, newOwner, changed[identity]);
    changed[identity] = block.number;
  }

  function changeOwnerWithPubkey(
    address identity,
    address oldOwner,
    address newOwner,
    bytes calldata publicKey,
    bytes calldata signature
  ) public {
    require(newOwner != address(0), "invalid_new_owner");

    // Validate signature length (96 bytes uncompressed G1)
    require(signature.length == 96, "invalid_signature_length");

    // Derive signer address from G2 public key (standard scheme)
    address signer = deriveAddressFromG2(publicKey);

    // Verify signer is the current owner
    require(signer == identityOwner(identity), "unauthorized");

    // Verify oldOwner matches current owner (replay protection via owner change)
    require(oldOwner == identityOwner(identity), "invalid_owner");

    // Construct EIP-712 hash
    bytes32 structHash = keccak256(abi.encode(CHANGE_OWNER_WITH_PUBKEY_TYPEHASH, identity, oldOwner, newOwner));
    bytes32 hash = keccak256(abi.encodePacked(EIP191_HEADER, DOMAIN_SEPARATOR, structHash));

    // BLS12-381 verification with standard scheme:
    // Unmarshal G2 public key (uncompressed only - BLSDockBBS library does not support G2 compression)
    BLSDockBBS.PointG2 memory pubkey = BLSDockBBS.g2Unmarshal(publicKey);

    // Hash message to G1 point (standard scheme) using BLSDockBBS library
    BLSDockBBS.PointG1 memory message = BLSDockBBS.hashToPoint("BLS_DST", abi.encodePacked(hash));

    // Unmarshal G1 signature (must be uncompressed 96 bytes)
    BLSDockBBS.PointG1 memory sig = BLSDockBBS.g1Unmarshal(signature);

    // Verify using BLSDockBBS library's verifySingle function
    (bool pairingSuccess, bool callSuccess) = BLSDockBBS.verifySingle(sig, pubkey, message);
    require(pairingSuccess && callSuccess, "bad_signature");

    // Update owner
    owners[identity] = newOwner;
    emit DIDOwnerChanged(identity, newOwner, changed[identity]);
    changed[identity] = block.number;
  }

  function addDelegate(address identity, address actor, bytes32 delegateType, address delegate, uint validity) internal onlyOwner(identity, actor) {
    delegates[identity][keccak256(abi.encode(delegateType))][delegate] = block.timestamp + validity;
    emit DIDDelegateChanged(identity, delegateType, delegate, block.timestamp + validity, changed[identity]);
    changed[identity] = block.number;
  }

  function addDelegate(address identity, bytes32 delegateType, address delegate, uint validity) public {
    addDelegate(identity, msg.sender, delegateType, delegate, validity);
  }

  function addDelegateSigned(address identity, uint8 sigV, bytes32 sigR, bytes32 sigS, bytes32 delegateType, address delegate, uint validity) public {
    bytes32 hash = keccak256(abi.encodePacked(bytes1(0x19), bytes1(0), this, nonce[identityOwner(identity)], identity, "addDelegate", delegateType, delegate, validity));
    addDelegate(identity, checkSignature(identity, sigV, sigR, sigS, hash), delegateType, delegate, validity);
  }

  function revokeDelegate(address identity, address actor, bytes32 delegateType, address delegate) internal onlyOwner(identity, actor) {
    delegates[identity][keccak256(abi.encode(delegateType))][delegate] = block.timestamp;
    emit DIDDelegateChanged(identity, delegateType, delegate, block.timestamp, changed[identity]);
    changed[identity] = block.number;
  }

  function revokeDelegate(address identity, bytes32 delegateType, address delegate) public {
    revokeDelegate(identity, msg.sender, delegateType, delegate);
  }

  function revokeDelegateSigned(address identity, uint8 sigV, bytes32 sigR, bytes32 sigS, bytes32 delegateType, address delegate) public {
    bytes32 hash = keccak256(abi.encodePacked(bytes1(0x19), bytes1(0), this, nonce[identityOwner(identity)], identity, "revokeDelegate", delegateType, delegate));
    revokeDelegate(identity, checkSignature(identity, sigV, sigR, sigS, hash), delegateType, delegate);
  }

  function setAttribute(address identity, address actor, bytes32 name, bytes memory value, uint validity ) internal onlyOwner(identity, actor) {
    emit DIDAttributeChanged(identity, name, value, block.timestamp + validity, changed[identity]);
    changed[identity] = block.number;
  }

  function setAttribute(address identity, bytes32 name, bytes memory value, uint validity) public {
    setAttribute(identity, msg.sender, name, value, validity);
  }

  function setAttributeSigned(address identity, uint8 sigV, bytes32 sigR, bytes32 sigS, bytes32 name, bytes memory value, uint validity) public {
    bytes32 hash = keccak256(abi.encodePacked(bytes1(0x19), bytes1(0), this, nonce[identityOwner(identity)], identity, "setAttribute", name, value, validity));
    setAttribute(identity, checkSignature(identity, sigV, sigR, sigS, hash), name, value, validity);
  }

  function revokeAttribute(address identity, address actor, bytes32 name, bytes memory value ) internal onlyOwner(identity, actor) {
    emit DIDAttributeChanged(identity, name, value, 0, changed[identity]);
    changed[identity] = block.number;
  }

  function revokeAttribute(address identity, bytes32 name, bytes memory value) public {
    revokeAttribute(identity, msg.sender, name, value);
  }

  function revokeAttributeSigned(address identity, uint8 sigV, bytes32 sigR, bytes32 sigS, bytes32 name, bytes memory value) public {
    bytes32 hash = keccak256(abi.encodePacked(bytes1(0x19), bytes1(0), this, nonce[identityOwner(identity)], identity, "revokeAttribute", name, value));
    revokeAttribute(identity, checkSignature(identity, sigV, sigR, sigS, hash), name, value);
  }

  // Support Dual DID here

  /**
   * @notice Modifier to provide authorization context for Dual DID operations
   */
  modifier withDualContext(bytes memory identity) {
    address pId = getPIdDualDID(identity);
    dualDIDContext[pId] = getOwnerDualDID(identity);
    _;
    delete dualDIDContext[pId];
  }
  
  /**
   * @notice Get the persistent identity (pId) for a 40-byte identity
   * @param identity 40-byte identity
   * @return pId keccak256 hash of the identity as an address
   */
  function getPIdDualDID(bytes memory identity) public pure returns (address pId) {
    require(identity.length == 40, "invalid_identity_length");
    return address(uint160(uint256(keccak256(identity))));
  }

    /**
   * @notice Get owner from 40-byte identity (owner + issuer concatenated)
   * @dev Extracts owner (first 20 bytes) and issuer (last 20 bytes)
   *      Computes pId = keccak256(identity)
   *      Returns owners[pId] if set, else returns extracted owner
   * @param identity 40-byte identity (owner + issuer)
   * @return The owner address
   */
  function getOwnerDualDID(bytes memory identity) public view returns(address) {
    address pId = getPIdDualDID(identity);
    
    // If owners[pId] is set, return it
    address registeredOwner = owners[pId];
    if (registeredOwner != address(0x00)) {
      return registeredOwner;
    }

    // Extract owner (first 20 bytes)
    address owner;
    
    assembly {
      // Load first 20 bytes as owner (skip 32-byte length prefix, then shift)
      owner := shr(96, mload(add(identity, 32)))
    }
    
    // Otherwise return the extracted owner
    return owner;
  }

    /**
   * @notice Get issuer from 40-byte identity (owner + issuer concatenated)
   * @dev Extracts owner (first 20 bytes) and issuer (last 20 bytes)
   *      Computes pId = keccak256(identity)
   *      Returns issuers[pId] if set, else falls back to getOwner logic
   * @param identity 40-byte identity (owner + issuer)
   * @return The issuer address
   */
  function getIssuerDualDID(bytes memory identity) public view returns(address) {
    address pId = getPIdDualDID(identity);
    
    // If issuers[pId] is set, return it
    address registeredIssuer = issuers[pId];
    if (registeredIssuer != address(0x00)) {
      return registeredIssuer;
    }
    
    // Otherwise fallback to getOwner logic (returns owners[pId] if set, else owner)
    address registeredOwner = owners[pId];
    if (registeredOwner != address(0x00)) {
      return registeredOwner;
    }

    // Extract issuer (last 20 bytes)
    address issuer;
    
    assembly {
      // Load 32 bytes from position 40 (32-byte length + 20-byte owner - 12 bytes for alignment)
      // This loads: last 12 bytes of owner + 20 bytes of issuer
      // The issuer ends up in the rightmost 20 bytes (correct position for address)
      issuer := mload(add(identity, 40))
    }
    
    // Return extracted issuer as final fallback
    return issuer;
  }

  function changeOwnerDualDID(bytes memory identity, address newOwner) public withDualContext(identity) {
    changeOwner(getPIdDualDID(identity), newOwner);
  }

  function changeOwnerSignedDualDID(bytes memory identity, uint8 sigV, bytes32 sigR, bytes32 sigS, address newOwner) public withDualContext(identity) {
    changeOwnerSigned(getPIdDualDID(identity), sigV, sigR, sigS, newOwner);
  }

  function adminChangeOwnerDualDID(bytes memory identity, address newOwner) public {
    adminChangeOwner(getPIdDualDID(identity), newOwner);
  }

  function changeOwnerEIP712DualDID(bytes memory identity, address newOwner, uint8 sigV, bytes32 sigR, bytes32 sigS) public withDualContext(identity) {
    changeOwnerEIP712(getPIdDualDID(identity), newOwner, sigV, sigR, sigS);
  }

  function changeOwnerWithPubkeyDualDID(
    bytes memory identity,
    address oldOwner,
    address newOwner,
    bytes calldata publicKey,
    bytes calldata signature
  ) public withDualContext(identity) {
    address pId = getPIdDualDID(identity);
    require(newOwner != address(0), "invalid_new_owner");

    // Validate signature length (96 bytes uncompressed G1)
    require(signature.length == 96, "invalid_signature_length");

    // Derive signer address from G2 public key (standard scheme)
    address signer = deriveAddressFromG2(publicKey);
    address currentOwner = identityOwner(pId);

    // Authorization: signer must be current owner or the BLS key from identity
    // (the issuer part of the 40-byte identity)
    require(signer == currentOwner || signer == getIssuerDualDID(identity), "unauthorized");

    // Replay protection & state consistency
    require(oldOwner == currentOwner || oldOwner == signer, "invalid_owner");

    // Construct EIP-712 hash
    // We use the pId as the identity for the hash since that's what's stored on-chain
    bytes32 structHash = keccak256(abi.encode(CHANGE_OWNER_WITH_PUBKEY_TYPEHASH, pId, oldOwner, newOwner));
    bytes32 hash = keccak256(abi.encodePacked(EIP191_HEADER, DOMAIN_SEPARATOR, structHash));

    // BLS12-381 verification with standard scheme:
    // Unmarshal G2 public key (uncompressed only - BLSDockBBS library does not support G2 compression)
    BLSDockBBS.PointG2 memory pubkey = BLSDockBBS.g2Unmarshal(publicKey);

    // Hash message to G1 point (standard scheme) using BLSDockBBS library
    BLSDockBBS.PointG1 memory message = BLSDockBBS.hashToPoint("BLS_DST", abi.encodePacked(hash));

    // Unmarshal G1 signature (must be uncompressed 96 bytes)
    BLSDockBBS.PointG1 memory sig = BLSDockBBS.g1Unmarshal(signature);

    // Verify using BLSDockBBS library's verifySingle function
    (bool pairingSuccess, bool callSuccess) = BLSDockBBS.verifySingle(sig, pubkey, message);
    require(pairingSuccess && callSuccess, "bad_signature");

    // Update owner
    owners[pId] = newOwner;
    emit DIDOwnerChanged(pId, newOwner, changed[pId]);
    changed[pId] = block.number;
  }

  function addDelegateDualDID(bytes memory identity, bytes32 delegateType, address delegate, uint validity) public withDualContext(identity) {
    addDelegate(getPIdDualDID(identity), delegateType, delegate, validity);
  }

  function addDelegateSignedDualDID(bytes memory identity, uint8 sigV, bytes32 sigR, bytes32 sigS, bytes32 delegateType, address delegate, uint validity) public withDualContext(identity) {
    addDelegateSigned(getPIdDualDID(identity), sigV, sigR, sigS, delegateType, delegate, validity);
  }

  function revokeDelegateDualDID(bytes memory identity, bytes32 delegateType, address delegate) public withDualContext(identity) {
    revokeDelegate(getPIdDualDID(identity), delegateType, delegate);
  }

  function revokeDelegateSignedDualDID(bytes memory identity, uint8 sigV, bytes32 sigR, bytes32 sigS, bytes32 delegateType, address delegate) public withDualContext(identity) {
    revokeDelegateSigned(getPIdDualDID(identity), sigV, sigR, sigS, delegateType, delegate);
  }

  function setAttributeDualDID(bytes memory identity, bytes32 name, bytes memory value, uint validity) public withDualContext(identity) {
    setAttribute(getPIdDualDID(identity), name, value, validity);
  }

  function setAttributeSignedDualDID(bytes memory identity, uint8 sigV, bytes32 sigR, bytes32 sigS, bytes32 name, bytes memory value, uint validity) public withDualContext(identity) {
    setAttributeSigned(getPIdDualDID(identity), sigV, sigR, sigS, name, value, validity);
  }

  function revokeAttributeDualDID(bytes memory identity, bytes32 name, bytes memory value) public withDualContext(identity) {
    revokeAttribute(getPIdDualDID(identity), name, value);
  }

  function revokeAttributeSignedDualDID(bytes memory identity, uint8 sigV, bytes32 sigR, bytes32 sigS, bytes32 name, bytes memory value) public withDualContext(identity) {
    revokeAttributeSigned(getPIdDualDID(identity), sigV, sigR, sigS, name, value);
  }
}
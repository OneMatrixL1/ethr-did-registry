/* SPDX-License-Identifier: MIT */

pragma solidity ^0.8.28;

import {IAdminManagement} from "./interfaces/IAdminManagement.sol";
import {BLS2} from "@onematrix/bls-solidity/src/libraries/BLS2.sol";

contract EthereumDIDRegistry {

  mapping(address => address) public owners;
  mapping(address => address) public issuers;

  mapping(address => mapping(bytes32 => mapping(address => uint))) public delegates;
  mapping(address => uint) public changed;
  mapping(address => uint) public nonce;
  
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

  function getIdentityFromPublicKey(bytes memory publicKey) public pure returns (address) {
      return address(uint160(uint256(keccak256(publicKey))));
  }

  function identityOwner(address identity) public view returns(address) {
     address owner = owners[identity];
     if (owner != address(0x00)) {
       return owner;
     }
     return identity;
  }

  function checkSignature(address identity, uint8 sigV, bytes32 sigR, bytes32 sigS, bytes32 hash) internal returns(address) {
    address signer = ecrecover(hash, sigV, sigR, sigS);
    require(signer == identityOwner(identity), "bad_signature");
    nonce[signer]++;
    return signer;
  }

  function checkBlsSignature(bytes calldata publicKeyBytes, bytes calldata messageBytes, bytes calldata signatureBytes) public view returns(bool success) {
    BLS2.PointG2 memory publicKey = BLS2.g2Unmarshal(publicKeyBytes);

    BLS2.PointG1 memory signature = BLS2.g1Unmarshal(signatureBytes);

    // Create EIP-712 style digest
    bytes32 digest = keccak256(abi.encodePacked(
        EIP191_HEADER,
        DOMAIN_SEPARATOR,
        structHash
    ));

    // Hash digest to G1 point using BLS DST
    BLS2.PointG1 memory messagePoint = BLS2.hashToPoint(BLS_DST, abi.encodePacked(digest));

    (bool pairingSuccess, bool callSuccess) = BLS2.verifySingle(signature, publicKey, messagePoint);

    return pairingSuccess && callSuccess;
  }

  /**
   * @notice Derive an Ethereum address from a public key
   * @dev For BLS12-381 (96-byte G2 pubkey): keccak256(pubkey)[last 20 bytes]
   * @param publicKeyBytes The public key bytes
   * @return The derived Ethereum address
   */
  function publicKeyToAddress(bytes calldata publicKeyBytes) internal pure returns(address) {
    if (publicKeyBytes.length == 96) {
      // BLS12-381 G2 public key: keccak256 hash, take last 20 bytes
      bytes32 hash = keccak256(publicKeyBytes);
      return address(uint160(uint256(hash)));
    }
    revert("unsupported_pubkey_type");
  }

  function checkEIP712Signature(address expectedSigner, uint8 sigV, bytes32 sigR, bytes32 sigS, bytes32 structHash) internal view returns(address) {
    bytes32 hash = keccak256(abi.encodePacked(EIP191_HEADER, DOMAIN_SEPARATOR, structHash));
    address signer = ecrecover(hash, sigV, sigR, sigS);
    require(signer == expectedSigner, "bad_eip712_signature");
    return signer;
  }

  /**
   * @notice Hash a message to a G2 curve point
   * @dev Follows RFC 9380 Section 5 with SHA256-based expansion
   * @dev Uses EIP-2537 BLS12_MAP_FP_TO_G2 precompile (address 0x12)
   * @param dst Domain separation tag
   * @param message Message to hash
   * @return out G2 point representing the hashed message
   */
  function hashToPointG2(bytes memory dst, bytes memory message) internal view returns(BLS2.PointG2 memory out) {
    // Expand message to 128 bytes using RFC 9380 Section 5.3.1
    bytes memory uniform_bytes = BLS2.expandMsg(dst, message, 128);

    // Map two field elements to G2 curve, then add them
    // We'll construct the result by hashing each 64-byte chunk to G2
    bytes memory buf = new bytes(192);
    bool ok;

    // Hash first 64 bytes to G2
    assembly {
      let p := add(buf, 32)
      // Input for BLS12_MAP_FP_TO_G2: 64 bytes (one field element)
      let uniform_ptr := add(uniform_bytes, 32)
      ok := staticcall(gas(), 0x12, uniform_ptr, 64, p, 192)
    }
    require(ok, "bls12_map_fp_to_g2_1 failed");

    // Hash second 64 bytes to G2
    bytes memory buf2 = new bytes(192);
    assembly {
      let p := add(buf2, 32)
      let uniform_ptr := add(uniform_bytes, 96)  // offset by 64 bytes
      ok := staticcall(gas(), 0x12, uniform_ptr, 64, p, 192)
    }
    require(ok, "bls12_map_fp_to_g2_2 failed");

    // Add the two G2 points using BLS12_G2ADD precompile (0x0d)
    bytes memory sum_buf = new bytes(192);
    assembly {
      let input := buf
      let input2 := buf2
      let output := sum_buf

      // Call G2ADD with buf and buf2 as inputs (each 192 bytes)
      ok := staticcall(gas(), 0x0d, add(input, 32), 384, add(output, 32), 192)
    }
    require(ok, "bls12_g2add failed");

    // Extract the result
    assembly {
      let p := add(sum_buf, 32)
      let out_ptr := out

      let x1_hi := shr(128, mload(p))
      let x1_lo := mload(add(p, 16))
      let x0_hi := shr(128, mload(add(p, 32)))
      let x0_lo := mload(add(p, 48))
      let y1_hi := shr(128, mload(add(p, 64)))
      let y1_lo := mload(add(p, 80))
      let y0_hi := shr(128, mload(add(p, 96)))
      let y0_lo := mload(add(p, 112))

      mstore(out_ptr, x1_hi)
      mstore(add(out_ptr, 16), x1_lo)
      mstore(add(out_ptr, 32), x0_hi)
      mstore(add(out_ptr, 48), x0_lo)
      mstore(add(out_ptr, 64), y1_hi)
      mstore(add(out_ptr, 80), y1_lo)
      mstore(add(out_ptr, 96), y0_hi)
      mstore(add(out_ptr, 112), y0_lo)
    }

    return out;
  }

  /**
   * @notice Verify inverted BLS signature using pairing: e(pubkey_G1, message_G2) = e(G1_gen, sig_G2)
   * @dev Uses EIP-2537 BLS12_PAIRING_CHECK precompile (address 0x0f)
   * @param pubkey G1 public key point
   * @param sig G2 signature point
   * @param message G2 hashed message point
   * @return pairingSuccess True if pairing check passes
   * @return callSuccess True if precompile call succeeded
   */
  function verifyInvertedPairing(
    BLS2.PointG1 memory pubkey,
    BLS2.PointG2 memory sig,
    BLS2.PointG2 memory message
  ) internal view returns(bool pairingSuccess, bool callSuccess) {
    // Generator point of G1 (for e(G1_gen, sig_G2) part)
    // This is the standard BLS12-381 generator G1
    BLS2.PointG1 memory g1_gen = BLS2.PointG1(
      0x024aa2b2f08f0a91260805272dc51051,
      0xc6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8,
      0x013fa4d4a0ad8b1ce186ed5061789213d,
      0x993923066dddaf1040bc3ff59f825c78df74f2d75467e25e0f55f8a00fa030ed
    );

    // Construct pairing input array for the check:
    // e(pubkey_G1, message_G2) * e(-G1_gen, sig_G2) = 1
    // Which verifies: e(pubkey_G1, message_G2) = e(G1_gen, sig_G2)

    uint256[24] memory input = [
      // e(pubkey, message)
      pubkey.x_hi,
      pubkey.x_lo,
      pubkey.y_hi,
      pubkey.y_lo,
      message.x0_hi,
      message.x0_lo,
      message.x1_hi,
      message.x1_lo,
      message.y0_hi,
      message.y0_lo,
      message.y1_hi,
      message.y1_lo,
      // e(-G1_gen, sig) = e(G1_gen, -sig) for negation
      // We negate sig by negating its y-coordinate
      g1_gen.x_hi,
      g1_gen.x_lo,
      g1_gen.y_hi,
      g1_gen.y_lo,
      sig.x0_hi,
      sig.x0_lo,
      sig.x1_hi,
      sig.x1_lo,
      sig.y0_hi,
      sig.y0_lo,
      sig.y1_hi,
      sig.y1_lo
    ];

    uint256[1] memory out;
    assembly {
      callSuccess := staticcall(gas(), 0x0f, input, 768, out, 0x20)
    }
    return (out[0] != 0, callSuccess);
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

  /**
   * @notice Get owner from 40-byte identity (owner + issuer concatenated)
   * @dev Extracts owner (first 20 bytes) and issuer (last 20 bytes)
   *      Computes pId = keccak256(identity)
   *      Returns owners[pId] if set, else returns extracted owner
   * @param identity 40-byte identity (owner + issuer)
   * @return The owner address
   */
  function getOwner(bytes memory identity) public view returns(address) {
    require(identity.length == 40, "invalid_identity_length");

    // Compute pId = keccak256(identity)
    address pId = address(uint160(uint256(keccak256(identity))));

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
  function getIssuer(bytes memory identity) public view returns(address) {
    require(identity.length == 40, "invalid_identity_length");

    // Compute pId = keccak256(identity)
    address pId = address(uint160(uint256(keccak256(identity))));

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

  // BLS signature version (EIP-712 style)
  function changeOwnerBLS(
      address identity,
      bytes memory publicKey,
      bytes memory signature,
      address newOwner
  ) public {
      require(newOwner != address(0), "zero_owner_address");

      address currentOwner = identityOwner(identity);

      // Verify publicKey corresponds to current owner (identity itself or its owner)
      address publicKeyAddress = getIdentityFromPublicKey(publicKey);

      require(publicKeyAddress == currentOwner, "public_key_not_owner");

      bytes32 structHash = keccak256(abi.encode(
          BLS_CHANGE_OWNER_TYPEHASH,
          identity,
          newOwner
      ));

      require(checkBlsSignature(publicKey, signature, structHash), "invalid_bls_signature");

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
  ) external {
    require(newOwner != address(0), "invalid_new_owner");

    // Derive signer address from public key
    address signer = publicKeyToAddress(publicKey);

    // Verify signer is the current owner
    require(signer == identityOwner(identity), "unauthorized");

    // Verify oldOwner matches current owner (replay protection via owner change)
    require(oldOwner == identityOwner(identity), "invalid_owner");

    // Route verification based on public key length
    require(publicKey.length == 96, "unsupported_pubkey_type");

    // Construct EIP-712 hash
    bytes32 structHash = keccak256(abi.encode(CHANGE_OWNER_WITH_PUBKEY_TYPEHASH, identity, oldOwner, newOwner));
    bytes32 hash = keccak256(abi.encodePacked(EIP191_HEADER, DOMAIN_SEPARATOR, structHash));

    // BLS12-381 verification: convert hash to G1 point and verify
    BLS2.PointG1 memory message = BLS2.hashToPoint("BLS_DST", abi.encodePacked(hash));
    BLS2.PointG2 memory pubkey = BLS2.g2Unmarshal(publicKey);
    BLS2.PointG1 memory sig = BLS2.g1Unmarshal(signature);

    (bool pairingSuccess, bool callSuccess) = BLS2.verifySingle(sig, pubkey, message);
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

  function setAttribute(bytes memory identity, address actor, bytes32 name, bytes memory value, uint validity ) internal {
    address identityAddress = address(uint160(uint256(keccak256(identity))));
    require (actor == identityOwner(identityAddress), "bad_actor");

    emit DIDAttributeChanged(identityAddress, name, value, block.timestamp + validity, changed[identityAddress]);
    changed[identityAddress] = block.number;
  }

  function setAttribute(address identity, address actor, bytes32 name, bytes memory value, uint validity ) internal onlyOwner(identity, actor) {
    emit DIDAttributeChanged(identity, name, value, block.timestamp + validity, changed[identity]);
    changed[identity] = block.number;
  }

  function setAttribute(address identity, bytes32 name, bytes memory value, uint validity) public {
    setAttribute(identity, msg.sender, name, value, validity);
  }

  function setAttribute(bytes memory identity, bytes32 name, bytes memory value, uint validity) public {
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
}

/* SPDX-License-Identifier: MIT */

pragma solidity ^0.8.28;

import {IAdminManagement} from "./interfaces/IAdminManagement.sol";
contract EthereumDIDRegistry {

  mapping(address => address) public owners;
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
  bytes32 public constant ADD_DELEGATE_TYPEHASH = keccak256("AddDelegate(address identity,bytes32 delegateType,address delegate,uint256 validTo)");
  bytes32 public constant REVOKE_DELEGATE_TYPEHASH = keccak256("RevokeDelegate(address identity,bytes32 delegateType,address delegate)");
  bytes32 public constant SET_ATTRIBUTE_TYPEHASH = keccak256("SetAttribute(address identity,bytes32 name,bytes value,uint256 validTo)");
  bytes32 public constant REVOKE_ATTRIBUTE_TYPEHASH = keccak256("RevokeAttribute(address identity,bytes32 name,bytes value)");

  modifier onlyOwner(address identity, address actor) {
    require (actor == identityOwner(identity), "bad_actor");
    _;
  }
  
  modifier onlyAdmin() {
    require(IAdminManagement(adminManagement).isAdmin(msg.sender), "only_admin");
    _;
  }

  constructor(address _adminManagement) {
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
     return identity;
  }

  function checkSignature(address identity, uint8 sigV, bytes32 sigR, bytes32 sigS, bytes32 hash) internal returns(address) {
    address signer = ecrecover(hash, sigV, sigR, sigS);
    require(signer == identityOwner(identity), "bad_signature");
    nonce[signer]++;
    return signer;
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
    bytes32 structHash = keccak256(abi.encode(CHANGE_OWNER_TYPEHASH, identity, newOwner));
    address currentOwner = identityOwner(identity);
    checkEIP712Signature(currentOwner, sigV, sigR, sigS, structHash);
    
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
  
  // EIP-712 version for adding delegate
  function addDelegateEIP712(address identity, bytes32 delegateType, address delegate, uint256 validTo, uint8 sigV, bytes32 sigR, bytes32 sigS) public {
    require(validTo >= block.timestamp, "invalid_expiry");
    
    bytes32 structHash = keccak256(abi.encode(ADD_DELEGATE_TYPEHASH, identity, delegateType, delegate, validTo));
    address currentOwner = identityOwner(identity);
    checkEIP712Signature(currentOwner, sigV, sigR, sigS, structHash);
    
    delegates[identity][keccak256(abi.encode(delegateType))][delegate] = validTo;
    emit DIDDelegateChanged(identity, delegateType, delegate, validTo, changed[identity]);
    changed[identity] = block.number;
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
  
  // EIP-712 version for revoking delegate
  function revokeDelegateEIP712(address identity, bytes32 delegateType, address delegate, uint8 sigV, bytes32 sigR, bytes32 sigS) public {
    bytes32 structHash = keccak256(abi.encode(REVOKE_DELEGATE_TYPEHASH, identity, delegateType, delegate));
    address currentOwner = identityOwner(identity);
    checkEIP712Signature(currentOwner, sigV, sigR, sigS, structHash);
    
    delegates[identity][keccak256(abi.encode(delegateType))][delegate] = block.timestamp;
    emit DIDDelegateChanged(identity, delegateType, delegate, block.timestamp, changed[identity]);
    changed[identity] = block.number;
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
  
  // EIP-712 version for setting attribute
  function setAttributeEIP712(address identity, bytes32 name, bytes memory value, uint256 validTo, uint8 sigV, bytes32 sigR, bytes32 sigS) public {
    require(validTo >= block.timestamp, "invalid_expiry");
    
    bytes32 structHash = keccak256(abi.encode(SET_ATTRIBUTE_TYPEHASH, identity, name, keccak256(value), validTo));
    address currentOwner = identityOwner(identity);
    checkEIP712Signature(currentOwner, sigV, sigR, sigS, structHash);
    
    emit DIDAttributeChanged(identity, name, value, validTo, changed[identity]);
    changed[identity] = block.number;
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
  
  // EIP-712 version for revoking attribute
  function revokeAttributeEIP712(address identity, bytes32 name, bytes memory value, uint8 sigV, bytes32 sigR, bytes32 sigS) public {
    bytes32 structHash = keccak256(abi.encode(REVOKE_ATTRIBUTE_TYPEHASH, identity, name, keccak256(value)));
    address currentOwner = identityOwner(identity);
    checkEIP712Signature(currentOwner, sigV, sigR, sigS, structHash);
    
    emit DIDAttributeChanged(identity, name, value, 0, changed[identity]);
    changed[identity] = block.number;
  }

}

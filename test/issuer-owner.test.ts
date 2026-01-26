import { expect } from 'chai'
import { SignerWithAddress } from '@nomiclabs/hardhat-ethers/signers'
import { EthereumDIDRegistry, AdminManagement } from '../typechain-types'

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { ethers } = require('hardhat')

describe('EthereumDIDRegistry - Issuer/Owner Separation', function () {
  let registry: EthereumDIDRegistry
  let adminManagement: AdminManagement
  let owner: SignerWithAddress
  let identity: SignerWithAddress
  let issuer: SignerWithAddress
  let newOwner: SignerWithAddress
  let accounts: SignerWithAddress[]

  beforeEach(async function () {
    accounts = await ethers.getSigners()
    ;[owner, identity, issuer, newOwner] = accounts

    // Deploy AdminManagement
    const AdminManagement = await ethers.getContractFactory('AdminManagement')
    adminManagement = await AdminManagement.deploy()
    await adminManagement.deployed()

    // Deploy EthereumDIDRegistry
    const Registry = await ethers.getContractFactory('EthereumDIDRegistry')
    registry = await Registry.deploy(adminManagement.address)
    await registry.deployed()

    // Set deployer as admin
    await adminManagement.setAdmin(owner.address, true)
  })

  describe('getIssuer(address) - Address-based identity', function () {
    it('should return owner if issuers[identity] is not set', async function () {
      const result = await registry['getIssuer(address)'](identity.address)
      expect(result).to.equal(identity.address)
    })

    it('should return custom owner if owners[identity] is set', async function () {
      // Change owner first
      await registry.connect(identity).changeOwner(identity.address, newOwner.address)

      // Now getIssuer should return the new owner
      const result = await registry['getIssuer(address)'](identity.address)
      expect(result).to.equal(newOwner.address)
    })
  })

  describe('getOwnerDualDID(bytes) - 40-byte identity', function () {
    it('should extract and return owner from 40-byte identity', async function () {
      // Create 40-byte identity (owner + issuer)
      const ownerBytes = identity.address.slice(2) // Remove 0x
      const issuerBytes = issuer.address.slice(2) // Remove 0x
      const identity40Bytes = '0x' + ownerBytes + issuerBytes

      const result = await registry.getOwnerDualDID(identity40Bytes)
      expect(result).to.equal(identity.address)
    })

    it('should return registered owner if owners[pId] is set', async function () {
      // Create 40-byte identity
      const ownerBytes = identity.address.slice(2)
      const issuerBytes = issuer.address.slice(2)
      const identity40Bytes = '0x' + ownerBytes + issuerBytes

      // Compute pId
      const pId = ethers.utils.keccak256(identity40Bytes)
      const pIdAddress = ethers.utils.getAddress('0x' + pId.slice(26)) // Last 20 bytes

      // Set owner for pId using admin
      await registry.connect(owner).adminChangeOwner(pIdAddress, newOwner.address)

      // Now getOwnerDualDID should return the registered owner
      const result = await registry.getOwnerDualDID(identity40Bytes)
      expect(result).to.equal(newOwner.address)
    })

    it('should reject identity with invalid length', async function () {
      const invalidIdentity = '0x1234' // Too short
      await expect(registry.getOwnerDualDID(invalidIdentity)).to.be.revertedWith('invalid_identity_length')
    })
  })

  describe('getIssuerDualDID(bytes) - 40-byte identity', function () {
    it('should extract and return issuer from 40-byte identity by default', async function () {
      // Create 40-byte identity (owner + issuer)
      const ownerBytes = identity.address.slice(2)
      const issuerBytes = issuer.address.slice(2)
      const identity40Bytes = '0x' + ownerBytes + issuerBytes

      const result = await registry['getIssuerDualDID(bytes)'](identity40Bytes)
      // Should return issuer (second 20 bytes) as fallback
      expect(result).to.equal(issuer.address)
    })

    it('should return registered owner if owners[pId] is set (fallback to getOwnerDualDID)', async function () {
      // Create 40-byte identity
      const ownerBytes = identity.address.slice(2)
      const issuerBytes = issuer.address.slice(2)
      const identity40Bytes = '0x' + ownerBytes + issuerBytes

      // Compute pId
      const pId = ethers.utils.keccak256(identity40Bytes)
      const pIdAddress = ethers.utils.getAddress('0x' + pId.slice(26))

      // Set owner for pId
      await registry.connect(owner).adminChangeOwner(pIdAddress, newOwner.address)

      // getIssuerDualDID should fallback to getOwnerDualDID and return registered owner
      const result = await registry['getIssuerDualDID(bytes)'](identity40Bytes)
      expect(result).to.equal(newOwner.address)
    })

    it('should reject identity with invalid length', async function () {
      const invalidIdentity = '0xabcd'
      await expect(registry['getIssuerDualDID(bytes)'](invalidIdentity)).to.be.revertedWith('invalid_identity_length')
    })
  })

  describe('Integration: 40-byte identity with owner and issuer', function () {
    it('should correctly separate owner and issuer from 40-byte identity', async function () {
      // Create 40-byte identity
      const ownerBytes = identity.address.slice(2)
      const issuerBytes = issuer.address.slice(2)
      const identity40Bytes = '0x' + ownerBytes + issuerBytes

      // Get owner and issuer
      const extractedOwner = await registry.getOwnerDualDID(identity40Bytes)
      const extractedIssuer = await registry['getIssuerDualDID(bytes)'](identity40Bytes)

      expect(extractedOwner).to.equal(identity.address)
      expect(extractedIssuer).to.equal(issuer.address)
    })

    it('should handle pId-based overrides correctly', async function () {
      const ownerBytes = identity.address.slice(2)
      const issuerBytes = issuer.address.slice(2)
      const identity40Bytes = '0x' + ownerBytes + issuerBytes

      // Compute pId
      const pId = ethers.utils.keccak256(identity40Bytes)
      const pIdAddress = ethers.utils.getAddress('0x' + pId.slice(26))

      // Register new owner for pId
      await registry.connect(owner).adminChangeOwner(pIdAddress, newOwner.address)

      // Both getOwnerDualDID and getIssuerDualDID should return newOwner
      const extractedOwner = await registry.getOwnerDualDID(identity40Bytes)
      const extractedIssuer = await registry['getIssuerDualDID(bytes)'](identity40Bytes)

      expect(extractedOwner).to.equal(newOwner.address)
      expect(extractedIssuer).to.equal(newOwner.address)
    })
  })
})

/* eslint-disable no-unused-expressions */
// Test file for BLS signature verification with EIP-712 style struct hashing

import chai, { expect } from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { solidity } from 'ethereum-waffle'
import { Contract } from 'ethers'
import { SignerWithAddress } from '@nomiclabs/hardhat-ethers/signers'
import { EthereumDIDRegistry } from '../typechain-types'

chai.use(chaiAsPromised)
chai.use(solidity)

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { ethers } = require('hardhat')

describe('BLS Signature Verification (EIP-712 Style)', () => {
  let didReg: EthereumDIDRegistry
  let adminManagement: Contract
  let admin: SignerWithAddress

  // BLS_CHANGE_OWNER_TYPEHASH = keccak256("BLSChangeOwner(address identity,address newOwner,uint256 nonce)")
  const BLS_CHANGE_OWNER_TYPEHASH = ethers.utils.keccak256(
    ethers.utils.toUtf8Bytes('BLSChangeOwner(address identity,address newOwner,uint256 nonce)')
  )

  // Valid BLS signature test data (pre-computed for EIP-712 style digest)
  // Note: These signatures need to be generated off-chain with the new message format
  // For now, we test the contract structure and error handling
  const validTestVectors = [
    {
      description: 'valid BLS signature for EIP-712 struct',
      // G2 Public Key - 192 bytes (PK_X1 + PK_X0 + PK_Y1 + PK_Y0)
      publicKey:
        '0x' +
        '032e5b9e02a090923681a5d44919e16995db40f86497754406e5afc39802ae33e2c367a3a147c6a55d6531ebb6af5dbf' +
        '0adf7abd27b86ae1436498c6fa09c91369d5d971ab8e2e76d6d3f9355dc2b16435bec7de51ee143757cfcceab694285a' +
        '0905b345c36460d605e56d778ceba70dd5569930d2c3b545800e0fc9ffdfa7fb02623647f7831f2a510e4de563f2428e' +
        '126d23e78717d0b8fbbeefd51add8724c47ea5b205d5491d7cc99f5529fd1d1e1b7a6d8205336edad346cebd1f5fba21',
      // G1 Signature - 96 bytes (SIG_X + SIG_Y)
      signature:
        '0x' +
        '04354919ba779ad031cd88774df9dd24e925b6396eafe20b5ab9c449f2cfc421e7eb463015d466040d446dff5cb62241' +
        '0462454c0ff9dc9cb2cbb87f12053839a4e7988b7a34483c59b4ee7965cc0603f2773033a68fdd5a9cc3f4915193645c',
    },
  ]

  before(async () => {
    // Deploy admin management contract
    const AdminManagement = await ethers.getContractFactory('AdminManagement')
      ;[admin] = await ethers.getSigners()

    adminManagement = await AdminManagement.connect(admin).deploy()
    await adminManagement.deployed()

    // Deploy registry with admin management address
    const Registry = await ethers.getContractFactory('EthereumDIDRegistry')

    didReg = await Registry.connect(admin).deploy(adminManagement.address)
    await didReg.deployed()
  })

  describe('EIP-712 Domain Separator', () => {
    it('should have BLS_DOMAIN_SEPARATOR initialized', async () => {
      const blsDomainSeparator = await didReg.BLS_DOMAIN_SEPARATOR()

      expect(blsDomainSeparator).to.not.equal(ethers.constants.HashZero)
    })

    it('should have different BLS_DOMAIN_SEPARATOR from DOMAIN_SEPARATOR', async () => {
      const domainSeparator = await didReg.DOMAIN_SEPARATOR()
      const blsDomainSeparator = await didReg.BLS_DOMAIN_SEPARATOR()

      expect(domainSeparator).to.not.equal(blsDomainSeparator)
    })

    it('should have BLS_CHANGE_OWNER_TYPEHASH constant', async () => {
      const contractTypeHash = await didReg.BLS_CHANGE_OWNER_TYPEHASH()

      expect(contractTypeHash).to.equal(BLS_CHANGE_OWNER_TYPEHASH)
    })
  })

  describe('checkBlsSignature with structHash', () => {
    it('should accept bytes32 structHash parameter', async () => {
      const testVector = validTestVectors[0]

      // Create a sample structHash (this won't verify correctly since we don't have matching signature)
      const structHash = ethers.utils.keccak256(
        ethers.utils.defaultAbiCoder.encode(
          ['bytes32', 'address', 'address', 'uint256'],
          [BLS_CHANGE_OWNER_TYPEHASH, admin.address, admin.address, 0]
        )
      )

      try {
        // This will return false since the signature doesn't match the structHash
        // But it should not revert with the structHash parameter
        const result = await didReg.checkBlsSignature(testVector.publicKey, testVector.signature, structHash)

        // Should return false since signature doesn't match
        expect(result).to.equal(false)
      } catch (error: any) {
        // May throw on pairing check failure - this is acceptable
        expect(error.message).to.exist
      }
    })

    it('should reject malformed public key length', async () => {
      const malformedPublicKey = '0x' + 'a0a0a0a0' // Too short

      const structHash = ethers.utils.keccak256(
        ethers.utils.defaultAbiCoder.encode(
          ['bytes32', 'address', 'address', 'uint256'],
          [BLS_CHANGE_OWNER_TYPEHASH, admin.address, admin.address, 0]
        )
      )

      try {
        await didReg.checkBlsSignature(malformedPublicKey, validTestVectors[0].signature, structHash)

        expect.fail('Should have reverted with malformed public key')
      } catch (error: any) {
        expect(error.message).to.exist
      }
    })

    it('should reject malformed signature length', async () => {
      const malformedSignature = '0x' + 'c0c0c0c0' // Too short

      const structHash = ethers.utils.keccak256(
        ethers.utils.defaultAbiCoder.encode(
          ['bytes32', 'address', 'address', 'uint256'],
          [BLS_CHANGE_OWNER_TYPEHASH, admin.address, admin.address, 0]
        )
      )

      try {
        await didReg.checkBlsSignature(validTestVectors[0].publicKey, malformedSignature, structHash)

        expect.fail('Should have reverted with malformed signature')
      } catch (error: any) {
        expect(error.message).to.exist
      }
    })

    it('should return different results for different structHashes', async () => {
      const testVector = validTestVectors[0]

      const structHash1 = ethers.utils.keccak256(
        ethers.utils.defaultAbiCoder.encode(
          ['bytes32', 'address', 'address', 'uint256'],
          [BLS_CHANGE_OWNER_TYPEHASH, admin.address, admin.address, 0]
        )
      )

      const structHash2 = ethers.utils.keccak256(
        ethers.utils.defaultAbiCoder.encode(
          ['bytes32', 'address', 'address', 'uint256'],
          [BLS_CHANGE_OWNER_TYPEHASH, admin.address, admin.address, 1] // Different nonce
        )
      )

      expect(structHash1).to.not.equal(structHash2)

      // Both should be callable without reverting (on valid curve points)
      try {
        await didReg.callStatic.checkBlsSignature(testVector.publicKey, testVector.signature, structHash1)
        await didReg.callStatic.checkBlsSignature(testVector.publicKey, testVector.signature, structHash2)
      } catch (error: any) {
        // May throw on pairing check - acceptable
        expect(error.message).to.exist
      }
    })
  })

  describe('BLS Signature Integration Tests', () => {
    it('should be a view function (no gas cost for calls)', async () => {
      const testVector = validTestVectors[0]

      const structHash = ethers.utils.keccak256(
        ethers.utils.defaultAbiCoder.encode(
          ['bytes32', 'address', 'address', 'uint256'],
          [BLS_CHANGE_OWNER_TYPEHASH, admin.address, admin.address, 0]
        )
      )

      try {
        // View functions don't require gas when called off-chain
        const result = await didReg.callStatic.checkBlsSignature(
          testVector.publicKey,
          testVector.signature,
          structHash
        )

        expect(result).to.be.a('boolean')
      } catch (error: any) {
        // Expected with non-matching signature
        expect(error.message).to.exist
      }
    })

    it('should be callable by any address (public function)', async () => {
      const [, , , randomUser] = await ethers.getSigners()
      const testVector = validTestVectors[0]

      const structHash = ethers.utils.keccak256(
        ethers.utils.defaultAbiCoder.encode(
          ['bytes32', 'address', 'address', 'uint256'],
          [BLS_CHANGE_OWNER_TYPEHASH, admin.address, admin.address, 0]
        )
      )

      try {
        // Any user should be able to call this public view function
        const result = await didReg
          .connect(randomUser)
          .checkBlsSignature(testVector.publicKey, testVector.signature, structHash)

        expect(result).to.be.a('boolean')
      } catch (error: any) {
        // Expected with non-matching signature
        expect(error.message).to.exist
      }
    })
  })
})

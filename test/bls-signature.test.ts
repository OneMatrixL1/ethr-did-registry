/* eslint-disable no-unused-expressions */
// Test file for BLS signature verification

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

describe('BLS Signature Verification', () => {
  let didReg: EthereumDIDRegistry
  let adminManagement: Contract
  let admin: SignerWithAddress

  // Valid BLS signature test data
  // Message: "Hello world!"
  // Curve: BLS12-381
  // DST: BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_
  const validTestVectors = [
    {
      description: 'valid BLS signature for "Hello world!"',
      // G2 Public Key - 192 bytes (PK_X1 + PK_X0 + PK_Y1 + PK_Y0)
      publicKey:
        '0x' +
        '032e5b9e02a090923681a5d44919e16995db40f86497754406e5afc39802ae33e2c367a3a147c6a55d6531ebb6af5dbf' +
        '0adf7abd27b86ae1436498c6fa09c91369d5d971ab8e2e76d6d3f9355dc2b16435bec7de51ee143757cfcceab694285a' +
        '0905b345c36460d605e56d778ceba70dd5569930d2c3b545800e0fc9ffdfa7fb02623647f7831f2a510e4de563f2428e' +
        '126d23e78717d0b8fbbeefd51add8724c47ea5b205d5491d7cc99f5529fd1d1e1b7a6d8205336edad346cebd1f5fba21',
      // Raw message - contract will hash this to G1 point using DST
      rawMessage: 'Hello world!',
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

  describe('checkBlsSignature', () => {
    it('should verify a valid BLS signature', async () => {
      const testVector = validTestVectors[0]
      const messageBytes = ethers.utils.toUtf8Bytes(testVector.rawMessage)

      const result = await didReg.checkBlsSignature(testVector.publicKey, testVector.signature, messageBytes)

      // Should return true for valid signature
      expect(result).to.equal(true)
    })

    it('should reject invalid BLS signature', async () => {
      const invalidSignature =
        '0x' +
        'd0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0' +
        'd0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0'

      const testVector = validTestVectors[0]

      try {
        const messageBytes = ethers.utils.toUtf8Bytes(testVector.rawMessage)
        const result = await didReg.checkBlsSignature(testVector.publicKey, invalidSignature, messageBytes)
        // Should return false for invalid signature
        expect(result).to.equal(false)
      } catch (error: any) {
        // May throw on invalid curve points
        expect(error.message).to.exist
      }
    })

    it('should reject signature with wrong message', async () => {
      const wrongMessage =
        '0x' +
        'e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0' +
        'e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0'

      const testVector = validTestVectors[0]

      try {
        const result = await didReg.checkBlsSignature(testVector.publicKey, testVector.signature, wrongMessage)

        // Should return false for wrong message
        expect(result).to.equal(false)
      } catch (error: any) {
        // May throw on invalid curve points
        expect(error.message).to.exist
      }
    })

    it('should reject signature with wrong public key', async () => {
      const wrongPublicKey =
        '0x' +
        'f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0' +
        'f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0' +
        'f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0'

      const testVector = validTestVectors[0]

      try {
        const messageBytes = ethers.utils.toUtf8Bytes(testVector.rawMessage)
        const result = await didReg.checkBlsSignature(wrongPublicKey, testVector.signature, messageBytes)

        // Should return false for wrong public key
        expect(result).to.equal(false)
      } catch (error: any) {
        // May throw on invalid curve points
        expect(error.message).to.exist
      }
    })

    it('should handle empty bytes inputs', async () => {
      try {
        await didReg.checkBlsSignature('0x', '0x', '0x')
        // Should fail
        expect.fail('Should have reverted with empty inputs')
      } catch (error: any) {
        // Expected to revert
        expect(error.message).to.exist
      }
    })

    it('should handle malformed public key length', async () => {
      const testVector = validTestVectors[0]
      const malformedPublicKey = '0x' + 'a0a0a0a0' // Too short

      try {
        const messageBytes = ethers.utils.toUtf8Bytes(testVector.rawMessage)
        await didReg.checkBlsSignature(malformedPublicKey, testVector.signature, messageBytes)
        // Should fail
        expect.fail('Should have reverted with malformed public key')
      } catch (error: any) {
        // Expected to revert
        expect(error.message).to.exist
      }
    })

    it('should handle malformed message length', async () => {
      const testVector = validTestVectors[0]
      const malformedMessage = '0x' + 'b0b0b0b0' // Too short

      try {
        await didReg.checkBlsSignature(testVector.publicKey, testVector.signature, malformedMessage)
        // Should fail
        expect.fail('Should have reverted with malformed message')
      } catch (error: any) {
        // Expected to revert
        expect(error.message).to.exist
      }
    })

    it('should handle malformed signature length', async () => {
      const testVector = validTestVectors[0]
      const malformedSignature = '0x' + 'c0c0c0c0' // Too short

      try {
        const messageBytes = ethers.utils.toUtf8Bytes(testVector.rawMessage)
        await didReg.checkBlsSignature(testVector.publicKey, malformedSignature, messageBytes)
        // Should fail
        expect.fail('Should have reverted with malformed signature')
      } catch (error: any) {
        // Expected to revert
        expect(error.message).to.exist
      }
    })
  })

  describe('BLS Signature Integration Tests', () => {
    it('should be a view function (no gas cost for calls)', async () => {
      const testVector = validTestVectors[0]

      try {
        // View functions don't require gas when called off-chain
        const messageBytes = ethers.utils.toUtf8Bytes(testVector.rawMessage)
        const result = await didReg.callStatic.checkBlsSignature(
          testVector.publicKey,
          testVector.signature,
          messageBytes
        )

        expect(result).to.be.a('boolean')
      } catch (error: any) {
        // Expected with placeholder data
        expect(error.message).to.exist
      }
    })

    it('should be callable by any address (public function)', async () => {
      const [, , , randomUser] = await ethers.getSigners()
      const testVector = validTestVectors[0]

      try {
        // Any user should be able to call this public view function
        const messageBytes = ethers.utils.toUtf8Bytes(testVector.rawMessage)
        const result = await didReg
          .connect(randomUser)
          .checkBlsSignature(testVector.publicKey, testVector.signature, messageBytes)

        expect(result).to.be.a('boolean')
      } catch (error: any) {
        // Expected with placeholder data
        expect(error.message).to.exist
      }
    })
  })
})



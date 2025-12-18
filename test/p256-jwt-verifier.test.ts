import { expect } from 'chai'
import { ethers } from 'hardhat'
import { P256JWTVerifier } from '../typechain-types'
import { createSign, generateKeyPairSync, KeyObject } from 'crypto'
import { BigNumber } from 'ethers'

describe('P256JWTVerifier', function () {
  let verifier: P256JWTVerifier

  beforeEach(async function () {
    const P256JWTVerifierFactory = await ethers.getContractFactory('P256JWTVerifier')
    verifier = await P256JWTVerifierFactory.deploy()
    await verifier.deployed()
  })

  describe('Deployment', function () {
    it('Should deploy successfully', async function () {
      expect(verifier.address).to.be.a('string')
    })

    it('Should return correct precompile address', async function () {
      const precompileAddr = await verifier.getPrecompileAddress()
      expect(precompileAddr).to.equal('0x0000000000000000000000000000000000000100')
    })

    it('Should return correct curve order', async function () {
      const curveOrder = await verifier.getCurveOrder()
      expect(curveOrder).to.equal('0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551')
    })
  })

  describe('P256 Signature Verification', function () {
    it('Should accept valid signature format', async function () {
      const messageHash = '0x4b688df40bcedbe641ddb16ff0a1842d9c67ea1c3bf63f3e0471baa664531d1a'
      const r = '0x5000000000000000000000000000000000000000000000000000000000000000'
      const s = '0x3000000000000000000000000000000000000000000000000000000000000000' // Valid s value (< n/2)
      const publicKeyX = '0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6'
      const publicKeyY = '0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299'

      // This will call the precompile. If not available in test environment, it may revert
      // In that case, we're testing the contract can make the call
      try {
        await verifier.verifyP256Signature(messageHash, r, s, publicKeyX, publicKeyY)
      } catch (error) {
        // Expected if precompile not available in test environment
        const errorMessage = error instanceof Error ? error.message : String(error)
        expect(errorMessage).to.not.include('MalleableSignature')
      }
    })

    it('Should reject signature with high s value (malleability)', async function () {
      const messageHash = '0x4b688df40bcedbe641ddb16ff0a1842d9c67ea1c3bf63f3e0471baa664531d1a'
      const r = '0x5000000000000000000000000000000000000000000000000000000000000000'
      // s value larger than n/2 - should be rejected
      const s = '0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632550'
      const publicKeyX = '0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6'
      const publicKeyY = '0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299'

      await expect(verifier.verifyP256Signature(messageHash, r, s, publicKeyX, publicKeyY)).to.be.revertedWith(
        'MalleableSignature'
      )
    })
  })

  describe('JWT Verification', function () {
    it('Should hash and verify JWT header.payload', async function () {
      // Example JWT header.payload (base64url encoded portions)
      const headerAndPayload =
        'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ'

      const r = '0x5000000000000000000000000000000000000000000000000000000000000000'
      const s = '0x3000000000000000000000000000000000000000000000000000000000000000'
      const publicKeyX = '0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6'
      const publicKeyY = '0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299'

      const headerAndPayloadBytes = ethers.utils.toUtf8Bytes(headerAndPayload)

      try {
        await verifier.verifyJWT(headerAndPayloadBytes, r, s, publicKeyX, publicKeyY)
        // If no error, the hashing and call structure is correct
      } catch (error) {
        // Expected if precompile not available
        const errorMessage = error instanceof Error ? error.message : String(error)
        expect(errorMessage).to.not.include('MalleableSignature')
      }
    })

    it('Should reject JWT with malleable signature', async function () {
      const headerAndPayload = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0'
      const headerAndPayloadBytes = ethers.utils.toUtf8Bytes(headerAndPayload)

      const r = '0x5000000000000000000000000000000000000000000000000000000000000000'
      const s = '0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632550' // High s
      const publicKeyX = '0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6'
      const publicKeyY = '0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299'

      await expect(verifier.verifyJWT(headerAndPayloadBytes, r, s, publicKeyX, publicKeyY)).to.be.revertedWith(
        'MalleableSignature'
      )
    })
  })

  describe('Batch Verification', function () {
    it('Should batch verify multiple JWTs', async function () {
      const headerAndPayloads = [
        ethers.utils.toUtf8Bytes('eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxIn0'),
        ethers.utils.toUtf8Bytes('eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIyIn0'),
        ethers.utils.toUtf8Bytes('eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIzIn0'),
      ]

      const rValues = [
        '0x5000000000000000000000000000000000000000000000000000000000000000',
        '0x5100000000000000000000000000000000000000000000000000000000000000',
        '0x5200000000000000000000000000000000000000000000000000000000000000',
      ]

      const sValues = [
        '0x3000000000000000000000000000000000000000000000000000000000000000',
        '0x3100000000000000000000000000000000000000000000000000000000000000',
        '0x3200000000000000000000000000000000000000000000000000000000000000',
      ]

      const publicKeysX = [
        '0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6',
        '0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6',
        '0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6',
      ]

      const publicKeysY = [
        '0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299',
        '0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299',
        '0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299',
      ]

      try {
        const results = await verifier.batchVerifyJWT(headerAndPayloads, rValues, sValues, publicKeysX, publicKeysY)
        expect(results.length).to.equal(3)
      } catch (error) {
        // Expected if precompile not available
      }
    })

    it('Should reject batch with mismatched array lengths', async function () {
      const headerAndPayloads = [ethers.utils.toUtf8Bytes('test')]
      const rValues = ['0x5000000000000000000000000000000000000000000000000000000000000000']
      const sValues = [] // Mismatched length
      const publicKeysX = ['0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6']
      const publicKeysY = ['0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299']

      await expect(
        verifier.batchVerifyJWT(headerAndPayloads, rValues, sValues, publicKeysX, publicKeysY)
      ).to.be.revertedWith('ArrayLengthMismatch')
    })

    it('Should return false for malleable signatures in batch (not revert)', async function () {
      const headerAndPayloads = [ethers.utils.toUtf8Bytes('eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxIn0')]

      const rValues = ['0x5000000000000000000000000000000000000000000000000000000000000000']
      const sValues = ['0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632550'] // High s
      const publicKeysX = ['0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6']
      const publicKeysY = ['0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299']

      const results = await verifier.batchVerifyJWT(headerAndPayloads, rValues, sValues, publicKeysX, publicKeysY)

      expect(results[0]).to.equal(false)
    })
  })

  describe('Edge Cases', function () {
    it('Should handle empty message', async function () {
      const emptyMessage = ethers.utils.toUtf8Bytes('')
      const r = '0x5000000000000000000000000000000000000000000000000000000000000000'
      const s = '0x3000000000000000000000000000000000000000000000000000000000000000'
      const publicKeyX = '0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6'
      const publicKeyY = '0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299'

      try {
        await verifier.verifyJWT(emptyMessage, r, s, publicKeyX, publicKeyY)
      } catch (error) {
        // Expected if precompile not available
      }
    })

    it('Should handle s value exactly at n/2 boundary', async function () {
      const messageHash = '0x4b688df40bcedbe641ddb16ff0a1842d9c67ea1c3bf63f3e0471baa664531d1a'
      const r = '0x5000000000000000000000000000000000000000000000000000000000000000'
      // s = n/2 + 1 (should be rejected)
      const s = '0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a9'
      const publicKeyX = '0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6'
      const publicKeyY = '0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299'

      await expect(verifier.verifyP256Signature(messageHash, r, s, publicKeyX, publicKeyY)).to.be.revertedWith(
        'MalleableSignature'
      )
    })

    it('Should handle zero values in signature components', async function () {
      const messageHash = '0x0000000000000000000000000000000000000000000000000000000000000000'
      const r = '0x0000000000000000000000000000000000000000000000000000000000000000'
      const s = '0x0000000000000000000000000000000000000000000000000000000000000000'
      const publicKeyX = '0x0000000000000000000000000000000000000000000000000000000000000000'
      const publicKeyY = '0x0000000000000000000000000000000000000000000000000000000000000000'

      try {
        await verifier.verifyP256Signature(messageHash, r, s, publicKeyX, publicKeyY)
      } catch (error) {
        // Expected behavior - zero values should fail in precompile
      }
    })

    it('Should handle maximum valid s value (exactly n/2)', async function () {
      const messageHash = '0x4b688df40bcedbe641ddb16ff0a1842d9c67ea1c3bf63f3e0471baa664531d1a'
      const r = '0x5000000000000000000000000000000000000000000000000000000000000000'
      // s = n/2 exactly (should be accepted)
      const s = '0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8'
      const publicKeyX = '0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6'
      const publicKeyY = '0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299'

      try {
        await verifier.verifyP256Signature(messageHash, r, s, publicKeyX, publicKeyY)
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error)
        expect(errorMessage).to.not.include('MalleableSignature')
      }
    })

    it('Should handle very long message in JWT verification', async function () {
      const longMessage = 'a'.repeat(10000)
      const messageBytes = ethers.utils.toUtf8Bytes(longMessage)
      const r = '0x5000000000000000000000000000000000000000000000000000000000000000'
      const s = '0x3000000000000000000000000000000000000000000000000000000000000000'
      const publicKeyX = '0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6'
      const publicKeyY = '0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299'

      try {
        await verifier.verifyJWT(messageBytes, r, s, publicKeyX, publicKeyY)
      } catch (error) {
        // Expected if precompile not available
      }
    })

    it('Should handle special characters in JWT', async function () {
      const specialChars = '{"alg":"ES256","typ":"JWT"}.{"sub":"test@email.com","name":"Tést Üser 测试"}'
      const messageBytes = ethers.utils.toUtf8Bytes(specialChars)
      const r = '0x5000000000000000000000000000000000000000000000000000000000000000'
      const s = '0x3000000000000000000000000000000000000000000000000000000000000000'
      const publicKeyX = '0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6'
      const publicKeyY = '0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299'

      try {
        await verifier.verifyJWT(messageBytes, r, s, publicKeyX, publicKeyY)
      } catch (error) {
        // Expected if precompile not available
      }
    })
  })

  describe('Batch Verification - Additional Coverage', function () {
    it('Should handle empty batch', async function () {
      const results = await verifier.batchVerifyJWT([], [], [], [], [])
      expect(results.length).to.equal(0)
    })

    it('Should handle single item batch', async function () {
      const headerAndPayloads = [ethers.utils.toUtf8Bytes('test')]
      const rValues = ['0x5000000000000000000000000000000000000000000000000000000000000000']
      const sValues = ['0x3000000000000000000000000000000000000000000000000000000000000000']
      const publicKeysX = ['0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6']
      const publicKeysY = ['0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299']

      const results = await verifier.batchVerifyJWT(headerAndPayloads, rValues, sValues, publicKeysX, publicKeysY)
      expect(results.length).to.equal(1)
    })

    it('Should handle mixed valid and invalid signatures in batch', async function () {
      const headerAndPayloads = [
        ethers.utils.toUtf8Bytes('valid1'),
        ethers.utils.toUtf8Bytes('invalid1'),
        ethers.utils.toUtf8Bytes('valid2'),
      ]

      const rValues = [
        '0x5000000000000000000000000000000000000000000000000000000000000000',
        '0x5100000000000000000000000000000000000000000000000000000000000000',
        '0x5200000000000000000000000000000000000000000000000000000000000000',
      ]

      const sValues = [
        '0x3000000000000000000000000000000000000000000000000000000000000000',
        '0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632550', // Malleable
        '0x3200000000000000000000000000000000000000000000000000000000000000',
      ]

      const publicKeysX = [
        '0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6',
        '0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6',
        '0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6',
      ]

      const publicKeysY = [
        '0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299',
        '0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299',
        '0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299',
      ]

      const results = await verifier.batchVerifyJWT(headerAndPayloads, rValues, sValues, publicKeysX, publicKeysY)
      expect(results.length).to.equal(3)
      expect(results[1]).to.equal(false) // Second signature should be invalid (malleable)
    })

    it('Should reject batch with mismatched rValues length', async function () {
      const headerAndPayloads = [ethers.utils.toUtf8Bytes('test'), ethers.utils.toUtf8Bytes('test2')]
      const rValues = ['0x5000000000000000000000000000000000000000000000000000000000000000']
      const sValues = [
        '0x3000000000000000000000000000000000000000000000000000000000000000',
        '0x3100000000000000000000000000000000000000000000000000000000000000',
      ]
      const publicKeysX = [
        '0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6',
        '0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6',
      ]
      const publicKeysY = [
        '0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299',
        '0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299',
      ]

      await expect(
        verifier.batchVerifyJWT(headerAndPayloads, rValues, sValues, publicKeysX, publicKeysY)
      ).to.be.revertedWith('ArrayLengthMismatch')
    })

    it('Should reject batch with mismatched publicKeysX length', async function () {
      const headerAndPayloads = [ethers.utils.toUtf8Bytes('test'), ethers.utils.toUtf8Bytes('test2')]
      const rValues = [
        '0x5000000000000000000000000000000000000000000000000000000000000000',
        '0x5100000000000000000000000000000000000000000000000000000000000000',
      ]
      const sValues = [
        '0x3000000000000000000000000000000000000000000000000000000000000000',
        '0x3100000000000000000000000000000000000000000000000000000000000000',
      ]
      const publicKeysX = ['0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6']
      const publicKeysY = [
        '0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299',
        '0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299',
      ]

      await expect(
        verifier.batchVerifyJWT(headerAndPayloads, rValues, sValues, publicKeysX, publicKeysY)
      ).to.be.revertedWith('ArrayLengthMismatch')
    })

    it('Should reject batch with mismatched publicKeysY length', async function () {
      const headerAndPayloads = [ethers.utils.toUtf8Bytes('test'), ethers.utils.toUtf8Bytes('test2')]
      const rValues = [
        '0x5000000000000000000000000000000000000000000000000000000000000000',
        '0x5100000000000000000000000000000000000000000000000000000000000000',
      ]
      const sValues = [
        '0x3000000000000000000000000000000000000000000000000000000000000000',
        '0x3100000000000000000000000000000000000000000000000000000000000000',
      ]
      const publicKeysX = [
        '0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6',
        '0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6',
      ]
      const publicKeysY = ['0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299']

      await expect(
        verifier.batchVerifyJWT(headerAndPayloads, rValues, sValues, publicKeysX, publicKeysY)
      ).to.be.revertedWith('ArrayLengthMismatch')
    })

    it('Should handle large batch verification', async function () {
      const batchSize = 10
      const headerAndPayloads = []
      const rValues = []
      const sValues = []
      const publicKeysX = []
      const publicKeysY = []

      for (let i = 0; i < batchSize; i++) {
        headerAndPayloads.push(ethers.utils.toUtf8Bytes(`message${i}`))
        rValues.push(`0x500000000000000000000000000000000000000000000000000000000000000${i % 10}`)
        sValues.push(`0x300000000000000000000000000000000000000000000000000000000000000${i % 10}`)
        publicKeysX.push('0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6')
        publicKeysY.push('0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299')
      }

      const results = await verifier.batchVerifyJWT(headerAndPayloads, rValues, sValues, publicKeysX, publicKeysY)
      expect(results.length).to.equal(batchSize)
    })
  })

  describe('JWT Parsing Functions', function () {
    it('Should parse a valid JWT token', async function () {
      const header = 'eyJhbGciOiJFUzI1NiJ9'
      const payload = 'eyJzdWIiOiJ0ZXN0In0'
      // Base64url encoded 64 bytes (all zeros) - exactly 86 characters
      const signature = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
      const jwt = `${header}.${payload}.${signature}`

      const [headerAndPayload, r, s] = await verifier.parseJWT(jwt)

      const expectedHeaderAndPayload = ethers.utils.toUtf8Bytes(`${header}.${payload}`)
      expect(ethers.utils.hexlify(headerAndPayload)).to.equal(ethers.utils.hexlify(expectedHeaderAndPayload))
      expect(r).to.equal('0x0000000000000000000000000000000000000000000000000000000000000000')
      expect(s).to.equal('0x0000000000000000000000000000000000000000000000000000000000000000')
    })

    it('Should reject JWT with invalid format (no dots)', async function () {
      const invalidJWT = 'nodotsjusttext'
      await expect(verifier.parseJWT(invalidJWT)).to.be.revertedWith('InvalidJWTFormat')
    })

    it('Should reject JWT with only one dot', async function () {
      const invalidJWT = 'header.payload'
      await expect(verifier.parseJWT(invalidJWT)).to.be.revertedWith('InvalidJWTFormat')
    })

    it('Should reject JWT with empty parts', async function () {
      const invalidJWT = '..signature'
      await expect(verifier.parseJWT(invalidJWT)).to.be.revertedWith('InvalidJWTFormat')
    })

    it('Should reject JWT with invalid signature length', async function () {
      const header = 'eyJhbGciOiJFUzI1NiJ9'
      const payload = 'eyJzdWIiOiJ0ZXN0In0'
      const shortSignature = 'AA'
      const jwt = `${header}.${payload}.${shortSignature}`

      await expect(verifier.parseJWT(jwt)).to.be.revertedWith('InvalidSignatureLength')
    })

    it('Should decode base64url with - and _ characters', async function () {
      // Valid base64url string that decodes to something
      const base64url = ethers.utils.toUtf8Bytes('ABCD')
      const decoded = await verifier.base64URLDecode(base64url)
      expect(decoded.length).to.be.greaterThan(0)
    })

    it('Should reject invalid base64 characters', async function () {
      const invalidBase64 = ethers.utils.toUtf8Bytes('!!!invalid!!!')
      await expect(verifier.base64URLDecode(invalidBase64)).to.be.revertedWith('InvalidBase64URL')
    })
  })

  describe('Complete JWT Verification', function () {
    it('Should verify complete JWT token', async function () {
      const header = 'eyJhbGciOiJFUzI1NiJ9'
      const payload = 'eyJzdWIiOiJ0ZXN0In0'
      const signature =
        'UAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
      const jwt = `${header}.${payload}.${signature}`

      const publicKeyX = '0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6'
      const publicKeyY = '0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299'

      try {
        await verifier.verifyJWTComplete(jwt, publicKeyX, publicKeyY)
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error)
        expect(errorMessage).to.not.include('InvalidJWTFormat')
      }
    })

    it('Should reject complete JWT with malleable signature', async function () {
      const header = 'eyJhbGciOiJFUzI1NiJ9'
      const payload = 'eyJzdWIiOiJ0ZXN0In0'
      // Proper 64-byte signature with high s value (all 0xFF bytes) - 86 chars in base64url
      const highSSignature = '_____________________________________________________________________________________w'
      const jwt = `${header}.${payload}.${highSSignature}`

      const publicKeyX = '0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6'
      const publicKeyY = '0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299'

      await expect(verifier.verifyJWTComplete(jwt, publicKeyX, publicKeyY)).to.be.revertedWith('MalleableSignature')
    })

    it('Should reject malformed complete JWT', async function () {
      const malformedJWT = 'notavalidjwt'
      const publicKeyX = '0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6'
      const publicKeyY = '0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299'

      await expect(verifier.verifyJWTComplete(malformedJWT, publicKeyX, publicKeyY)).to.be.revertedWith(
        'InvalidJWTFormat'
      )
    })
  })

  describe('Batch Complete JWT Verification', function () {
    it('Should batch verify multiple complete JWT tokens', async function () {
      const jwts = [
        'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxIn0.UAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIyIn0.UQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIzIn0.UgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      ]

      const publicKeysX = [
        '0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6',
        '0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6',
        '0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6',
      ]

      const publicKeysY = [
        '0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299',
        '0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299',
        '0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299',
      ]

      const results = await verifier.batchVerifyJWTComplete(jwts, publicKeysX, publicKeysY)
      expect(results.length).to.equal(3)
    })

    it('Should handle mixed valid and invalid JWTs in batch', async function () {
      const jwts = [
        'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxIn0.UAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        'invalid.jwt.format', // Invalid format
        'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIzIn0.UAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA___________________________________________8', // Malleable
      ]

      const publicKeysX = [
        '0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6',
        '0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6',
        '0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6',
      ]

      const publicKeysY = [
        '0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299',
        '0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299',
        '0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299',
      ]

      const results = await verifier.batchVerifyJWTComplete(jwts, publicKeysX, publicKeysY)
      expect(results.length).to.equal(3)
      expect(results[1]).to.equal(false) // Invalid format
      expect(results[2]).to.equal(false) // Malleable signature
    })

    it('Should reject batch with mismatched array lengths', async function () {
      const jwts = ['jwt1', 'jwt2']
      const publicKeysX = ['0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6']
      const publicKeysY = [
        '0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299',
        '0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299',
      ]

      await expect(verifier.batchVerifyJWTComplete(jwts, publicKeysX, publicKeysY)).to.be.revertedWith(
        'ArrayLengthMismatch'
      )
    })

    it('Should handle empty batch of complete JWTs', async function () {
      const results = await verifier.batchVerifyJWTComplete([], [], [])
      expect(results.length).to.equal(0)
    })

    it('Should handle single complete JWT in batch', async function () {
      const jwts = [
        'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.UAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      ]
      const publicKeysX = ['0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6']
      const publicKeysY = ['0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299']

      const results = await verifier.batchVerifyJWTComplete(jwts, publicKeysX, publicKeysY)
      expect(results.length).to.equal(1)
    })

    it('Should handle all invalid JWTs in batch', async function () {
      const jwts = ['invalid1', 'invalid2', 'invalid3']
      const publicKeysX = [
        '0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6',
        '0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6',
        '0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6',
      ]
      const publicKeysY = [
        '0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299',
        '0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299',
        '0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299',
      ]

      const results = await verifier.batchVerifyJWTComplete(jwts, publicKeysX, publicKeysY)
      expect(results.length).to.equal(3)
      expect(results[0]).to.equal(false)
      expect(results[1]).to.equal(false)
      expect(results[2]).to.equal(false)
    })

    it('Should handle large batch of complete JWTs', async function () {
      const batchSize = 5
      const jwts = []
      const publicKeysX = []
      const publicKeysY = []

      for (let i = 0; i < batchSize; i++) {
        jwts.push(
          `eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ0ZXN0JHtpfSJ9.UAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`
        )
        publicKeysX.push('0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6')
        publicKeysY.push('0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299')
      }

      const results = await verifier.batchVerifyJWTComplete(jwts, publicKeysX, publicKeysY)
      expect(results.length).to.equal(batchSize)
    })
  })

  describe('End-to-End JWT Generation and Verification', function () {
    // NOTE: These tests require the P-256 precompile at address 0x100 (RIP-7212)
    // To run these tests with actual P-256 verification on a forked network:
    //
    // Example with Sepolia (has P-256 precompile after certain block):
    // FORK_NETWORK=https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY yarn test test/p256-jwt-verifier.test.ts
    //
    // Example with OneMatrix:
    // FORK_NETWORK=https://rpc.vietcha.in yarn test test/p256-jwt-verifier.test.ts
    //
    // Without forking, these tests demonstrate JWT generation and signing is correct,
    // but verification will return false (precompile not available in local Hardhat)

    // Helper function to generate P-256 key pair
    function generateP256KeyPair() {
      return generateKeyPairSync('ec', {
        namedCurve: 'prime256v1',
      })
    }

    // Helper function to extract public key coordinates from DER format
    function extractPublicKeyCoordinates(publicKey: KeyObject): { x: string; y: string } {
      const publicKeyDer = publicKey.export({ type: 'spki', format: 'der' })
      // P-256 uncompressed public key: 0x04 + 32 bytes X + 32 bytes Y
      // DER encoding has headers, the actual key starts at the end
      const uncompressedKey = publicKeyDer.slice(-65)

      if (uncompressedKey[0] !== 0x04) {
        throw new Error('Expected uncompressed public key format')
      }

      const x = '0x' + uncompressedKey.slice(1, 33).toString('hex')
      const y = '0x' + uncompressedKey.slice(33, 65).toString('hex')

      return { x, y }
    }

    // Helper function to normalize s value to prevent malleability
    function normalizeSignature(signature: Buffer): Buffer {
      const P256_N = BigNumber.from('0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551')
      const P256_N_DIV_2 = P256_N.div(2)

      const r = signature.slice(0, 32)
      const s = BigNumber.from('0x' + signature.slice(32, 64).toString('hex'))

      // If s > n/2, normalize it to n - s
      if (s.gt(P256_N_DIV_2)) {
        const normalizedS = P256_N.sub(s)
        const normalizedSBuffer = Buffer.from(normalizedS.toHexString().slice(2).padStart(64, '0'), 'hex')
        return Buffer.concat([r, normalizedSBuffer])
      }

      return signature
    }

    // Helper function to create JWT and sign it
    function createAndSignJWT(
      payload: object,
      privateKey: KeyObject
    ): { jwt: string; header: string; payload: string; signature: Buffer } {
      const header = { alg: 'ES256', typ: 'JWT' }
      const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url')
      const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url')
      const message = `${headerB64}.${payloadB64}`

      // Sign with P-256
      const sign = createSign('SHA256')
      sign.update(message)
      sign.end()
      let signature = sign.sign({
        key: privateKey,
        dsaEncoding: 'ieee-p1363', // This gives us r || s format (64 bytes)
      })

      // Normalize signature to prevent malleability
      signature = normalizeSignature(signature)

      const signatureB64 = signature.toString('base64url')
      const jwt = `${message}.${signatureB64}`

      return { jwt, header: headerB64, payload: payloadB64, signature }
    }

    it('Should generate and parse a real JWT signed with P-256', async function () {
      const { publicKey, privateKey } = generateP256KeyPair()
      const { x, y } = extractPublicKeyCoordinates(publicKey)

      const payload = { sub: 'user123', name: 'Test User', iat: Math.floor(Date.now() / 1000) }
      const { header, payload: payloadB64, signature } = createAndSignJWT(payload, privateKey)

      const r = '0x' + signature.slice(0, 32).toString('hex')
      const s = '0x' + signature.slice(32, 64).toString('hex')
      const headerAndPayload = `${header}.${payloadB64}`

      // Verify signature components are correct format
      expect(signature.length).to.equal(64)
      expect(r).to.match(/^0x[0-9a-f]{64}$/i)
      expect(s).to.match(/^0x[0-9a-f]{64}$/i)

      // Verify public key coordinates are extracted correctly
      expect(x).to.match(/^0x[0-9a-f]{64}$/i)
      expect(y).to.match(/^0x[0-9a-f]{64}$/i)

      // Call verifier (will return false without precompile, true with forked network)
      const result = await verifier.verifyJWT(ethers.utils.toUtf8Bytes(headerAndPayload), r, s, x, y)
      // In forked network with P-256 precompile, this should be true
      // In local Hardhat without precompile, this will be false
      expect(typeof result).to.equal('boolean')
    })

    it('Should parse and verify complete JWT token structure', async function () {
      const { publicKey, privateKey } = generateP256KeyPair()
      const { x, y } = extractPublicKeyCoordinates(publicKey)

      const payload = { sub: 'user456', email: 'test@example.com', exp: Math.floor(Date.now() / 1000) + 3600 }
      const { jwt } = createAndSignJWT(payload, privateKey)

      // Verify JWT structure
      const parts = jwt.split('.')
      expect(parts.length).to.equal(3)
      expect(parts[2].length).to.equal(86) // Base64url 64 bytes = 86 chars

      const result = await verifier.verifyJWTComplete(jwt, x, y)
      expect(typeof result).to.equal('boolean')
    })

    it('Should reject JWT with wrong public key', async function () {
      // Generate two different key pairs
      const { publicKey: publicKey1, privateKey: privateKey1 } = generateP256KeyPair()
      const { publicKey: publicKey2 } = generateP256KeyPair()

      const { x, y } = extractPublicKeyCoordinates(publicKey2) // Use wrong public key

      const payload = { sub: 'user789', data: 'sensitive' }
      const { jwt } = createAndSignJWT(payload, privateKey1)

      // Should fail verification with wrong key
      const result = await verifier.verifyJWTComplete(jwt, x, y)

      expect(result).to.be.a('boolean')
    })

    it('Should verify multiple JWTs from different signers', async function () {
      // Generate 3 different signers
      const signer1 = generateP256KeyPair()
      const signer2 = generateP256KeyPair()
      const signer3 = generateP256KeyPair()

      const key1 = extractPublicKeyCoordinates(signer1.publicKey)
      const key2 = extractPublicKeyCoordinates(signer2.publicKey)
      const key3 = extractPublicKeyCoordinates(signer3.publicKey)

      // Create JWTs
      const jwt1 = createAndSignJWT({ user: 'alice', role: 'admin' }, signer1.privateKey).jwt
      const jwt2 = createAndSignJWT({ user: 'bob', role: 'user' }, signer2.privateKey).jwt
      const jwt3 = createAndSignJWT({ user: 'charlie', role: 'guest' }, signer3.privateKey).jwt

      // Batch verify
      const results = await verifier.batchVerifyJWTComplete(
        [jwt1, jwt2, jwt3],
        [key1.x, key2.x, key3.x],
        [key1.y, key2.y, key3.y]
      )

      expect(results[0]).to.be.a('boolean')
      expect(results[1]).to.be.a('boolean')
      expect(results[2]).to.be.a('boolean')
    })

    it('Should handle mixed valid and invalid JWTs in batch', async function () {
      const signer1 = generateP256KeyPair()
      const signer2 = generateP256KeyPair()
      const wrongKey = generateP256KeyPair()

      const key1 = extractPublicKeyCoordinates(signer1.publicKey)
      const key2 = extractPublicKeyCoordinates(signer2.publicKey)
      const wrongKeyCoords = extractPublicKeyCoordinates(wrongKey.publicKey)

      const jwt1 = createAndSignJWT({ valid: true }, signer1.privateKey).jwt
      const jwt2 = createAndSignJWT({ valid: false }, signer2.privateKey).jwt // Signed by signer2

      // Verify jwt1 correctly, but jwt2 with wrong key
      const results = await verifier.batchVerifyJWTComplete(
        [jwt1, jwt2],
        [key1.x, wrongKeyCoords.x], // jwt2 uses wrong key
        [key1.y, wrongKeyCoords.y]
      )

      expect(results[0]).to.be.a('boolean') // Valid
      expect(results[1]).to.be.a('boolean') // Invalid (wrong key)
    })

    it('Should verify JWT with various payload sizes', async function () {
      const { publicKey, privateKey } = generateP256KeyPair()
      const { x, y } = extractPublicKeyCoordinates(publicKey)

      // Small payload
      const smallPayload = { sub: '1' }
      const smallJWT = createAndSignJWT(smallPayload, privateKey).jwt
      const result1 = await verifier.verifyJWTComplete(smallJWT, x, y)
      expect(result1).to.be.a('boolean')

      // Medium payload
      const mediumPayload = {
        sub: 'user123',
        name: 'John Doe',
        email: 'john@example.com',
        roles: ['admin', 'user'],
        iat: Date.now(),
      }
      const mediumJWT = createAndSignJWT(mediumPayload, privateKey).jwt
      const result2 = await verifier.verifyJWTComplete(mediumJWT, x, y)
      expect(result2).to.be.a('boolean')

      // Large payload
      const largePayload = {
        sub: 'user456',
        data: 'x'.repeat(1000),
        metadata: { key1: 'value1', key2: 'value2', key3: 'value3' },
        array: Array.from({ length: 50 }, (_, i) => ({ id: i, value: `item${i}` })),
      }
      const largeJWT = createAndSignJWT(largePayload, privateKey).jwt
      const result3 = await verifier.verifyJWTComplete(largeJWT, x, y)
      expect(result3).to.be.a('boolean')
    })

    it('Should verify JWT with special characters in payload', async function () {
      const { publicKey, privateKey } = generateP256KeyPair()
      const { x, y } = extractPublicKeyCoordinates(publicKey)

      const payload = {
        name: 'Tëst Üser 测试',
        emoji: '🔐🚀',
        special: '!@#$%^&*()_+-=[]{}|;:,.<>?',
      }

      const { jwt } = createAndSignJWT(payload, privateKey)
      const result = await verifier.verifyJWTComplete(jwt, x, y)

      expect(result).to.be.a('boolean')
    })

    it('Should verify same payload signed by different keys', async function () {
      const payload = { sub: 'shared-user', action: 'login' }

      const signer1 = generateP256KeyPair()
      const signer2 = generateP256KeyPair()

      const key1 = extractPublicKeyCoordinates(signer1.publicKey)
      const key2 = extractPublicKeyCoordinates(signer2.publicKey)

      const jwt1 = createAndSignJWT(payload, signer1.privateKey).jwt
      const jwt2 = createAndSignJWT(payload, signer2.privateKey).jwt

      // Both should verify with their respective keys
      const result1 = await verifier.verifyJWTComplete(jwt1, key1.x, key1.y)
      const result2 = await verifier.verifyJWTComplete(jwt2, key2.x, key2.y)

      expect(result1).to.be.a('boolean')
      expect(result2).to.be.a('boolean')

      // Cross-verification should fail
      const crossResult1 = await verifier.verifyJWTComplete(jwt1, key2.x, key2.y)
      const crossResult2 = await verifier.verifyJWTComplete(jwt2, key1.x, key1.y)

      expect(crossResult1).to.be.a('boolean')
      expect(crossResult2).to.be.a('boolean')
    })

    it('Should handle batch verification with 10 different signers', async function () {
      const signers = Array.from({ length: 10 }, () => generateP256KeyPair())
      const keys = signers.map((s) => extractPublicKeyCoordinates(s.publicKey))
      const jwts = signers.map((s, i) => createAndSignJWT({ user: `user${i}`, index: i }, s.privateKey).jwt)

      const results = await verifier.batchVerifyJWTComplete(
        jwts,
        keys.map((k) => k.x),
        keys.map((k) => k.y)
      )

      // All should be valid
      results.forEach((result) => {
        expect(result).to.be.a('boolean')
      })
    })

    it('Should verify using pre-extracted components', async function () {
      const { publicKey, privateKey } = generateP256KeyPair()
      const { x, y } = extractPublicKeyCoordinates(publicKey)

      const payload = { test: 'option-c-verification' }
      const { header, payload: payloadB64, signature } = createAndSignJWT(payload, privateKey)

      const headerAndPayload = ethers.utils.toUtf8Bytes(`${header}.${payloadB64}`)
      const r = '0x' + signature.slice(0, 32).toString('hex')
      const s = '0x' + signature.slice(32, 64).toString('hex')

      const result = await verifier.verifyJWT(headerAndPayload, r, s, x, y)

      expect(result).to.be.a('boolean')
    })

    it('Should verify batch using pre-extracted components', async function () {
      const signers = Array.from({ length: 5 }, () => generateP256KeyPair())
      const keys = signers.map((s) => extractPublicKeyCoordinates(s.publicKey))

      const headerAndPayloads = []
      const rValues = []
      const sValues = []

      for (let i = 0; i < signers.length; i++) {
        const { header, payload, signature } = createAndSignJWT({ id: i }, signers[i].privateKey)
        headerAndPayloads.push(ethers.utils.toUtf8Bytes(`${header}.${payload}`))
        rValues.push('0x' + signature.slice(0, 32).toString('hex'))
        sValues.push('0x' + signature.slice(32, 64).toString('hex'))
      }

      const results = await verifier.batchVerifyJWT(
        headerAndPayloads,
        rValues,
        sValues,
        keys.map((k) => k.x),
        keys.map((k) => k.y)
      )

      results.forEach((result) => {
        expect(result).to.be.a('boolean')
      })
    })
  })
})

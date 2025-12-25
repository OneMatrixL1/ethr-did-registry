// Integration tests for BLS owner change functionality (changeOwnerWithPubkey)

import chai, { expect } from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { solidity } from 'ethereum-waffle'
import { Contract } from 'ethers'
import { SignerWithAddress } from '@nomiclabs/hardhat-ethers/signers'
import { EthereumDIDRegistry } from '../typechain-types'

chai.use(chaiAsPromised)
chai.use(solidity)

describe('BLS Owner Change Integration Tests (changeOwnerWithPubkey)', () => {
  let didReg: EthereumDIDRegistry
  let adminManagement: Contract
  let admin: SignerWithAddress
  let user1: SignerWithAddress
  let user2: SignerWithAddress
  let user3: SignerWithAddress

  // Test BLS public key (96 bytes = G2 point)
  // From test/data/bls_signature.json
  const blsPublicKey =
    '0x' +
    '032e5b9e02a090923681a5d44919e16995db40f86497754406e5afc39802ae33e2c367a3a147c6a55d6531ebb6af5dbf' +
    '0adf7abd27b86ae1436498c6fa09c91369d5d971ab8e2e76d6d3f9355dc2b16435bec7de51ee143757cfcceab694285a' +
    '0905b345c36460d605e56d778ceba70dd5569930d2c3b545800e0fc9ffdfa7fb02623647f7831f2a510e4de563f2428e' +
    '126d23e78717d0b8fbbeefd51add8724c47ea5b205d5491d7cc99f5529fd1d1e1b7a6d8205336edad346cebd1f5fba21'

  // Test BLS signature
  const blsSignature =
    '0x' +
    '04354919ba779ad031cd88774df9dd24e925b6396eafe20b5ab9c449f2cfc421e7eb463015d466040d446dff5cb62241' +
    '0462454c0ff9dc9cb2cbb87f12053839a4e7988b7a34483c59b4ee7965cc0603f2773033a68fdd5a9cc3f4915193645c'

  before(async () => {
    // Get signers
    const signers = await ethers.getSigners()
    admin = signers[0]
    user1 = signers[1]
    user2 = signers[2]
    user3 = signers[3]

    // Deploy admin management contract
    const AdminManagement = await ethers.getContractFactory('AdminManagement')
    adminManagement = await AdminManagement.connect(admin).deploy()
    await adminManagement.deployed()

    // Deploy registry with admin management address
    const Registry = await ethers.getContractFactory('EthereumDIDRegistry')
    didReg = await Registry.connect(admin).deploy(adminManagement.address)
    await didReg.deployed()

    console.log(`\n✓ Contracts deployed:`)
    console.log(`  - Registry: ${didReg.address}`)
    console.log(`  - Admin Management: ${adminManagement.address}`)
  })

  describe('Owner state for replay protection', () => {
    it('should allow identity to return itself as owner by default', async () => {
      const testAddress = user1.address
      const owner = await didReg.identityOwner(testAddress)

      expect(owner).to.equal(testAddress)
      console.log(`\n✓ Identity owner defaults to self: ${testAddress}`)
    })

    it('should allow tracking owner independently from nonce', async () => {
      const testAddress = user2.address
      const owner = await didReg.identityOwner(testAddress)
      const regularNonce = await didReg.nonce(testAddress)

      expect(owner).to.equal(testAddress)
      expect(regularNonce).to.equal(0)
      console.log(`\n✓ Owner state is independent from nonce tracking:`)
      console.log(`  - Identity owner: ${owner}`)
      console.log(`  - Nonce: ${regularNonce}`)
    })
  })

  describe('changeOwnerWithPubkey function existence and signature', () => {
    it('should have changeOwnerWithPubkey function', async () => {
      expect(didReg.changeOwnerWithPubkey).to.be.a('function')
      console.log(`\n✓ changeOwnerWithPubkey function exists`)
    })

    it('should have correct EIP-712 type hash constant (3-field simplified structure)', async () => {
      const typeHash = await didReg.CHANGE_OWNER_WITH_PUBKEY_TYPEHASH()

      // New simplified structure: 3 fields (identity, oldOwner, newOwner)
      const expectedTypeHash = ethers.utils.keccak256(
        ethers.utils.toUtf8Bytes('ChangeOwnerWithPubkey(address identity,address oldOwner,address newOwner)')
      )

      expect(typeHash).to.equal(expectedTypeHash)
      console.log(`\n✓ CHANGE_OWNER_WITH_PUBKEY_TYPEHASH matches new 3-field structure`)
      console.log(`  - Type hash: ${typeHash}`)
      console.log(`  - Structure: ChangeOwnerWithPubkey(address identity,address oldOwner,address newOwner)`)
    })

    it('should have domain separator set correctly', async () => {
      const domainSeparator = await didReg.DOMAIN_SEPARATOR()

      expect(domainSeparator).to.not.equal(undefined)
      expect(domainSeparator).to.not.equal(ethers.constants.HashZero)
      console.log(`\n✓ DOMAIN_SEPARATOR is correctly initialized`)
      console.log(`  - Domain separator: ${domainSeparator}`)
    })
  })

  describe('Owner change workflow', () => {
    it('should allow direct owner change via changeOwner', async () => {
      const identity = user1.address
      const newOwner = user2.address

      // Identity starts with identity as its own owner (default)
      let currentOwner = await didReg.identityOwner(identity)
      expect(currentOwner).to.equal(identity)

      // User1 (identity owner) can change owner
      await didReg.connect(user1).changeOwner(identity, newOwner)
      currentOwner = await didReg.identityOwner(identity)
      expect(currentOwner).to.equal(newOwner)

      console.log(`\n✓ Direct owner change works:`)
      console.log(`  - Identity: ${identity}`)
      console.log(`  - New Owner: ${newOwner}`)
    })

    it('should have identityOwner return self for unset owners', async () => {
      const identity = user3.address
      const owner = await didReg.identityOwner(identity)

      expect(owner).to.equal(identity)
      console.log(`\n✓ identityOwner returns self for unset owner: ${identity}`)
    })
  })

  describe('changeOwnerWithPubkey validation', () => {
    it('should reject zero newOwner address', async () => {
      const identity = user1.address
      const oldOwner = await didReg.identityOwner(identity)
      const zeroAddress = ethers.constants.AddressZero

      await expect(
        didReg.connect(admin).changeOwnerWithPubkey(identity, oldOwner, zeroAddress, blsPublicKey, blsSignature)
      ).to.be.revertedWith('invalid_new_owner')
    })

    it('should reject if signer is not current owner', async () => {
      const testIdentity = ethers.Wallet.createRandom().address
      const testOldOwner = testIdentity // testIdentity is its own owner

      // testIdentity starts as its own owner (since no owner is set)
      // The BLS pubkey address is NOT the owner
      // So changeOwnerWithPubkey should fail

      await expect(
        didReg
          .connect(admin)
          .changeOwnerWithPubkey(testIdentity, testOldOwner, user2.address, blsPublicKey, blsSignature)
      ).to.be.reverted
    })
  })

  describe('Event emission', () => {
    it('should emit DIDOwnerChanged event on successful owner change', async () => {
      // Use admin as the identity so admin can call changeOwner on it
      const testIdentity = admin.address
      const newOwner = user2.address

      // admin (who is the identity owner) changes owner to user2
      const tx = await didReg.connect(admin).changeOwner(testIdentity, newOwner)

      // Check that event was emitted
      const receipt = await tx.wait()
      const events = receipt.events?.filter((e) => e.event === 'DIDOwnerChanged')

      expect(events).to.have.lengthOf(1)
      expect(events?.[0].args?.identity).to.equal(testIdentity)
      expect(events?.[0].args?.owner).to.equal(newOwner)

      console.log(`\n✓ DIDOwnerChanged event emitted correctly`)
    })
  })
})

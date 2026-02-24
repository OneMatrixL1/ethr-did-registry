import { expect } from 'chai'
import { SignerWithAddress } from '@nomiclabs/hardhat-ethers/signers'
import { EthereumDIDRegistry, AdminManagement } from '../typechain-types'
import { 
  concat, 
  hexlify, 
  keccak256, 
  toUtf8Bytes, 
  zeroPad, 
  arrayify,
  SigningKey,
  joinSignature,
  formatBytes32String
} from 'ethers/lib/utils'

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { ethers } = require('hardhat')

describe('EthereumDIDRegistry - Dual DID Support', function () {
  let registry: EthereumDIDRegistry
  let adminManagement: AdminManagement
  let admin: SignerWithAddress
  let owner: SignerWithAddress
  let issuer: SignerWithAddress
  let other: SignerWithAddress
  let newOwner: SignerWithAddress
  let accounts: SignerWithAddress[]

  let identity40Bytes: string
  let pId: string

  beforeEach(async function () {
    accounts = await ethers.getSigners()
    ;[admin, owner, issuer, other, newOwner] = accounts

    // Deploy AdminManagement
    const AdminManagementFactory = await ethers.getContractFactory('AdminManagement')
    adminManagement = await AdminManagementFactory.deploy()
    await adminManagement.deployed()

    // Deploy EthereumDIDRegistry
    const RegistryFactory = await ethers.getContractFactory('EthereumDIDRegistry')
    registry = await RegistryFactory.deploy(adminManagement.address)
    await registry.deployed()

    // Set admin
    await adminManagement.setAdmin(admin.address, true)

    // Create 40-byte identity (owner + issuer)
    const ownerBytes = owner.address.slice(2).toLowerCase()
    const issuerBytes = issuer.address.slice(2).toLowerCase()
    identity40Bytes = '0x' + ownerBytes + issuerBytes
    
    // Compute pId (address derived from keccak256 hash)
    const hash = keccak256(identity40Bytes)
    pId = ethers.utils.getAddress('0x' + hash.slice(26))
  })

  describe('View/Pure Functions', function () {
    it('getPIdDualDID should return expected address of 40-byte identity', async function () {
      const result = await registry.getPIdDualDID(identity40Bytes)
      expect(result).to.equal(pId)
    })

    it('getOwnerDualDID should extract owner from 40-byte identity by default', async function () {
      const result = await registry.getOwnerDualDID(identity40Bytes)
      expect(result).to.equal(owner.address)
    })

    it('getIssuerDualDID should extract issuer from 40-byte identity by default', async function () {
      const result = await registry.getIssuerDualDID(identity40Bytes)
      expect(result).to.equal(issuer.address)
    })

    it('identityOwner should return pId itself by default if not registered/contextualized', async function () {
      const result = await registry.identityOwner(pId)
      expect(result).to.equal(pId)
    })
  })

  describe('State Changing Functions with withDualContext', function () {
    it('changeOwnerDualDID should succeed when called by extracted owner', async function () {
      await registry.connect(owner).changeOwnerDualDID(identity40Bytes, newOwner.address)
      const registeredOwner = await registry.owners(pId)
      expect(registeredOwner).to.equal(newOwner.address)
    })

    it('changeOwnerDualDID should fail when called by others', async function () {
      await expect(
        registry.connect(other).changeOwnerDualDID(identity40Bytes, newOwner.address)
      ).to.be.revertedWith('bad_actor')
    })

    it('addDelegateDualDID should succeed when called by extracted owner', async function () {
      const delegateType = formatBytes32String('attestor')
      await registry.connect(owner).addDelegateDualDID(identity40Bytes, delegateType, other.address, 86400)
      
      const isValid = await registry.validDelegate(pId, delegateType, other.address)
      expect(isValid).to.be.true
    })

    it('setAttributeDualDID should succeed when called by extracted owner', async function () {
      const attrName = formatBytes32String('encryptionKey')
      const attrValue = toUtf8Bytes('my-key')
      
      await expect(
        registry.connect(owner).setAttributeDualDID(identity40Bytes, attrName, attrValue, 86400)
      ).to.emit(registry, 'DIDAttributeChanged')
    })
  })

  describe('Signed Functions', function () {
    async function signData(
      identity: string,
      privateKeyStr: string,
      dataBytes: string,
      nonce?: number
    ) {
      const _nonce = nonce !== undefined ? nonce : await registry.nonce(owner.address)
      const paddedNonce = zeroPad(arrayify(_nonce), 32)
      // Standard signature format: hexConcat(['0x1900', registry.address, paddedNonce, identity, dataBytes])
      const dataToSign = concat([
        toUtf8Bytes('\x19\x00'),
        registry.address,
        paddedNonce,
        identity,
        dataBytes
      ])
      const hash = keccak256(dataToSign)
      const signingKey = new SigningKey(privateKeyStr)
      return signingKey.signDigest(hash)
    }

    it('changeOwnerSignedDualDID should succeed with valid signature from extracted owner', async function () {
      // Data bytes for changeOwner: concat([toUtf8Bytes('changeOwner'), newOwner.address])
      const dataBytes = hexlify(concat([
        toUtf8Bytes('changeOwner'),
        arrayify(newOwner.address)
      ]))
      
      const privateKey = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80' // Hardhat account 0 (Owner)
      // Note: We need a real private key for a reliable test. owner is Hardhat account 1.
      // accounts = [admin, owner, issuer, other, newOwner]
      // Hardhat provides 20 accounts by default.
      
      // Let's use the actual private key if we can't get it from signer, 
      // but in hardhat we usually don't have direct access to private keys of signers.
      // We can use a wallet created from a known PK.
      const wallet = new ethers.Wallet('0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d', ethers.provider) // Account 1
      // Check if wallet address matches owner.address
      // console.log('Wallet address:', wallet.address)
      // console.log('Owner address:', owner.address)

      const sig = await signData(
        pId,
        '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d',
        dataBytes,
        0
      )

      await registry.connect(other).changeOwnerSignedDualDID(
        identity40Bytes,
        sig.v,
        sig.r,
        sig.s,
        newOwner.address
      )

      const registeredOwner = await registry.owners(pId)
      expect(registeredOwner).to.equal(newOwner.address)
    })
  })

  describe('Administrative Functions', function () {
    it('adminChangeOwnerDualDID should succeed when called by admin', async function () {
      await registry.connect(admin).adminChangeOwnerDualDID(identity40Bytes, newOwner.address)
      const registeredOwner = await registry.owners(pId)
      expect(registeredOwner).to.equal(newOwner.address)
    })

    it('adminChangeOwnerDualDID should fail when called by non-admin', async function () {
      await expect(
        registry.connect(other).adminChangeOwnerDualDID(identity40Bytes, newOwner.address)
      ).to.be.revertedWith('only_admin')
    })
  })
})

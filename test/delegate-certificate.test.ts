import chai, { expect } from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { solidity } from 'ethereum-waffle'
import { ContractTransaction, Contract } from 'ethers'
import { SignerWithAddress } from '@nomiclabs/hardhat-ethers/signers'
import {
  arrayify,
  concat,
  hexConcat,
  hexlify,
  SigningKey,
  toUtf8Bytes,
  zeroPad,
} from 'ethers/lib/utils'
import { EthereumDIDRegistry } from '../typechain-types/contracts/EthereumDIDRegistry'

chai.use(chaiAsPromised)
chai.use(solidity)

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { ethers } = require('hardhat')

describe('DelegateCertificate', () => {
  let didReg: EthereumDIDRegistry
  let adminManagement: Contract
  let identity: SignerWithAddress
  let badBoy: SignerWithAddress
  let sponsor: SignerWithAddress

  // Deterministic key pair — identity owner is signerAddress itself (no prior owner change)
  const privateKey = arrayify('0xb285ab66393c5fdda46d6fbad9e27fafd438254ab72ad5acb681a0e9f20f5d7b')
  const signerAddress = ethers.utils.computeAddress(privateKey)

  const privateKey2 = arrayify('0xb285ab66393c5fdda46d6fbad9e27fafd438254ab72ad5acb681a0e9f20f5d7a')

  const HOLDER_DID = 'did:ethr:0x75Bddf594B019140fEBB5913a5ffB907EafFd20E'
  const CHIP_DID =
    'did:key:z2MGw4gk84USotaWf4AkJ83DcnrfgGaceF86KQXRYMfQ7xqnUG7bWD1cwaaD4uZaSQdcptppWTUqU7dM4i7ZdWL5'
  const TIMESTAMP = 1773995311
  const AA_SIGNATURE = toUtf8Bytes('mock-aa-signature-bytes')

  before(async () => {
    const AdminManagement = await ethers.getContractFactory('AdminManagement')
    ;[identity, badBoy, sponsor] = await ethers.getSigners()
    adminManagement = await AdminManagement.deploy()
    await adminManagement.deployed()

    const Registry = await ethers.getContractFactory('EthereumDIDRegistry')
    didReg = await Registry.deploy(adminManagement.address)
    await didReg.deployed()
  })

  async function signCertificate(
    identityAddr: string,
    ownerAddr: string,
    privateKeyBytes: Uint8Array,
    holderDID: string,
    chipDID: string,
    timestamp: number,
    aaSignature: Uint8Array,
    nonce?: number
  ) {
    const _nonce = nonce !== undefined ? nonce : (await didReg.nonce(ownerAddr)).toNumber()
    const paddedNonce = zeroPad(arrayify(_nonce), 32)
    const dataToSign = hexConcat([
      '0x1900',
      didReg.address,
      paddedNonce,
      identityAddr,
      concat([
        toUtf8Bytes('setDelegateCertificate'),
        toUtf8Bytes(holderDID),
        toUtf8Bytes(chipDID),
        zeroPad(hexlify(timestamp), 32),
        aaSignature,
      ]),
    ])
    const hash = ethers.utils.keccak256(dataToSign)
    return new SigningKey(privateKeyBytes).signDigest(hash)
  }

  describe('setDelegateCertificate()', () => {
    describe('as identity owner', () => {
      let tx: ContractTransaction

      before(async () => {
        tx = await didReg
          .connect(identity)
          .setDelegateCertificate(identity.address, HOLDER_DID, CHIP_DID, TIMESTAMP, AA_SIGNATURE)
      })

      it('should store the certificate', async () => {
        const cert = await didReg.getDelegateCertificate(identity.address)
        expect(cert.holderDID).to.equal(HOLDER_DID)
        expect(cert.chipDID).to.equal(CHIP_DID)
        expect(cert.timestamp.toNumber()).to.equal(TIMESTAMP)
        expect(cert.aaSignature).to.equal(ethers.utils.hexlify(AA_SIGNATURE))
      })

      it('should update changed to current block', async () => {
        const latest = await didReg.changed(identity.address)
        expect(latest).to.equal(tx.blockNumber)
      })

      it('should emit DIDDelegateCertificateChanged event', async () => {
        const receipt = await tx.wait()
        const event = receipt.events?.[0]
        expect(event?.event).to.equal('DIDDelegateCertificateChanged')
        expect(event?.args?.identity).to.equal(identity.address)
        expect(event?.args?.holderDID).to.equal(HOLDER_DID)
        expect(event?.args?.chipDID).to.equal(CHIP_DID)
        expect(event?.args?.timestamp.toNumber()).to.equal(TIMESTAMP)
        expect(event?.args?.aaSignature).to.equal(ethers.utils.hexlify(AA_SIGNATURE))
      })
    })

    describe('as non-owner', () => {
      it('should fail', async () => {
        await expect(
          didReg
            .connect(badBoy)
            .setDelegateCertificate(identity.address, HOLDER_DID, CHIP_DID, TIMESTAMP, AA_SIGNATURE)
        ).to.be.revertedWith('bad_actor')
      })
    })

    describe('overwrite existing certificate', () => {
      const NEW_CHIP_DID = 'did:key:zNewChipDID'
      const NEW_TIMESTAMP = 1773999999
      let previousChange: number
      let tx: ContractTransaction

      before(async () => {
        previousChange = (await didReg.changed(identity.address)).toNumber()
        tx = await didReg
          .connect(identity)
          .setDelegateCertificate(identity.address, HOLDER_DID, NEW_CHIP_DID, NEW_TIMESTAMP, AA_SIGNATURE)
      })

      it('should overwrite chipDID and timestamp', async () => {
        const cert = await didReg.getDelegateCertificate(identity.address)
        expect(cert.chipDID).to.equal(NEW_CHIP_DID)
        expect(cert.timestamp.toNumber()).to.equal(NEW_TIMESTAMP)
      })

      it('should emit event with previousChange pointing to prior block', async () => {
        const receipt = await tx.wait()
        const event = receipt.events?.[0]
        expect(event?.args?.previousChange.toNumber()).to.equal(previousChange)
      })
    })
  })

  describe('setDelegateCertificateSigned()', () => {
    describe('with valid signature (sponsor pays gas)', () => {
      let tx: ContractTransaction
      const NEW_HOLDER_DID = 'did:ethr:0xSignedHolder'

      before(async () => {
        const sig = await signCertificate(
          signerAddress,
          signerAddress,
          privateKey,
          NEW_HOLDER_DID,
          CHIP_DID,
          TIMESTAMP,
          AA_SIGNATURE
        )
        // sponsor submits tx on behalf of signerAddress
        tx = await didReg
          .connect(sponsor)
          .setDelegateCertificateSigned(
            signerAddress,
            sig.v,
            sig.r,
            sig.s,
            NEW_HOLDER_DID,
            CHIP_DID,
            TIMESTAMP,
            AA_SIGNATURE
          )
      })

      it('should store the certificate', async () => {
        const cert = await didReg.getDelegateCertificate(signerAddress)
        expect(cert.holderDID).to.equal(NEW_HOLDER_DID)
        expect(cert.chipDID).to.equal(CHIP_DID)
        expect(cert.timestamp.toNumber()).to.equal(TIMESTAMP)
      })

      it('should increment nonce', async () => {
        const n = await didReg.nonce(signerAddress)
        expect(n.toNumber()).to.equal(1)
      })

      it('should emit DIDDelegateCertificateChanged event', async () => {
        const receipt = await tx.wait()
        const event = receipt.events?.[0]
        expect(event?.event).to.equal('DIDDelegateCertificateChanged')
        expect(event?.args?.identity).to.equal(signerAddress)
      })
    })

    describe('with wrong signer', () => {
      it('should fail', async () => {
        const sig = await signCertificate(
          signerAddress,
          signerAddress,
          privateKey2, // wrong key
          HOLDER_DID,
          CHIP_DID,
          TIMESTAMP,
          AA_SIGNATURE
        )
        await expect(
          didReg
            .connect(sponsor)
            .setDelegateCertificateSigned(
              signerAddress,
              sig.v,
              sig.r,
              sig.s,
              HOLDER_DID,
              CHIP_DID,
              TIMESTAMP,
              AA_SIGNATURE
            )
        ).to.be.revertedWith('bad_signature')
      })
    })

    describe('with replayed nonce', () => {
      it('should fail', async () => {
        const sig = await signCertificate(
          signerAddress,
          signerAddress,
          privateKey,
          HOLDER_DID,
          CHIP_DID,
          TIMESTAMP,
          AA_SIGNATURE,
          0 // stale nonce
        )
        await expect(
          didReg
            .connect(sponsor)
            .setDelegateCertificateSigned(
              signerAddress,
              sig.v,
              sig.r,
              sig.s,
              HOLDER_DID,
              CHIP_DID,
              TIMESTAMP,
              AA_SIGNATURE
            )
        ).to.be.revertedWith('bad_signature')
      })
    })
  })

  describe('getDelegateCertificate()', () => {
    it('should return empty struct for identity with no certificate', async () => {
      const cert = await didReg.getDelegateCertificate(badBoy.address)
      expect(cert.holderDID).to.equal('')
      expect(cert.chipDID).to.equal('')
      expect(cert.timestamp.toNumber()).to.equal(0)
      expect(cert.aaSignature).to.equal('0x')
    })
  })
})

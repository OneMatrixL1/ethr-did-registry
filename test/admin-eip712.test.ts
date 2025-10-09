// Test file to demonstrate new admin functionality and EIP-712 signatures

import chai, { expect } from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { SignerWithAddress } from '@nomiclabs/hardhat-ethers/signers'
import { EthereumDIDRegistry } from '../typechain-types/EthereumDIDRegistry'

chai.use(chaiAsPromised)

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { ethers } = require('hardhat')

describe('Admin and EIP-712 Functionality', () => {
  let didReg: EthereumDIDRegistry
  let admin: SignerWithAddress
  let identity: SignerWithAddress
  let newOwner: SignerWithAddress
  let attacker: SignerWithAddress

  before(async () => {
    const Registry = await ethers.getContractFactory('EthereumDIDRegistry')
    ;[admin, identity, newOwner, attacker] = await ethers.getSigners()
    didReg = await Registry.connect(admin).deploy()
    await didReg.deployed()
  })

  describe('Admin functionality', () => {
    it('should set deployer as admin', async () => {
      const currentAdmin = await didReg.admin()
      expect(currentAdmin).to.equal(admin.address)
    })

    it('should allow admin to change owner of any identity', async () => {
      // Initially, identity owns itself
      const initialOwner = await didReg.identityOwner(identity.address)
      expect(initialOwner).to.equal(identity.address)

      // Admin changes the owner
      await didReg.connect(admin).adminChangeOwner(identity.address, newOwner.address)

      // Verify the change
      const updatedOwner = await didReg.identityOwner(identity.address)
      expect(updatedOwner).to.equal(newOwner.address)
    })

    it('should not allow non-admin to use admin functions', async () => {
      await expect(didReg.connect(attacker).adminChangeOwner(identity.address, attacker.address)).to.be.revertedWith(
        'only_admin'
      )
    })

    it('should allow admin to change admin', async () => {
      await didReg.connect(admin).changeAdmin(newOwner.address)
      const updatedAdmin = await didReg.admin()
      expect(updatedAdmin).to.equal(newOwner.address)

      // Restore admin for other tests
      await didReg.connect(newOwner).changeAdmin(admin.address)
    })
  })

  describe('EIP-712 functionality', () => {
    let domain: {
      name: string
      version: string
      chainId: number
      verifyingContract: string
    }
    let changeOwnerTypes: {
      ChangeOwner: Array<{
        name: string
        type: string
      }>
    }
    let addDelegateTypes: {
      AddDelegate: Array<{
        name: string
        type: string
      }>
    }
    let revokeDelegateTypes: {
      RevokeDelegate: Array<{
        name: string
        type: string
      }>
    }
    let setAttributeTypes: {
      SetAttribute: Array<{
        name: string
        type: string
      }>
    }
    let revokeAttributeTypes: {
      RevokeAttribute: Array<{
        name: string
        type: string
      }>
    }

    before(async () => {
      const chainId = await didReg.provider.getNetwork().then((n) => n.chainId)

      domain = {
        name: 'EthereumDIDRegistry',
        version: '1',
        chainId,
        verifyingContract: didReg.address,
      }

      changeOwnerTypes = {
        ChangeOwner: [
          { name: 'identity', type: 'address' },
          { name: 'newOwner', type: 'address' },
        ],
      }

      addDelegateTypes = {
        AddDelegate: [
          { name: 'identity', type: 'address' },
          { name: 'delegateType', type: 'bytes32' },
          { name: 'delegate', type: 'address' },
          { name: 'validity', type: 'uint256' },
        ],
      }

      revokeDelegateTypes = {
        RevokeDelegate: [
          { name: 'identity', type: 'address' },
          { name: 'delegateType', type: 'bytes32' },
          { name: 'delegate', type: 'address' },
        ],
      }

      setAttributeTypes = {
        SetAttribute: [
          { name: 'identity', type: 'address' },
          { name: 'name', type: 'bytes32' },
          { name: 'value', type: 'bytes' },
          { name: 'validity', type: 'uint256' },
        ],
      }

      revokeAttributeTypes = {
        RevokeAttribute: [
          { name: 'identity', type: 'address' },
          { name: 'name', type: 'bytes32' },
          { name: 'value', type: 'bytes' },
        ],
      }
    })

    describe('changeOwnerEIP712', () => {
      it('should change owner using EIP-712 signature without nonce', async () => {
        // First, set identity as its own owner
        await didReg.connect(admin).adminChangeOwner(identity.address, identity.address)

        const message = {
          identity: identity.address,
          newOwner: newOwner.address,
        }

        // Sign with identity's private key
        const signature = await identity._signTypedData(domain, changeOwnerTypes, message)
        const { v, r, s } = ethers.utils.splitSignature(signature)

        // Execute the change using EIP-712 signature
        await didReg.connect(attacker).changeOwnerEIP712(identity.address, newOwner.address, v, r, s)

        // Verify the change
        const updatedOwner = await didReg.identityOwner(identity.address)
        expect(updatedOwner).to.equal(newOwner.address)
      })

      it('should reject invalid EIP-712 signature', async () => {
        const message = {
          identity: identity.address,
          newOwner: attacker.address,
        }

        // Sign with wrong key (attacker instead of current owner)
        const signature = await attacker._signTypedData(domain, changeOwnerTypes, message)
        const { v, r, s } = ethers.utils.splitSignature(signature)

        await expect(
          didReg.connect(attacker).changeOwnerEIP712(identity.address, attacker.address, v, r, s)
        ).to.be.revertedWith('bad_eip712_signature')
      })

      it('should allow same signature to be used multiple times (no nonce)', async () => {
        // Reset owner to identity
        await didReg.connect(admin).adminChangeOwner(identity.address, identity.address)

        const message = {
          identity: identity.address,
          newOwner: newOwner.address,
        }

        const signature = await identity._signTypedData(domain, changeOwnerTypes, message)
        const { v, r, s } = ethers.utils.splitSignature(signature)

        // First use - should work
        await didReg.connect(attacker).changeOwnerEIP712(identity.address, newOwner.address, v, r, s)

        // Reset back to identity
        await didReg.connect(admin).adminChangeOwner(identity.address, identity.address)

        // Second use of same signature - should also work (no nonce control)
        await didReg.connect(attacker).changeOwnerEIP712(identity.address, newOwner.address, v, r, s)

        const finalOwner = await didReg.identityOwner(identity.address)
        expect(finalOwner).to.equal(newOwner.address)
      })
    })

    describe('addDelegateEIP712', () => {
      const { formatBytes32String } = ethers.utils
      const delegateType = formatBytes32String('attestor')
      const validity = 86400 // 1 day

      beforeEach(async () => {
        // Ensure identity owns itself
        await didReg.connect(admin).adminChangeOwner(identity.address, identity.address)
      })

      it('should add delegate using EIP-712 signature', async () => {
        const message = {
          identity: identity.address,
          delegateType,
          delegate: newOwner.address,
          validity,
        }

        const signature = await identity._signTypedData(domain, addDelegateTypes, message)
        const { v, r, s } = ethers.utils.splitSignature(signature)

        // Execute add delegate
        await didReg
          .connect(attacker)
          .addDelegateEIP712(identity.address, delegateType, newOwner.address, validity, v, r, s)

        // Verify delegate was added
        const isValid = await didReg.validDelegate(identity.address, delegateType, newOwner.address)
        expect(isValid).to.equal(true)
      })

      it('should reject invalid signature for addDelegate', async () => {
        const message = {
          identity: identity.address,
          delegateType,
          delegate: newOwner.address,
          validity,
        }

        // Sign with wrong key
        const signature = await attacker._signTypedData(domain, addDelegateTypes, message)
        const { v, r, s } = ethers.utils.splitSignature(signature)

        await expect(
          didReg
            .connect(attacker)
            .addDelegateEIP712(identity.address, delegateType, newOwner.address, validity, v, r, s)
        ).to.be.revertedWith('bad_eip712_signature')
      })
    })

    describe('revokeDelegateEIP712', () => {
      const { formatBytes32String } = ethers.utils
      const delegateType = formatBytes32String('attestor')

      beforeEach(async () => {
        // Setup: add a delegate first
        await didReg.connect(admin).adminChangeOwner(identity.address, identity.address)
        await didReg.connect(identity).addDelegate(identity.address, delegateType, newOwner.address, 86400)
      })

      it('should revoke delegate using EIP-712 signature', async () => {
        // Verify delegate exists
        let isValid = await didReg.validDelegate(identity.address, delegateType, newOwner.address)
        expect(isValid).to.equal(true)

        const message = {
          identity: identity.address,
          delegateType,
          delegate: newOwner.address,
        }

        const signature = await identity._signTypedData(domain, revokeDelegateTypes, message)
        const { v, r, s } = ethers.utils.splitSignature(signature)

        // Execute revoke delegate
        await didReg.connect(attacker).revokeDelegateEIP712(identity.address, delegateType, newOwner.address, v, r, s)

        // Verify delegate was revoked
        isValid = await didReg.validDelegate(identity.address, delegateType, newOwner.address)
        expect(isValid).to.equal(false)
      })

      it('should reject invalid signature for revokeDelegate', async () => {
        const message = {
          identity: identity.address,
          delegateType,
          delegate: newOwner.address,
        }

        // Sign with wrong key
        const signature = await attacker._signTypedData(domain, revokeDelegateTypes, message)
        const { v, r, s } = ethers.utils.splitSignature(signature)

        await expect(
          didReg.connect(attacker).revokeDelegateEIP712(identity.address, delegateType, newOwner.address, v, r, s)
        ).to.be.revertedWith('bad_eip712_signature')
      })
    })

    describe('setAttributeEIP712', () => {
      const { formatBytes32String, toUtf8Bytes } = ethers.utils
      const attributeName = formatBytes32String('encryptionKey')
      const attributeValue = toUtf8Bytes('mykey')
      const validity = 86400

      beforeEach(async () => {
        // Ensure identity owns itself
        await didReg.connect(admin).adminChangeOwner(identity.address, identity.address)
      })

      it('should set attribute using EIP-712 signature', async () => {
        const message = {
          identity: identity.address,
          name: attributeName,
          value: attributeValue,
          validity,
        }

        const signature = await identity._signTypedData(domain, setAttributeTypes, message)
        const { v, r, s } = ethers.utils.splitSignature(signature)

        // Execute set attribute
        const tx = await didReg
          .connect(attacker)
          .setAttributeEIP712(identity.address, attributeName, attributeValue, validity, v, r, s)

        // Verify event was emitted
        const receipt = await tx.wait()
        expect(receipt.events).to.have.lengthOf(1)
        expect(receipt.events?.[0]?.event).to.equal('DIDAttributeChanged')
      })

      it('should reject invalid signature for setAttribute', async () => {
        const message = {
          identity: identity.address,
          name: attributeName,
          value: attributeValue,
          validity,
        }

        // Sign with wrong key
        const signature = await attacker._signTypedData(domain, setAttributeTypes, message)
        const { v, r, s } = ethers.utils.splitSignature(signature)

        await expect(
          didReg
            .connect(attacker)
            .setAttributeEIP712(identity.address, attributeName, attributeValue, validity, v, r, s)
        ).to.be.revertedWith('bad_eip712_signature')
      })
    })

    describe('revokeAttributeEIP712', () => {
      const { formatBytes32String, toUtf8Bytes } = ethers.utils
      const attributeName = formatBytes32String('encryptionKey')
      const attributeValue = toUtf8Bytes('mykey')

      beforeEach(async () => {
        // Ensure identity owns itself and set an attribute first
        await didReg.connect(admin).adminChangeOwner(identity.address, identity.address)
        await didReg.connect(identity).setAttribute(identity.address, attributeName, attributeValue, 86400)
      })

      it('should revoke attribute using EIP-712 signature', async () => {
        const message = {
          identity: identity.address,
          name: attributeName,
          value: attributeValue,
        }

        const signature = await identity._signTypedData(domain, revokeAttributeTypes, message)
        const { v, r, s } = ethers.utils.splitSignature(signature)

        // Execute revoke attribute
        const tx = await didReg
          .connect(attacker)
          .revokeAttributeEIP712(identity.address, attributeName, attributeValue, v, r, s)

        // Verify event was emitted with validTo = 0 (revoked)
        const receipt = await tx.wait()
        expect(receipt.events).to.have.lengthOf(1)
        expect(receipt.events?.[0]?.event).to.equal('DIDAttributeChanged')
        expect(receipt.events?.[0]?.args?.validTo).to.equal(0)
      })

      it('should reject invalid signature for revokeAttribute', async () => {
        const message = {
          identity: identity.address,
          name: attributeName,
          value: attributeValue,
        }

        // Sign with wrong key
        const signature = await attacker._signTypedData(domain, revokeAttributeTypes, message)
        const { v, r, s } = ethers.utils.splitSignature(signature)

        await expect(
          didReg.connect(attacker).revokeAttributeEIP712(identity.address, attributeName, attributeValue, v, r, s)
        ).to.be.revertedWith('bad_eip712_signature')
      })
    })
  })
})

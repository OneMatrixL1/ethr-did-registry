// Test file to demonstrate new admin functionality and EIP-712 signatures

import chai, { expect } from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { solidity } from 'ethereum-waffle'
import { Contract } from 'ethers'
import { SignerWithAddress } from '@nomiclabs/hardhat-ethers/signers'
import { EthereumDIDRegistry } from '../typechain-types/EthereumDIDRegistry.sol/EthereumDIDRegistry'

chai.use(chaiAsPromised)
chai.use(solidity)

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { ethers } = require('hardhat')

describe('Admin and EIP-712 Functionality', () => {
  let didReg: EthereumDIDRegistry
  let adminManagement: Contract
  let admin: SignerWithAddress
  let identity: SignerWithAddress
  let newOwner: SignerWithAddress
  let attacker: SignerWithAddress

  before(async () => {
    // Deploy admin management contract
    const AdminManagement = await ethers.getContractFactory('AdminManagement')
    ;[admin, identity, newOwner, attacker] = await ethers.getSigners()
    adminManagement = await AdminManagement.connect(admin).deploy()
    await adminManagement.deployed()

    // Deploy registry with admin management address
    const Registry = await ethers.getContractFactory('EthereumDIDRegistry')
    didReg = await Registry.connect(admin).deploy(adminManagement.address)
    await didReg.deployed()
  })

  describe('Admin functionality', () => {
    it('should set deployer as admin in admin management contract', async () => {
      const isAdmin = await adminManagement.isAdmin(admin.address)
      expect(isAdmin).to.equal(true)
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

    it('should allow admin to manage admin status in admin management contract', async () => {
      // Add newOwner as admin
      await adminManagement.connect(admin).setAdmin(newOwner.address, true)
      const isNewOwnerAdmin = await adminManagement.isAdmin(newOwner.address)
      expect(isNewOwnerAdmin).to.equal(true)

      // Verify newOwner can now use admin functions
      await didReg.connect(newOwner).adminChangeOwner(attacker.address, identity.address)
      const ownerChanged = await didReg.identityOwner(attacker.address)
      expect(ownerChanged).to.equal(identity.address)

      // Remove admin status
      await adminManagement.connect(admin).setAdmin(newOwner.address, false)
      const isStillAdmin = await adminManagement.isAdmin(newOwner.address)
      expect(isStillAdmin).to.equal(false)
    })

    it('should not allow non-owner to manage admin status', async () => {
      await expect(adminManagement.connect(attacker).setAdmin(attacker.address, true)).to.be.reverted
    })

    it('should emit DIDOwnerChanged event when admin changes owner', async () => {
      const testIdentity = identity.address
      const testNewOwner = attacker.address

      // Get initial changed block
      const initialChanged = await didReg.changed(testIdentity)

      // Admin changes owner and expect event
      await expect(didReg.connect(admin).adminChangeOwner(testIdentity, testNewOwner))
        .to.emit(didReg, 'DIDOwnerChanged')
        .withArgs(testIdentity, testNewOwner, initialChanged)

      // Verify the change was recorded
      const newChanged = await didReg.changed(testIdentity)
      expect(newChanged).to.be.gt(initialChanged)

      // Verify the owner mapping was updated
      const actualOwner = await didReg.owners(testIdentity)
      expect(actualOwner).to.equal(testNewOwner)
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
          { name: 'nonce', type: 'uint256' },
        ],
      }

      addDelegateTypes = {
        AddDelegate: [
          { name: 'identity', type: 'address' },
          { name: 'delegateType', type: 'bytes32' },
          { name: 'delegate', type: 'address' },
          { name: 'validTo', type: 'uint256' },
          { name: 'nonce', type: 'uint256' },
        ],
      }

      revokeDelegateTypes = {
        RevokeDelegate: [
          { name: 'identity', type: 'address' },
          { name: 'delegateType', type: 'bytes32' },
          { name: 'delegate', type: 'address' },
          { name: 'nonce', type: 'uint256' },
        ],
      }

      setAttributeTypes = {
        SetAttribute: [
          { name: 'identity', type: 'address' },
          { name: 'name', type: 'bytes32' },
          { name: 'value', type: 'bytes' },
          { name: 'validTo', type: 'uint256' },
          { name: 'nonce', type: 'uint256' },
        ],
      }

      revokeAttributeTypes = {
        RevokeAttribute: [
          { name: 'identity', type: 'address' },
          { name: 'name', type: 'bytes32' },
          { name: 'value', type: 'bytes' },
          { name: 'nonce', type: 'uint256' },
        ],
      }
    })

    describe('changeOwnerEIP712', () => {
      it('should change owner using EIP-712 signature with nonce', async () => {
        // First, set identity as its own owner
        await didReg.connect(admin).adminChangeOwner(identity.address, identity.address)

        const currentNonce = await didReg.eip712Nonces(identity.address)
        const message = {
          identity: identity.address,
          newOwner: newOwner.address,
          nonce: currentNonce,
        }

        // Sign with identity's private key
        const signature = await identity._signTypedData(domain, changeOwnerTypes, message)
        const { v, r, s } = ethers.utils.splitSignature(signature)

        // Execute the change using EIP-712 signature
        await didReg.connect(attacker).changeOwnerEIP712(identity.address, newOwner.address, v, r, s)

        // Verify the change
        const updatedOwner = await didReg.identityOwner(identity.address)
        expect(updatedOwner).to.equal(newOwner.address)
        
        // Verify nonce was incremented
        const newNonce = await didReg.eip712Nonces(identity.address)
        expect(newNonce).to.equal(currentNonce.add(1))
      })

      it('should reject invalid EIP-712 signature', async () => {
        const currentNonce = await didReg.eip712Nonces(newOwner.address)
        const message = {
          identity: identity.address,
          newOwner: attacker.address,
          nonce: currentNonce,
        }

        // Sign with wrong key (attacker instead of current owner)
        const signature = await attacker._signTypedData(domain, changeOwnerTypes, message)
        const { v, r, s } = ethers.utils.splitSignature(signature)

        await expect(
          didReg.connect(attacker).changeOwnerEIP712(identity.address, attacker.address, v, r, s)
        ).to.be.revertedWith('bad_eip712_signature')
      })

      it('should prevent signature replay with nonce', async () => {
        // Reset owner to identity
        await didReg.connect(admin).adminChangeOwner(identity.address, identity.address)

        const currentNonce = await didReg.eip712Nonces(identity.address)
        const message = {
          identity: identity.address,
          newOwner: newOwner.address,
          nonce: currentNonce,
        }

        const signature = await identity._signTypedData(domain, changeOwnerTypes, message)
        const { v, r, s } = ethers.utils.splitSignature(signature)

        // First use - should work
        await didReg.connect(attacker).changeOwnerEIP712(identity.address, newOwner.address, v, r, s)

        // Reset back to identity
        await didReg.connect(admin).adminChangeOwner(identity.address, identity.address)

        // Second use of same signature - should fail because nonce has been consumed
        await expect(
          didReg.connect(attacker).changeOwnerEIP712(identity.address, newOwner.address, v, r, s)
        ).to.be.revertedWith('bad_eip712_signature')
      })

      it('should reject zero address as new owner', async () => {
        // Reset owner to identity
        await didReg.connect(admin).adminChangeOwner(identity.address, identity.address)

        const currentNonce = await didReg.eip712Nonces(identity.address)
        const message = {
          identity: identity.address,
          newOwner: ethers.constants.AddressZero,
          nonce: currentNonce,
        }

        const signature = await identity._signTypedData(domain, changeOwnerTypes, message)
        const { v, r, s } = ethers.utils.splitSignature(signature)

        await expect(
          didReg.connect(attacker).changeOwnerEIP712(identity.address, ethers.constants.AddressZero, v, r, s)
        ).to.be.revertedWith('zero_owner')
      })
    })

    describe('addDelegateEIP712', () => {
      const { formatBytes32String } = ethers.utils
      const delegateType = formatBytes32String('attestor')
      let validTo: number

      beforeEach(async () => {
        // Ensure identity owns itself
        await didReg.connect(admin).adminChangeOwner(identity.address, identity.address)
        // Set validTo to 1 day from now
        const currentBlock = await ethers.provider.getBlock('latest')
        validTo = currentBlock.timestamp + 86400 // 1 day
      })

      it('should add delegate using EIP-712 signature', async () => {
        const currentNonce = await didReg.eip712Nonces(identity.address)
        const message = {
          identity: identity.address,
          delegateType,
          delegate: newOwner.address,
          validTo,
          nonce: currentNonce,
        }

        const signature = await identity._signTypedData(domain, addDelegateTypes, message)
        const { v, r, s } = ethers.utils.splitSignature(signature)

        // Execute add delegate
        await didReg
          .connect(attacker)
          .addDelegateEIP712(identity.address, delegateType, newOwner.address, validTo, v, r, s)

        // Verify delegate was added
        const isValid = await didReg.validDelegate(identity.address, delegateType, newOwner.address)
        expect(isValid).to.equal(true)
        
        // Verify nonce was incremented
        const newNonce = await didReg.eip712Nonces(identity.address)
        expect(newNonce).to.equal(currentNonce.add(1))
      })

      it('should reject invalid signature for addDelegate', async () => {
        const currentNonce = await didReg.eip712Nonces(identity.address)
        const message = {
          identity: identity.address,
          delegateType,
          delegate: newOwner.address,
          validTo,
          nonce: currentNonce,
        }

        // Sign with wrong key
        const signature = await attacker._signTypedData(domain, addDelegateTypes, message)
        const { v, r, s } = ethers.utils.splitSignature(signature)

        await expect(
          didReg.connect(attacker).addDelegateEIP712(identity.address, delegateType, newOwner.address, validTo, v, r, s)
        ).to.be.revertedWith('bad_eip712_signature')
      })

      it('should reject expired validTo timestamp', async () => {
        // Set validTo to past timestamp
        const currentBlock = await ethers.provider.getBlock('latest')
        const expiredValidTo = currentBlock.timestamp - 3600 // 1 hour ago

        const currentNonce = await didReg.eip712Nonces(identity.address)
        const message = {
          identity: identity.address,
          delegateType,
          delegate: newOwner.address,
          validTo: expiredValidTo,
          nonce: currentNonce,
        }

        const signature = await identity._signTypedData(domain, addDelegateTypes, message)
        const { v, r, s } = ethers.utils.splitSignature(signature)

        await expect(
          didReg
            .connect(attacker)
            .addDelegateEIP712(identity.address, delegateType, newOwner.address, expiredValidTo, v, r, s)
        ).to.be.revertedWith('invalid_expiry')
      })

      it('should prevent signature replay attacks with nonce', async () => {
        const currentNonce = await didReg.eip712Nonces(identity.address)
        const message = {
          identity: identity.address,
          delegateType,
          delegate: newOwner.address,
          validTo,
          nonce: currentNonce,
        }

        const signature = await identity._signTypedData(domain, addDelegateTypes, message)
        const { v, r, s } = ethers.utils.splitSignature(signature)

        // First call should succeed
        await didReg
          .connect(attacker)
          .addDelegateEIP712(identity.address, delegateType, newOwner.address, validTo, v, r, s)

        // Wait for time to pass (simulate time advancement)
        await ethers.provider.send('evm_increaseTime', [3600]) // 1 hour
        await ethers.provider.send('evm_mine', [])

        // Try to replay the same signature - should fail because nonce has been consumed
        await expect(
          didReg
            .connect(attacker)
            .addDelegateEIP712(identity.address, delegateType, newOwner.address, validTo, v, r, s)
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

        const currentNonce = await didReg.eip712Nonces(identity.address)

        const message = {
          identity: identity.address,
          delegateType,
          delegate: newOwner.address,
          nonce: currentNonce,
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
        const currentNonce = await didReg.eip712Nonces(identity.address)

        const message = {
          identity: identity.address,
          delegateType,
          delegate: newOwner.address,
          nonce: currentNonce,
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
      let validTo: number

      beforeEach(async () => {
        // Ensure identity owns itself
        await didReg.connect(admin).adminChangeOwner(identity.address, identity.address)
        // Set validTo to 1 day from now
        const currentBlock = await ethers.provider.getBlock('latest')
        validTo = currentBlock.timestamp + 86400 // 1 day
      })

      it('should set attribute using EIP-712 signature', async () => {
        const currentNonce = await didReg.eip712Nonces(identity.address)

        const message = {
          identity: identity.address,
          name: attributeName,
          value: attributeValue,
          validTo,
          nonce: currentNonce,
        }

        const signature = await identity._signTypedData(domain, setAttributeTypes, message)
        const { v, r, s } = ethers.utils.splitSignature(signature)

        // Execute set attribute
        const tx = await didReg
          .connect(attacker)
          .setAttributeEIP712(identity.address, attributeName, attributeValue, validTo, v, r, s)

        // Verify event was emitted
        const receipt = await tx.wait()
        expect(receipt.events).to.have.lengthOf(1)
        expect(receipt.events?.[0]?.event).to.equal('DIDAttributeChanged')
      })

      it('should reject invalid signature for setAttribute', async () => {
        const currentNonce = await didReg.eip712Nonces(identity.address)

        const message = {
          identity: identity.address,
          name: attributeName,
          value: attributeValue,
          validTo,
          nonce: currentNonce,
        }

        // Sign with wrong key
        const signature = await attacker._signTypedData(domain, setAttributeTypes, message)
        const { v, r, s } = ethers.utils.splitSignature(signature)

        await expect(
          didReg.connect(attacker).setAttributeEIP712(identity.address, attributeName, attributeValue, validTo, v, r, s)
        ).to.be.revertedWith('bad_eip712_signature')
      })

      it('should reject expired validTo timestamp for setAttribute', async () => {
        // Set validTo to past timestamp
        const currentBlock = await ethers.provider.getBlock('latest')
        const expiredValidTo = currentBlock.timestamp - 3600 // 1 hour ago

        const currentNonce = await didReg.eip712Nonces(identity.address)

        const message = {
          identity: identity.address,
          name: attributeName,
          value: attributeValue,
          validTo: expiredValidTo,
          nonce: currentNonce,
        }

        const signature = await identity._signTypedData(domain, setAttributeTypes, message)
        const { v, r, s } = ethers.utils.splitSignature(signature)

        await expect(
          didReg
            .connect(attacker)
            .setAttributeEIP712(identity.address, attributeName, attributeValue, expiredValidTo, v, r, s)
        ).to.be.revertedWith('invalid_expiry')
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
        const currentNonce = await didReg.eip712Nonces(identity.address)

        const message = {
          identity: identity.address,
          name: attributeName,
          value: attributeValue,
          nonce: currentNonce,
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
        const currentNonce = await didReg.eip712Nonces(identity.address)

        const message = {
          identity: identity.address,
          name: attributeName,
          value: attributeValue,
          nonce: currentNonce,
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

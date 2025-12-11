// Test file to demonstrate new admin functionality and EIP-712 signatures

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
    })

    describe('changeOwnerEIP712', () => {
      it('should change owner using EIP-712 signature', async () => {
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

      it('should allow signature reuse (no nonce protection)', async () => {
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

        // Second use of same signature - should work (signature can be reused)
        await didReg.connect(attacker).changeOwnerEIP712(identity.address, newOwner.address, v, r, s)
        
        // Verify the change worked
        const updatedOwner = await didReg.identityOwner(identity.address)
        expect(updatedOwner).to.equal(newOwner.address)
      })

      it('should reject zero address as new owner', async () => {
        // Reset owner to identity
        await didReg.connect(admin).adminChangeOwner(identity.address, identity.address)

        const message = {
          identity: identity.address,
          newOwner: ethers.constants.AddressZero,
        }

        const signature = await identity._signTypedData(domain, changeOwnerTypes, message)
        const { v, r, s } = ethers.utils.splitSignature(signature)

        await expect(
          didReg.connect(attacker).changeOwnerEIP712(identity.address, ethers.constants.AddressZero, v, r, s)
        ).to.be.revertedWith('zero_owner')
      })
    })
  })
})

import * as dotenv from 'dotenv'

import { HardhatUserConfig, task } from 'hardhat/config'
import '@nomiclabs/hardhat-etherscan'
import '@nomiclabs/hardhat-waffle'
import '@typechain/hardhat'
import 'hardhat-gas-reporter'
import 'solidity-coverage'

dotenv.config()

// This is a sample Hardhat task. To learn how to create your own go to
// https://hardhat.org/guides/create-task.html
task('accounts', 'Prints the list of accounts', async (taskArgs, hre) => {
  const accounts = await hre.ethers.getSigners()

  for (const account of accounts) {
    console.log(account.address)
  }
})

// You need to export an object to set up your config
// Go to https://hardhat.org/config/ to learn more

const config: HardhatUserConfig = {
  solidity: {
    compilers: [
      {
        version: '0.8.28',
        settings: {
          evmVersion: 'cancun',
          optimizer: {
            enabled: true,
            runs: 1000,
          },
          viaIR: true,
        },
      },
    ],
  },
  paths: {
    sources: './contracts',
    tests: './test',
    cache: './cache',
    artifacts: './artifacts',
  },
  networks: {
    hardhat: {
      forking: process.env.FORK_NETWORK
        ? {
          url: process.env.FORK_NETWORK,
          enabled: true,
        }
        : undefined,
      allowUnlimitedContractSize: true,
    },
    ropsten: {
      url: process.env.ROPSTEN_URL || '',
      accounts: process.env.PRIVATE_KEY !== undefined ? [process.env.PRIVATE_KEY] : [],
    },
    onematrix: {
      url: 'https://rpc.vietcha.in',
      accounts: process.env.PRIVATE_KEY !== undefined ? [process.env.PRIVATE_KEY] : [],
    },
    vnidchain: {
      url: 'https://vnidchain-rpc.vbsn.vn',
      accounts: process.env.PRIVATE_KEY !== undefined ? [process.env.PRIVATE_KEY] : [],
    },
  },
  gasReporter: {
    enabled: process.env.REPORT_GAS !== undefined,
    currency: 'USD',
  },
  etherscan: {
    apiKey: {
      onematrix: 'abc', // Fallback to 'abc' for Blockscout
      vnidchain: 'empty',
    },
    customChains: [
      {
        network: 'onematrix',
        chainId: 84005,
        urls: {
          apiURL: 'https://explorer.vietcha.in/api',
          browserURL: 'https://explorer.vietcha.in',
        },
      },
      {
        network: 'vnidchain',
        chainId: 54000,
        urls: {
          apiURL: 'https://vnidchain-explorer.vbsn.vn/api/v1',
          browserURL: 'https://vnidchain-explorer.vbsn.vn',
        },
      },
    ],
  },
}

export default config

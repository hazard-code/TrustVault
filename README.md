# TrustVault

A decentralized, multi-signature smart vault built on Stacks blockchain for securely storing and managing digital assets with programmable conditions for withdrawals.

## Overview

TrustVault is a secure smart contract platform that enables users to store both STX tokens and NFTs in a vault protected by multi-signature authorization and conditional withdrawal mechanisms. The platform provides robust security features and flexible asset management capabilities.

## Features

### Core Functionality
- **Multi-Signature Support**: Requires multiple authorized signatures for withdrawal approval
- **Conditional Withdrawals**: Assets can only be withdrawn based on predefined conditions (time-based)
- **Dual Asset Support**: Handles both STX tokens and NFT assets
- **Secure Storage**: Assets are held in a secure contract with strict access controls
- **Programmable Logic**: Customizable conditions for asset withdrawals

### Security Features
- Input validation for all operations
- Overflow protection for financial operations
- Principal address validation
- Request ID verification
- Time-based condition checks
- Maximum amount limits
- NFT ownership verification
- Multi-signature threshold enforcement

## Technical Architecture

### Smart Contract Components

1. **Storage**
   - `vault-balances`: Tracks STX balances for each user
   - `nft-holdings`: Records NFT ownership information
   - `withdrawal-requests`: Manages withdrawal requests and their states
   - `authorized-signers`: Stores approved signers for multi-sig operations

2. **Core Functions**
   - `initialize`: Sets up the vault with initial signers and threshold
   - `deposit-stx`: Deposits STX tokens into the vault
   - `deposit-nft`: Deposits NFTs into the vault
   - `create-withdrawal-request`: Initiates a withdrawal request
   - `sign-withdrawal-request`: Adds a signature to a withdrawal request
   - `execute-withdrawal`: Processes approved withdrawals
   - `transfer-single-nft`: Handles individual NFT transfers

### Error Codes

| Code | Description |
|------|-------------|
| u100 | Not authorized |
| u101 | Invalid signature |
| u102 | Condition not met |
| u103 | Already initialized |
| u104 | Not initialized |
| u105 | Insufficient balance |
| u106 | NFT transfer failed |
| u107 | Invalid NFT |
| u108 | Invalid amount |
| u109 | Invalid time |
| u110 | Invalid principal |
| u111 | Invalid request ID |

## Usage Guide

### Setting Up the Vault

1. Deploy the contract
2. Initialize with authorized signers and signature threshold:
```clarity
(contract-call? .trustvault initialize (list tx-sender addr1 addr2) u2)
```

### Depositing Assets

For STX:
```clarity
(contract-call? .trustvault deposit-stx u1000)
```

For NFTs:
```clarity
(contract-call? .trustvault deposit-nft .my-nft u1)
```

### Creating Withdrawal Requests

```clarity
(contract-call? .trustvault create-withdrawal-request 
    u500 
    (list {asset-contract: .my-nft, token-id: u1}) 
    beneficiary-address 
    block-height)
```

### Signing and Executing Withdrawals

To sign:
```clarity
(contract-call? .trustvault sign-withdrawal-request u1)
```

To execute:
```clarity
(contract-call? .trustvault execute-withdrawal u1)
```

## Security Considerations

1. **Multi-Signature Security**
   - Multiple signatures required for withdrawals
   - Configurable signature threshold
   - Signature verification before execution

2. **Input Validation**
   - Amount limits enforcement
   - Time-based condition validation
   - Principal address verification
   - Request ID validation

3. **Asset Protection**
   - NFT ownership verification
   - Balance checks before withdrawals
   - Contract state validation
   - Execution state tracking

## Development

### Prerequisites
- Clarinet
- Stacks CLI tools
- Node.js (for testing environment)

### Testing
1. Clone the repository
2. Install dependencies
3. Run Clarinet tests:
```bash
clarinet test
```

### Deployment
1. Update deployment configuration
2. Deploy using Clarinet:
```bash
clarinet deploy
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit changes
4. Push to the branch
5. Create a Pull Request

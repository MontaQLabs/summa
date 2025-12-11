#!/bin/bash
# ============================================================================
# Summa Confidential Asset Deployment Script
# ============================================================================
#
# This script deploys the Confidential Asset contract to Polkadot Asset Hub.
#
# USAGE:
#   ./deploy.sh [options]
#
# OPTIONS:
#   --network <name>    Network to deploy to (default: testnet)
#   --contract <path>   Path to contract binary (default: confidential-asset.polkavm)
#   --help              Show this help message
#
# ENVIRONMENT VARIABLES:
#   ETH_RPC_URL         RPC endpoint (overrides --network)
#   PRIVATE_KEY         Deployer's private key (REQUIRED - never commit this!)
#
# SECURITY:
#   - Never commit private keys to version control
#   - Use environment variables or secure key management
#   - Consider using hardware wallets for mainnet deployments
#
# ============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default configuration
NETWORK="testnet"
CONTRACT_FILE="confidential-asset.polkavm"

# Network RPC endpoints
declare -A RPC_ENDPOINTS=(
    ["testnet"]="https://testnet-passet-hub-eth-rpc.polkadot.io"
    ["westend"]="https://westend-asset-hub-eth-rpc.polkadot.io"
    ["localhost"]="http://localhost:8545"
)

# Print header
print_header() {
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║           🔐 Summa - Confidential Asset Deployer             ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Print help
print_help() {
    echo "Usage: ./deploy.sh [options]"
    echo ""
    echo "Options:"
    echo "  --network <name>    Network to deploy to (testnet, westend, localhost)"
    echo "  --contract <path>   Path to contract binary"
    echo "  --help              Show this help message"
    echo ""
    echo "Environment Variables:"
    echo "  ETH_RPC_URL         Custom RPC endpoint"
    echo "  PRIVATE_KEY         Deployer's private key (REQUIRED)"
    echo ""
    echo "Example:"
    echo "  export PRIVATE_KEY=0x..."
    echo "  ./deploy.sh --network testnet"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --network)
            NETWORK="$2"
            shift 2
            ;;
        --contract)
            CONTRACT_FILE="$2"
            shift 2
            ;;
        --help)
            print_help
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            print_help
            exit 1
            ;;
    esac
done

print_header

# Validate private key
if [ -z "$PRIVATE_KEY" ]; then
    echo -e "${RED}❌ ERROR: PRIVATE_KEY environment variable not set!${NC}"
    echo ""
    echo "Please set your private key:"
    echo "  export PRIVATE_KEY=0x<your_64_char_hex_key>"
    echo ""
    echo -e "${YELLOW}⚠️  Security Warning:${NC}"
    echo "  - Never commit private keys to version control"
    echo "  - Consider using a hardware wallet for mainnet"
    echo "  - Use a dedicated deployment account"
    exit 1
fi

# Set RPC URL
if [ -z "$ETH_RPC_URL" ]; then
    if [ -z "${RPC_ENDPOINTS[$NETWORK]}" ]; then
        echo -e "${RED}❌ Unknown network: $NETWORK${NC}"
        echo "Available networks: testnet, westend, localhost"
        exit 1
    fi
    export ETH_RPC_URL="${RPC_ENDPOINTS[$NETWORK]}"
fi

echo -e "${BLUE}Configuration:${NC}"
echo "  Network:  $NETWORK"
echo "  RPC URL:  $ETH_RPC_URL"
echo "  Contract: $CONTRACT_FILE"
echo ""

# Check if contract file exists
if [ ! -f "$CONTRACT_FILE" ]; then
    echo -e "${RED}❌ Contract file not found: $CONTRACT_FILE${NC}"
    echo ""
    echo "Build the contract first:"
    echo "  make all"
    exit 1
fi

# Get deployer address from private key
DEPLOYER_ADDRESS=$(cast wallet address "$PRIVATE_KEY" 2>/dev/null)
if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Invalid private key format${NC}"
    exit 1
fi

echo -e "${YELLOW}Deployer Address:${NC}"
echo "  $DEPLOYER_ADDRESS"
echo ""

# Check balance
echo -e "${YELLOW}Checking balance...${NC}"
BALANCE=$(cast balance "$DEPLOYER_ADDRESS" 2>/dev/null)
if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Failed to get balance (check RPC connection)${NC}"
    exit 1
fi

echo "  Balance: $BALANCE wei"

if [ "$BALANCE" = "0" ]; then
    echo -e "${RED}❌ No balance! Get tokens from:${NC}"
    echo "   https://contracts.polkadot.io/connect-to-asset-hub"
    echo "   Address: $DEPLOYER_ADDRESS"
    exit 1
fi

echo -e "${GREEN}✓ Balance OK${NC}"
echo ""

# Estimate gas
echo -e "${YELLOW}Estimating deployment cost...${NC}"
CONTRACT_HEX=$(xxd -p -c 99999 "$CONTRACT_FILE")
CONTRACT_SIZE=$(echo -n "$CONTRACT_HEX" | wc -c | tr -d ' ')
CONTRACT_SIZE=$((CONTRACT_SIZE / 2))
echo "  Contract size: $CONTRACT_SIZE bytes"

# Deploy contract
echo ""
echo -e "${YELLOW}Deploying contract...${NC}"
echo "  This may take a few moments..."

RESULT=$(cast send --private-key "$PRIVATE_KEY" --create "0x$CONTRACT_HEX" --json 2>&1)

if echo "$RESULT" | jq -e '.contractAddress' > /dev/null 2>&1; then
    CONTRACT_ADDRESS=$(echo "$RESULT" | jq -r '.contractAddress')
    TX_HASH=$(echo "$RESULT" | jq -r '.transactionHash')
    GAS_USED=$(echo "$RESULT" | jq -r '.gasUsed')
    BLOCK=$(echo "$RESULT" | jq -r '.blockNumber')

    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║              ✅ CONTRACT DEPLOYED SUCCESSFULLY!                  ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}Contract Details:${NC}"
    echo "  Address:     $CONTRACT_ADDRESS"
    echo "  TX Hash:     $TX_HASH"
    echo "  Block:       $BLOCK"
    echo "  Gas Used:    $GAS_USED"
    echo ""
    echo -e "${BLUE}Contract Owner:${NC}"
    echo "  $DEPLOYER_ADDRESS"
    echo ""
    echo -e "${YELLOW}Quick Commands:${NC}"
    echo ""
    echo "  # Generate a keypair"
    echo "  cargo run -p gen-ciphertext keygen"
    echo ""
    echo "  # Register your public key"
    echo "  cast send $CONTRACT_ADDRESS '0x1234abcd<your_32_byte_pubkey>' --private-key \$PRIVATE_KEY"
    echo ""
    echo "  # Mint tokens (owner only)"
    echo "  cast send $CONTRACT_ADDRESS '0xaabb1122<20_byte_address><64_byte_ciphertext>' --private-key \$PRIVATE_KEY"
    echo ""
    echo "  # Get encrypted balance"
    echo "  cast call $CONTRACT_ADDRESS '0xdef45678<20_byte_address>'"
    echo ""
    echo "  # Check contract owner"
    echo "  cast call $CONTRACT_ADDRESS '0x8da5cb5b'"
    echo ""

    # Save deployment info
    DEPLOY_FILE="deployment-$(date +%Y%m%d-%H%M%S).json"
    cat > "$DEPLOY_FILE" << EOF
{
    "network": "$NETWORK",
    "rpc_url": "$ETH_RPC_URL",
    "contract_address": "$CONTRACT_ADDRESS",
    "deployer": "$DEPLOYER_ADDRESS",
    "tx_hash": "$TX_HASH",
    "block_number": "$BLOCK",
    "gas_used": "$GAS_USED",
    "deployed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "contract_size_bytes": $CONTRACT_SIZE
}
EOF
    echo -e "${GREEN}Deployment info saved to: $DEPLOY_FILE${NC}"

else
    echo ""
    echo -e "${RED}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║                    ❌ DEPLOYMENT FAILED                          ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Error details:"
    echo "$RESULT" | jq '.' 2>/dev/null || echo "$RESULT"
    echo ""
    echo "Possible causes:"
    echo "  - Insufficient balance for gas"
    echo "  - Contract too large for PVM"
    echo "  - Network congestion"
    echo "  - Invalid contract bytecode"
    exit 1
fi

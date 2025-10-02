# 🎬 TSS-ECDSA Wallet Demo Guide

This guide provides step-by-step instructions to quickly demo the Threshold Signature Scheme (TSS) wallet application.

## 🚀 Quick Start Demo

### Prerequisites
- **Rust installed** (get it at [rustup.rs](https://rustup.rs/))
- **Web browser** (Chrome only)

### Step 1: Clone and Build

```bash
# Clone the repository
git clone https://github.com/emmorais/waas.git
cd waas

# Build the application
cargo build --release
```

### Step 2: Start the Server

```bash
# Run the server
cargo run
```

**Expected Output:**
```
🎯 TSS-ECDSA Wallet-as-a-Service Server
📍 Listening on https://localhost:8443
🔐 TLS encryption enabled
🔑 Authentication: admin/admin123
📊 Dashboard: https://localhost:8443/dashboard

✨ Ready to process TSS operations!
```

### Step 3: Access the Web Interface

1. **Open your browser** and navigate to:
   ```
   https://localhost:8443/
   ```

2. **Accept the security warning**
   - Click "Advanced" or "Show Details"
   - Click "Proceed to localhost (unsafe)" or "Accept Risk and Continue"
   - *This is expected behavior due to self-signed certificates*

3. **Login with demo credentials:**
   - **Username:** `admin`
   - **Password:** `admin123`

## 🎭 Demo Scenarios

### Scenario 1: Basic TSS Key Generation

**What you're demonstrating:** Distributed key generation without single points of failure

1. **Click "Generate Key Pair"**
   - Shows distributed key generation protocol in action
   - Generates threshold signature keys (3-of-3 scheme)
   - Creates root key for HD wallet functionality

2. **Observe the output:**
   ```
   🔐 TSS Key Generation Result:
   ✅ Status: TSS Key generation completed successfully
   🔑 Public Key: 04a1b2c3d4e5f6...
   👥 Participants: 3 workers
   ```

**Key Points to Highlight:**
- No single participant holds the complete private key
- Requires cooperation from multiple parties to sign
- Public key is standard ECDSA (compatible with existing systems)

### Scenario 2: Hierarchical Deterministic (HD) Key Derivation

**What you're demonstrating:** Bitcoin-style HD wallet functionality with TSS security

1. **Click "List Keys"** to see current keys

2. **Derive a child key:**
   - Enter `1` in "Child Index" field
   - Enter `"Demo Key"` in "Key Label" field
   - Click "Derive Child Key"

3. **Observe the result:**
   ```
   🌱 Child Key Derived Successfully:
   🔢 Child Index: 1
   🏷️ Label: Demo Key
   🔑 Public Key: 04d1e2f3a4b5c6...
   ```

4. **Verify in key list:**
   - Click "List Keys" again
   - See both Root Key (Index 0) and Child Key 1 (Demo Key)

**Key Points to Highlight:**
- Deterministic key generation (same input = same key)
- Hierarchical structure like traditional HD wallets
- Each child key maintains TSS security properties
# 🎬 TSS-ECDSA Wallet Demo Guide

This guide provides step-by-step instructions to quickly demo the Threshold Signature Scheme (TSS) wallet application.

## 🚀 Quick Start Demo

### Prerequisites
- **Rust installed** (get it at [rustup.rs](https://rustup.rs/))
- **Web browser** (Chrome, Firefox, Safari, or Edge)

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
   - Generates threshold signature keys (2-of-3 scheme)
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

### Scenario 3: Threshold Signature Creation and Verification

**What you're demonstrating:** Multi-party signature generation and cryptographic verification

1. **Create a signature:**
   - Type `Hello TSS Demo!` in the message field
   - Ensure "Root Key (Index 0)" is selected
   - Click "Create Signature"

2. **Observe signature creation:**
   ```
   ✍️ TSS Message Signing Result:
   ✅ Status: Message signed successfully
   📨 Message Signed: "Hello TSS Demo!"
   🔑 Key Used: Root Key (Index 0)
   🔏 Signature: 304502210095a1b2c3...
   ```

3. **Verify the signature:**
   - Keep the same message in the field
   - Click "Verify Signature"

4. **Observe verification result:**
   ```
   🔍 TSS Signature Verification Result:
   ✅ Verification Result: VALID
   📨 Message: "Hello TSS Demo!"
   🛡️ This confirms message integrity and authentic origin!
   ```

**Key Points to Highlight:**
- Signature created through multi-party computation
- Standard ECDSA signature (works with any ECDSA system)
- Cryptographic proof of authenticity and integrity

### Scenario 4: Child Key Signing

**What you're demonstrating:** Using derived keys for signatures while maintaining security

1. **Select a child key:**
   - Use the dropdown to select "Child Key 1 (Demo Key)"

2. **Sign with child key:**
   - Type `Child key signature test`
   - Click "Create Signature"

3. **Verify child key signature:**
   - Click "Verify Signature"
   - Observe successful verification with child key

**Key Points to Highlight:**
- Each derived key can sign independently
- Child keys inherit TSS security properties
- Enables account/purpose separation like traditional HD wallets

### Scenario 5: Key Management and Security

**What you're demonstrating:** Secure key lifecycle management

1. **Delete a child key:**
   - Select "Child Key 1 (Demo Key)" from dropdown
   - Click "Delete Child Key"
   - Confirm deletion when prompted

2. **Verify deletion:**
   - Click "List Keys"
   - Observe that only Root Key remains

3. **Complete key deletion:**
   - Click "Delete Key Material"
   - Read the warning carefully
   - Confirm deletion to remove all cryptographic material

4. **Verify complete cleanup:**
   - Try clicking "List Keys" - should show no keys
   - Try signing - should fail with "No root key found"

**Key Points to Highlight:**
- Granular key management (delete specific child keys)
- Secure deletion of all cryptographic material
- System returns to clean state for fresh demo

## 🎯 Key Demo Points to Emphasize

### Security Benefits
- **No Single Point of Failure:** Private key distributed across multiple parties
- **Threshold Security:** Requires cooperation (2-of-3) to create signatures
- **Standard Compatibility:** Produces normal ECDSA signatures

### Practical Applications
- **Cryptocurrency Custody:** Secure wallet for institutions and individuals
- **Multi-Signature Scenarios:** Corporate treasury, escrow services
- **Compliance Requirements:** Regulatory frameworks requiring distributed control

### Technical Innovation
- **Real TSS Implementation:** Not simulated - actual threshold cryptography
- **HD Wallet Integration:** Combines TSS with hierarchical deterministic keys
- **Production Ready Architecture:** HTTPS, authentication, persistent storage

## 🔧 Demo Tips

### For Technical Audiences
- Show the **browser developer tools** to inspect API calls
- Explain the **cryptographic protocols** happening behind each operation
- Highlight the **file system storage** (keygen_result.json, etc.)

### For Business Audiences
- Focus on **security benefits** and risk reduction
- Emphasize **regulatory compliance** advantages
- Show **user experience** similar to traditional wallets

### For Quick Demos (5 minutes)
1. Generate keys (1 min)
2. Sign and verify message (2 min)
3. Show HD key derivation (2 min)

### For Detailed Demos (15 minutes)
1. All quick demo steps
2. Child key signing
3. Key management operations
4. Explain security architecture
5. Show command-line API access

## 🛠️ Troubleshooting Demo Issues

**Server won't start:**
```bash
# Check if port is in use
lsof -i :8443

# Kill conflicting process if needed
kill -9 <PID>

# Restart server
cargo run
```

**Browser certificate warnings:**
- This is expected with self-signed certificates
- Always click "Proceed to localhost (unsafe)"
- Explain this is development-only behavior

**Authentication fails:**
- Verify credentials: `admin` / `admin123`
- Check for typos (case-sensitive)
- Refresh page if needed

**"No root key found" errors:**
- Generate keys first with "Generate Key Pair"
- Check that server storage files exist
- Restart demo from clean state if needed

## 🎊 Demo Conclusion

After completing the demo scenarios, audiences will understand:

- **How TSS eliminates single points of failure** in cryptographic systems
- **Practical applications** for secure cryptocurrency custody
- **Technical feasibility** of threshold signature schemes
- **User experience** comparable to traditional wallet software
- **Security advantages** over conventional key management

The demo showcases a **production-ready foundation** for threshold signature applications while highlighting **clear next steps** for enterprise deployment.

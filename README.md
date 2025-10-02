# 🔐 Wallet as a Service (WaaS)

A **Threshold Signature Scheme (TSS) based wallet service** built with Rust, providing secure multi-party computation for cryptocurrency operations. This service implements distributed key generation, hierarchical deterministic (HD) keys, and threshold signatures without any single point of failure.

## 🚀 Features

### Core TSS Operations
- **🔑 Distributed Key Generation**: Generate cryptographic keys across multiple parties using threshold cryptography
- **✍️ Threshold Signatures**: Create signatures that require cooperation from multiple parties
- **🔍 Signature Verification**: Verify signatures against public keys
- **🗑️ Secure Key Deletion**: Safely remove all cryptographic material from storage

### Hierarchical Deterministic (HD) Wallet
- **🌱 Child Key Derivation**: Generate deterministic child keys from a master key

### Security & Infrastructure
- **🛡️ HTTPS/TLS**: All communications encrypted with self-signed certificates
- **🔐 Basic Authentication**: Simple username/password protection (admin/admin123)
- **💾 Persistent Storage**: Keys and configurations saved to local files
- **🌐 Web UI**: Modern, responsive interface for all operations

## 🏗️ Architecture

### Backend Components
- **`src/main.rs`**: HTTPS server setup with TLS and route configuration
- **`src/keygen.rs`**: TSS key generation protocol implementation
- **`src/sign.rs`**: Message signing and signature verification
- **`src/hd_keys.rs`**: Hierarchical deterministic key derivation
- **`src/delete_key.rs`**: Secure key material deletion
- **`src/dashboard.rs`**: API endpoints for web interface

### Cryptographic Libraries
- **`tss-ecdsa`**: Core threshold signature implementation
- **`k256`**: Elliptic curve operations (secp256k1)
- **`hmac/sha2`**: Key derivation functions for HD wallets
- **`ecdsa`**: ECDSA signature verification

### Storage Format
- **`keygen_result.json`**: Complete TSS key generation outputs (all private shares)
- **`keygen_configs.bin`**: Participant configurations (binary serialized)
- **`keygen_completed.marker`**: Completion marker file
- **`hd_keys.json`**: Hierarchical deterministic key metadata

## 🛠️ Installation & Setup

### Prerequisites
- **Rust** (latest stable version)

### Performance Notes
- **First-time operations** (keygen, signing) can take 60+ seconds on slower systems
- **Subsequent operations** are typically much faster due to cached cryptographic material
- **TSS operations** are computationally intensive - this is expected behavior
- **Browser timeout** extended to 10 minutes with progress tracking
- **Progress indicator** shows elapsed time and keeps users informed during long operations

### Browser Compatibility
- **✅ Chrome**: Fully tested and supported on Linux and Mac
- **⚠️ Firefox**: Known timeout issues with long TSS operations (not currently supported)
- **⚠️ Safari**: Known timeout issues with long TSS operations (not currently supported)
- **⚠️ Edge**: Not tested, compatibility unknown
- **📱 Mobile browsers**: Not tested, desktop Chrome recommended for development

**Recommendation**: Use Google Chrome for optimal experience. The application has been tested exclusively with Chrome on Linux and Mac systems.

### Clone and Build
```bash
git clone https://github.com/emmorais/waas.git
cd waas
cargo build --release
```

## 🚀 Running the Server

### Start the Service
```bash
cargo run
```

Or using the compiled binary:
```bash
./target/release/waas
```

### Server Output
```
🎯 TSS-ECDSA Wallet-as-a-Service Server
📍 Listening on https://localhost:8443
🔐 TLS encryption enabled
🔑 Authentication: admin/admin123
📊 Dashboard: https://localhost:8443/dashboard

✨ Ready to process TSS operations!
```

## 🌐 Testing & Usage

### Access the Web Interface

1. **Open your browser** and navigate to:
   ```
   https://localhost:8443/
   ```

2. **Accept the security warning** (self-signed certificate is expected for local testing)

3. **Login with default credentials**:
   - **Username**: `admin`
   - **Password**: `admin123`

### Web Interface Operations

#### 🔑 Key Generation
1. Click **"Generate Key Pair"** to create new TSS keys
2. The system will generate:
   - Multi-party private key shares
   - Aggregated public key
   - Root key for HD wallet derivation
   - Chain code for deterministic derivation

#### 🌱 HD Key Derivation
1. Enter a **child index** (optional - auto-generated if empty)
2. Add a **key label** (optional)
3. Click **"Derive Child Key"**
4. View all keys with **"List Keys"**

#### ✍️ Message Signing
1. Enter your message in the text field
2. Select which key to use (root or child) from the dropdown
3. Click **"Create Signature"**
4. The system performs distributed signature generation

#### 🔍 Signature Verification
1. Enter the same message used for signing
2. Click **"Verify Signature"** (uses the last generated signature)
3. The system validates cryptographic authenticity

#### 🗑️ Key Management
- **Delete Child Key**: Remove specific derived keys
- **Delete Key Material**: Remove all cryptographic data (requires confirmation)

### Command Line Testing

You can also interact with the service via curl:

```bash
# Check if server is running
curl -k https://localhost:8443/

# Generate new keys (requires basic auth)
curl -k -u admin:admin123 -X POST https://localhost:8443/keygen

# Check existing keys
curl -k -u admin:admin123 -X GET https://localhost:8443/keygen

# Sign a message
curl -k -u admin:admin123 -X POST https://localhost:8443/sign \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello World", "child_index": 0}'

# Verify a signature
curl -k -u admin:admin123 -X POST https://localhost:8443/verify \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello World", "signature": "...", "child_index": 0}'
```

## 🔒 Security Considerations

### For Development/Testing
- Uses **self-signed TLS certificates** (browsers will show security warnings)
- **Hardcoded credentials** (`admin/admin123`) - change for production use
- **Local file storage** - keys stored in working directory

### Production Recommendations
- Generate **proper TLS certificates** from a trusted CA
- Implement **secure credential management** (environment variables, secrets manager)
- Use **hardware security modules (HSMs)** for key storage
- Add **rate limiting** and **audit logging**
- Implement **proper access controls** and **multi-factor authentication**

## 📁 File Structure

```
waas/
├── src/
│   ├── main.rs              # HTTPS server & routing
│   ├── keygen.rs            # TSS key generation
│   ├── sign.rs              # Signing & verification
│   ├── hd_keys.rs           # HD wallet functionality
│   ├── delete_key.rs        # Key deletion
│   ├── dashboard.rs         # Web API endpoints
│   └── static/
│       └── index.html       # Web interface
├── cert.pem                 # TLS certificate
├── key.pem                  # TLS private key
├── Cargo.toml               # Dependencies
└── README.md               # This file
```

## 🔧 Development

### Adding New Features
1. **API Endpoints**: Add routes in `src/main.rs`
2. **TSS Operations**: Implement in respective modules
3. **Web Interface**: Update `src/static/index.html`
4. **Storage**: Modify storage functions in `src/sign.rs`

### Testing Changes
```bash
# Build and run
cargo run

# Check logs for errors
# Access https://localhost:8443/ to test UI
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 🆘 Troubleshooting

### Common Issues

**❌ "Compiling"**
````
error: failed to parse manifest at `/home/eduardo/waas/Cargo.toml`

Caused by:
  feature `edition2024` is required

  The package requires the Cargo feature called `edition2024`, but that feature is not stabilized in this version of Cargo (1.81.0 (2dbb1af80 2024-08-20)).
  Consider trying a newer version of Cargo (this may require the nightly release).
  See https://doc.rust-lang.org/nightly/cargo/reference/unstable.html#edition-2024 for more information about the status of this feature.
  ````

  Fix: 

  ````
  rustup update
  ````


**❌ "Connection refused"**
- Ensure the server is running with `cargo run`
- Check that port 8443 is not blocked by firewall

**❌ "TLS certificate error"**
- Click "Advanced" → "Proceed to localhost (unsafe)" in browser
- This is expected behavior with self-signed certificates

**❌ "Authentication failed"**
- Use credentials: `admin` / `admin123`
- Check that Authorization header is properly formatted

**❌ "No root key found"**
- Generate keys first using the "Generate Key Pair" button
- Ensure `keygen_result.json` file exists in working directory

**❌ "TSS signature generation failed" but server logs show success**
- **Most common cause**: Browser/network timeout (operations take 60+ seconds on slower systems)
- **Updated timeout handling**: Browser now waits up to 10 minutes with progress indicator
- Check server logs to see if operation completed successfully after any timeout
- If server shows success, the signature was generated but browser timed out
- Open browser developer tools (F12) and check Console tab for detailed errors
- This can happen due to:
  - **Browser/network request timeout** (most common on first run or slower systems)
  - Network connectivity issues between browser and server
  - Browser security policies blocking long-running requests
  - System resource constraints during intensive cryptographic operations

**⏱️ "Network/Browser timeout" messages**
- **Enhanced timeout handling**: Operations now have 10-minute browser timeout with progress tracking
- **Progress indicator** shows elapsed time during long operations
- Server continues processing even after any browser timeout occurs
- Check server logs to confirm if operation completed successfully
- If successful, try the operation again - it may use cached results and be faster
- **First-time operations are typically slower** due to cryptographic setup and initialization

**❌ "NetworkError when attempting to fetch resource"**
- **Most common cause**: Server not running or not accessible on https://localhost:8443
- **Browser compatibility issues**: Firefox and Safari have known timeout issues with long TSS operations
  - **Solution**: Use Google Chrome instead - fully tested and supported
  - **Status**: Firefox and Safari support is not currently available
- **Check server status**: Ensure `cargo run` is active and shows "Ready to process TSS operations!"
- **Certificate issues**: Make sure you accepted the self-signed certificate warning in browser
- **Port conflicts**: Verify port 8443 is not used by another process (`lsof -i :8443` on Linux/Mac)
- **Firewall blocking**: Check if firewall is blocking port 8443
- **Enhanced debugging**: Open browser dev tools (F12) → Console tab for detailed connection logs
- **Test connectivity**: The login process now tests server connection automatically

**❌ Browser shows "network error" for successful operations**
- Check browser developer console (F12 → Console tab) for detailed error messages
- Verify CORS headers are properly set (not typically an issue with same-origin requests)
- Ensure the response Content-Type is `application/json`
- Try refreshing the page and clearing browser cache

### Support
For issues and questions, please open an issue on the [GitHub repository](https://github.com/emmorais/waas).

# Test Credentials Management

This document explains how to manage and use encrypted test credentials for connector integration tests.

## Overview

Our testing system uses GPG-encrypted credentials to securely run integration tests both locally and in CI. All sensitive connector credentials are stored in an encrypted bundle that requires a passphrase to decrypt.

## 🔧 First-Time Setup

### For Developers (Local)

1. **Get the GPG passphrase** from your team lead
2. **Create the passphrase file**:
   ```bash
   echo 'your_passphrase_here' > .env.gpg.key
   ```
3. **Verify setup**:
   ```bash
   make test-setup
   ```
4. **Run tests**:
   ```bash
   make test
   ```

### For CI/CD

1. **Set GitHub Secret**:
   - Go to repository Settings → Secrets and variables → Actions
   - Add `GPG_PASSPHRASE` with the passphrase value
   - The CI workflow automatically uses the environment variable (no file needed)

### Alternative: Environment Variable (Local)

You can also use environment variable locally instead of creating a file:
```bash
export GPG_PASSPHRASE='your_passphrase_here'
make test
```

## 📁 File Structure

```
├── test-credentials.json.gpg       # Encrypted credential file (committed)
├── .env.gpg.key                    # Local passphrase file (gitignored)
├── test-credentials.json           # Decrypted credential file (gitignored)
└── scripts/
    ├── manage-credentials.sh       # Credential management utility
    └── decrypt-and-test.sh        # Test execution with decryption
```

## 🎯 Running Tests

### Local Development

```bash
# Run comprehensive test suite (auto-detects credentials)
make test

# Run with specific cargo arguments
./scripts/decrypt-and-test.sh -- --nocapture

# Run specific test pattern  
./scripts/decrypt-and-test.sh -- adyen
```

### CI/CD

Tests run automatically on:
- Push to `main` branch
- Pull requests
- Merge queue events

The CI will:
1. ✅ Check if `GPG_PASSPHRASE` secret exists
2. ✅ Decrypt credentials if available
3. ✅ Run tests with real credentials
4. ⚠️ Fall back to unit tests only if credentials unavailable

## 🔐 Managing Credentials

### Quick Reference

```bash
# View available commands
make manage-creds

# List current connectors
./scripts/manage-credentials.sh list

# Add new connector
./scripts/manage-credentials.sh add stripe ./stripe-creds.json

# Update existing connector
./scripts/manage-credentials.sh update adyen ./new-adyen-creds.json

# Delete connector
./scripts/manage-credentials.sh delete old_connector

# Verify bundle integrity
./scripts/manage-credentials.sh verify
```

### Adding New Connector Credentials

1. **Create credential file** (e.g., `stripe-creds.json`):
   ```json
   {
     "api_key": "sk_test_...",
     "public_key": "pk_test_...",
     "auth_type": "api_key",
     "base_url": "https://api.stripe.com/"
   }
   ```

2. **Add to encrypted file**:
   ```bash
   ./scripts/manage-credentials.sh add stripe ./stripe-creds.json
   ```

3. **Commit the updated file**:
   ```bash
   git add test-credentials.json.gpg
   git commit -m "Add Stripe test credentials"
   ```

### Updating Existing Credentials

```bash
# Update credentials
./scripts/manage-credentials.sh update adyen ./updated-adyen-creds.json

# Commit changes
git add test-credentials.json.gpg
git commit -m "Update Adyen test credentials"
```

### Removing Credentials

```bash
# Remove with confirmation
./scripts/manage-credentials.sh delete old_connector

# Force remove without confirmation
./scripts/manage-credentials.sh delete old_connector --force

# Commit changes
git add test-credentials.json.gpg
git commit -m "Remove old_connector credentials"
```

## 📋 Credential File Format

The main credentials file has this structure with connectors as top-level keys:

```json
{
  "adyen": {
    "api_key": "your_api_key",
    "api_secret": "your_api_secret",
    "merchant_id": "your_merchant_id",
    "auth_type": "signaturekey",
    "base_url": "https://checkout-test.adyen.com/"
  },
  "razorpay": {
    "api_key": "rzp_test_your_key",
    "api_secret": "your_secret",
    "auth_type": "api_key",
    "base_url": "https://api.razorpay.com/"
  }
}
```

When adding individual connectors, create a file with just the flattened key-value pairs (no connector name wrapper).

### Supported Connectors

| Connector | Auth Type | Required Fields |
|-----------|-----------|----------------|
| Adyen | SignatureKey | `api_key`, `key1`, `api_secret` |
| Razorpay | ApiKey | `api_key`, `api_secret` |
| Fiserv | ApiKey | `api_key`, `api_secret`, `merchant_id` |
| Elavon | ApiKey | `api_key`, `api_secret` |
| Xendit | ApiKey | `api_key` |
| Checkout | ApiKey | `api_key`, `public_key` |

## 🔒 Security Best Practices

### Do's ✅

- ✅ Always encrypt credentials before committing
- ✅ Use the management scripts for credential operations
- ✅ Rotate credentials regularly
- ✅ Verify bundle integrity after changes
- ✅ Use test/sandbox credentials only
- ✅ Keep passphrase secure and share only with authorized team members

### Don'ts ❌

- ❌ Never commit unencrypted credential files
- ❌ Never add `.env.gpg.key` to git
- ❌ Never use production credentials in tests
- ❌ Never share passphrases in plain text over insecure channels
- ❌ Never modify `test-credentials.tar.gz.gpg` manually

## 🐛 Troubleshooting

### Common Issues

#### "No GPG passphrase found"
**Option 1: Create passphrase file (local development)**
```bash
echo 'your_passphrase' > .env.gpg.key
```

**Option 2: Use environment variable**
```bash
export GPG_PASSPHRASE='your_passphrase'
```

#### "Failed to decrypt credentials"
```bash
# Verify passphrase is correct
./scripts/manage-credentials.sh verify
```

#### "Passphrase source priority"
The scripts check for passphrases in this order:
1. `GPG_PASSPHRASE` environment variable (used first if available)
2. `.env.gpg.key` file (fallback for local development)

#### "Invalid JSON format"
```bash
# Validate your JSON file
jq empty your-creds.json
```

#### "GPG not found"
```bash
# Install GPG
# On macOS: brew install gnupg
# On Ubuntu: sudo apt-get install gnupg
```

### Test Failures

#### Integration tests failing locally
1. Verify passphrase file exists: `ls -la .env.gpg.key`
2. Verify credentials decrypt: `./scripts/manage-credentials.sh verify`
3. Check credential format: `./scripts/manage-credentials.sh list`

#### CI tests failing
1. Check if `GPG_PASSPHRASE` secret is set in GitHub
2. Verify `test-credentials.tar.gz.gpg` is committed to repo
3. Check CI logs for specific error messages

### Getting Help

If you encounter issues:

1. **Check the logs** - Both scripts provide detailed error messages
2. **Verify dependencies** - Ensure GPG, jq, and tar are installed
3. **Test manually** - Use the verification commands to isolate issues
4. **Ask for help** - Contact your team lead if passphrase-related issues persist

## 📚 Advanced Usage

### Custom Test Commands

```bash
# Run tests with custom cargo arguments
./scripts/decrypt-and-test.sh -- --nocapture

# Run tests with specific feature flags  
./scripts/decrypt-and-test.sh -- --features "integration_tests"

# Run tests for specific package
./scripts/decrypt-and-test.sh -- grpc-server
```

### Environment Variables

The decryption script sets individual environment variables for easy access in tests:

```bash
# Adyen credentials
ADYEN_API_KEY='test_api_key_adyen'
ADYEN_KEY1='test_key1_adyen'
ADYEN_API_SECRET='test_api_secret_adyen'
ADYEN_AUTH_TYPE='signaturekey'
ADYEN_BASE_URL='https://checkout-test.adyen.com/'

# Razorpay credentials
RAZORPAY_API_KEY='rzp_test_your_key'
RAZORPAY_API_SECRET='your_secret'
RAZORPAY_AUTH_TYPE='api_key'
RAZORPAY_BASE_URL='https://api.razorpay.com/'
```

### Using in Tests

Simply read environment variables in your Rust tests:

```rust
#[cfg(test)]
mod tests {
    use std::env;

    #[test]
    fn test_adyen_payment() {
        let api_key = env::var("ADYEN_API_KEY").expect("ADYEN_API_KEY not set");
        let secret = env::var("ADYEN_API_SECRET").expect("ADYEN_API_SECRET not set");
        let base_url = env::var("ADYEN_BASE_URL").expect("ADYEN_BASE_URL not set");
        
        // Use credentials in your test...
    }

    #[test] 
    fn test_razorpay_payment() {
        let api_key = env::var("RAZORPAY_API_KEY").expect("RAZORPAY_API_KEY not set");
        let secret = env::var("RAZORPAY_API_SECRET").expect("RAZORPAY_API_SECRET not set");
        
        // Use credentials in your test...
    }
}
```

### Manual Credential Operations

For advanced users who prefer manual control:

```bash
# Decrypt manually
gpg --decrypt test-credentials.tar.gz.gpg > test-credentials.tar.gz
tar -xzf test-credentials.tar.gz

# Make changes to test-credentials/

# Re-encrypt manually
tar -czf test-credentials.tar.gz test-credentials/
gpg --symmetric --cipher-algo AES256 test-credentials.tar.gz
rm -rf test-credentials/ test-credentials.tar.gz
```

---

## 📞 Support

For questions or issues with credential management:

- **Documentation**: This README
- **Script help**: `./scripts/manage-credentials.sh help`
- **Test help**: `./scripts/decrypt-and-test.sh help` 
- **Team lead**: For passphrase and access issues
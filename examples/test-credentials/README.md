# Test Credential Templates

This directory contains template files for creating connector credentials. The main template shows the structure for the complete credentials file with all connectors.

## Usage

### Option 1: Start with Complete Template

1. **Copy the complete template**:
   ```bash
   cp examples/test-credentials/all-connectors-template.json ./my-credentials.json
   ```

2. **Fill in your actual credentials** for each connector you use
3. **Encrypt the complete file**:
   ```bash
   gpg --symmetric --cipher-algo AES256 ./my-credentials.json
   mv my-credentials.json.gpg test-credentials.json.gpg
   rm ./my-credentials.json
   ```

### Option 2: Add Individual Connectors

1. **Create individual connector file** (e.g., for Adyen):
   ```json
   {
     "api_key": "YOUR_ACTUAL_API_KEY_HERE",
     "key1": "YOUR_ACTUAL_KEY1_HERE",
     "api_secret": "YOUR_ACTUAL_SECRET_HERE",
     "auth_type": "signaturekey",
     "base_url": "https://checkout-test.adyen.com/"
   }
   ```

2. **Add to encrypted file**:
   ```bash
   ./scripts/manage-credentials.sh add adyen ./my-adyen-creds.json
   ```

3. **Clean up the unencrypted file**:
   ```bash
   rm ./my-adyen-creds.json
   ```

## Available Templates

- `all-connectors-template.json` - Complete template with all supported connectors

## Security Notes

⚠️ **NEVER commit actual credentials to git**

- ✅ These template files are safe (contain placeholder values)
- ❌ Never commit files with real API keys, secrets, or merchant IDs
- ✅ Always use the credential management scripts
- ✅ Always delete unencrypted credential files after adding them to the bundle

## Creating New Templates

When adding support for a new connector:

1. Create a new template file: `{connector}-template.json`
2. Use placeholder values that clearly indicate what should be replaced
3. Include all required fields for that connector
4. Update the main README-credentials.md with the new connector info
5. Test the template with the management scripts
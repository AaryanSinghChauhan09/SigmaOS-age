# SigmaOS-age Component Wiki

## Overview
SigmaOS-age provides age (GNU) encryption and decryption support for the SigmaOS operating system. It demonstrates the cryptography subsystem and file encryption within the SigmaOS ecosystem, following the principles of clear abstraction and deterministic crypto initialization.

## Principles
- Single Responsibility
- Cryptography Abstraction
- Fail-Fast on Crypto Initialization Errors
- Deterministic Crypto Setup
- Clear Abstraction Over Crypto APIs
- Composition over Inheritance for crypto extensions

## Architecture
SigmaOS-age follows a cryptography pattern:
- **Crypto Core**: Provides encryption, decryption, and key management primitives
- **Age Format**: Supports age encryption format with recipient keys and data integrity
- **Key Management**: Supports key generation, key storage, and key rotation
- **Error Handling**: Fail-fast on invalid cryptography configurations or unsupported algorithms

## API
The component provides the following public APIs:
- `crypto::age::encrypt(path, recipients)` - Encrypt a file using age protocol
- `crypto::age::decrypt(path, recipient_key)` - Decrypt a file using age protocol
- `crypto::key::generate(bits)` - Generate a new encryption key pair
- `crypto::status::algorithms()` - Get supported cryptography algorithms
- Error types for crypto failure scenarios or unsupported algorithms

## Test Structure (Arrange-Act-ASSERT)
All tests follow the AAA pattern:
1. **Arrange**: Set up test environment with specific cryptography configuration
2. **Act**: Execute the code under test (encryption, decryption)
3. **Assert**: Verify the expected crypto results

Example:
```rust
#[test]
fn test_crypto_encrypt_aaa() {
    // Arrange
    let test_file = "/tmp/test-plaintext.txt";
    let recipients = vec!["user@sigmaos.example"];
    
    // Act
    let result = crypto::age::encrypt(test_file, &recipients);
    
    // Assert
    assert!(result.is_ok());
    let encrypted = result.unwrap();
    assert!(encrypted.is_valid());
}
```

## Development
- Follows Rust best practices with `#![forbid(unsafe_code)]`
- Cryptography initialization is best-effort; gracefully degrades on unsupported configurations
- Comprehensive error types for all crypto failure scenarios
- Unit tests provided for encryption and decryption
- Integration tests for full cryptography subsystem with actual file encryption

## TODO
- Add support for additional cryptography algorithms (RSA, ECC, ChaCha20-Poly1305)
- Expand key management capabilities (key rotation, revocation, key storage)
- Add format support (PGP, OpenPG, S/MIME integration)
- Create integration tests with actual file encryption and decryption
- Implement key persistence and secure key storage features
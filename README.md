# pwd-crypto

Password cryptography library providing Argon2 hashing and AES-256-GCM encryption.

## Features

| Feature | Description |
|---------|-------------|
| `hash` (default) | Argon2 password hashing |
| `cipher` | AES-256-GCM encryption |
| `pwd-types` | Integration with pwd-types for `create_cipher` |
| `full` | All features enabled |
| `base64` | Base64 encoding utilities |

## Usage

### Basic (hashing only)

```toml
[dependencies]
pwd-crypto = { git = "https://github.com/LucioPg/pwd-crypto" }
```

### Full crypto suite

```toml
[dependencies]
pwd-crypto = { git = "https://github.com/LucioPg/pwd-crypto", features = ["full"] }
```

## Example

### Password Hashing

```rust
use pwd_crypto::{encrypt, verify_password};
use secrecy::SecretString;

// Hash a password
let password = SecretString::new("my_password".into());
let hash = encrypt(password.clone())?;

// Verify the password
verify_password(password, &hash)?;
```

### Encryption

```rust
use pwd_crypto::{encrypt_string, decrypt_to_string, create_nonce};

// Create a nonce
let nonce = create_nonce();

// Encrypt a string
let encrypted = encrypt_string("secret data", &cipher, &nonce)?;

// Decrypt
let decrypted = decrypt_to_string(&encrypted, &cipher, &nonce)?;
```

## License

MIT

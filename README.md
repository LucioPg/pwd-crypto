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

## License and Commercial Use

This project is licensed under the **Prosperity Public License 3.0.0**.

### What does this mean for you?

- **Personal and Non-Profit Use:** You are free to use, study, and modify this software at no cost for personal,
  educational, or research purposes.
- **Commercial Use:** If you are a company or a professional using this software for profit-making activities, you are
  granted a **30-day trial period**.

### How to Obtain a Commercial License

To continue using the software for commercial purposes after the 30-day trial, you must purchase a dedicated commercial
license.

To request a quote or activate your license, please contact:
**ldcproductions@proton.me**

*Please use the subject line: "Commercial License Request - pwd-crypto"*

---
*Note: This software is built using the Dioxus framework (MIT/Apache 2.0). All third-party open-source components remain
subject to their respective licenses.*
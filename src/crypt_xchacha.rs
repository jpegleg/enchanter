use rand::TryRngCore;
use rand::rngs::OsRng;
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
use argon2::Argon2;
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    XChaCha20Poly1305,
};
use chacha20poly1305::aead::generic_array::GenericArray;

use std::fs::File;
use std::io::{Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

/// There are three arbitrary consants of sufficient length (46 bytes) used as fixed salts.
/// One of them is a "public const" named "TUR", while the other two are
/// a private constants used within this module named "MAH" and "DEP".
#[allow(unused)]
pub const TUR: &[u8] = b"fe3oUFSXweSdjiYDFssoMUgkZ7KfG8pu4PGEsd3aFJzrU3";
/// The ENCHA constant is a fixed salt (46 bytes) used within the crypt_xchacha module
/// during the second round of Argon2id.
#[allow(unused)]
const MAH: &[u8] = b"6uUfPu7Y22NaUZKqmzVufiMX8DcZJwrDwoBMpRhzcAc9LF";
/// The DEP constant is a fixed salt (46 bytes) used within the crypt_xchacha module
/// during the third round of Argon2id.
#[allow(unused)]
const DEP: &[u8] = b"fe3oUFSXweSdjiYDFssoMUgkZ7KfG8p8EhD16HmvkLZ5FB";


/// This "checks" function is a string comparison function to ensure that the ciphertext hasn't been
/// tampered with and that the key material is correct. Supply the function with two hashes
/// generated from the ciphertext_hash function.
#[allow(unused)]
pub fn checks(validate: &str, ciphertext_hash: &str) -> bool {
    let result = validate == ciphertext_hash;
    if result == true {
      return true
    } else {
      println!("{{\n  \"ERROR\": \"Ciphertext and/or password are not as expected. \
        The supplied password, the enchanter.toml was wrong, or the file was tampered with.\",");
      println!("  \"Found hash\": \"{}\",", validate);
      println!("  \"Expected hash\": \"{}\",", ciphertext_hash);
      return false
    };
}

/// Generate key material with three rounds of Argon2id.
/// The first round is based on the password and supplied salt.
/// The second round is the output of the first round and the "MAH" salt.
/// The third round is the output of the second round and the "DEP" salt.
#[allow(unused)]
pub fn a3(password: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut okm = [0u8; 32];
    let mut rkm = [0u8; 32];
    let mut zkm = [0u8; 32];
    let _ = Argon2::default().hash_password_into(password, salt, &mut okm);
    let _ = Argon2::default().hash_password_into(MAH, &okm,  &mut rkm);
    let _ = Argon2::default().hash_password_into(DEP, &rkm, &mut zkm);
    zkm
}

/// This function generates a SHA3 XOF with SHAKE 256.
/// The XOF (hash) has input of the password and the ciphertext so
/// that if either the password is incorrect or the ciphertext has been
/// modified, the value will change.
#[allow(unused)]
pub fn ciphertext_hash(password: &[u8], file_data: &[u8], length: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(password);
    hasher.update(file_data);
    let mut reader = hasher.finalize_xof();
    let mut key = vec![0u8; length];
    XofReader::read(&mut reader, &mut key);
    key
}

/// Encrypt a file with XChaCha20Poly1305. The function takes an input file, and output, and key to use for
/// the encryption. A nonce is generated using 8 bytes of time data and 16 random bytes.
#[allow(unused)]
pub fn encrypt_file(input_file: &str, output_file: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut plaintext_file = File::open(input_file)?;
    let mut plaintext = Vec::new();
    plaintext_file.read_to_end(&mut plaintext)?;
    let mut nonce = [0u8; 24];
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let timestamp_nanos = now.as_nanos();
    nonce[0..8].copy_from_slice(&timestamp_nanos.to_le_bytes()[0..8]);
    OsRng.try_fill_bytes(&mut nonce[8..24]);
    let aead = XChaCha20Poly1305::new(GenericArray::from_slice(&key));
    let mut ciphertext_file = File::create(output_file)?;
    let mut ciphertext = plaintext.to_vec();
    let tag = aead.encrypt_in_place_detached(&nonce.into(), &[], &mut ciphertext);
    let wtag: &[u8] = &tag.unwrap();
    let mut output = File::create(output_file)?;
    output.write_all(&nonce)?;
    output.write_all(&wtag)?;
    output.write_all(&ciphertext)?;
    Ok(())
}

/// Decrypt a file with XChaCha20Poly1305.
#[allow(unused)]
pub fn decrypt_file(input_file: &str, output_file: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut ciphertext_file = File::open(input_file)?;
    let mut ciphertext = Vec::new();
    ciphertext_file.read_to_end(&mut ciphertext)?;
    let nonce = chacha20poly1305::XNonce::from_slice(&ciphertext[..24]);
    let tag = GenericArray::clone_from_slice(&ciphertext[24..40]);
    let mut plaintext = ciphertext[40..].to_vec();
    let aead = XChaCha20Poly1305::new(GenericArray::from_slice(&key));
    aead.decrypt_in_place_detached(&nonce, &[], &mut plaintext, &tag);

    let mut plaintext_file = File::create(output_file)?;
    plaintext_file.write_all(&plaintext)?;
    Ok(())
}

/// Decrypt a file to STDOUT.
/// The output is any UTF-8 data. If the data is non-UTF-8,
/// decrypt to a file instead with the decrypt_file function.
#[allow(unused)]
pub fn decrypt_stdout(input_file: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut ciphertext_file = File::open(input_file)?;
    let mut ciphertext = Vec::new();
    ciphertext_file.read_to_end(&mut ciphertext)?;
    let nonce = chacha20poly1305::XNonce::from_slice(&ciphertext[..24]);
    let tag = GenericArray::clone_from_slice(&ciphertext[24..40]);
    let mut plaintext = ciphertext[40..].to_vec();
    let aead = XChaCha20Poly1305::new(GenericArray::from_slice(&key));
    aead.decrypt_in_place_detached(&nonce, &[], &mut plaintext, &tag);

    println!("{}", String::from_utf8_lossy(&plaintext).to_string());

    Ok(())
}

mod crypt_xchacha;

pub use crypt_xchacha::*;

/// These unit tests validate a number of critical upstream behaviors, including
/// encryption, decryption, date/time, and hashing capabilities.
#[cfg(test)]
mod tests {
    #[test]
    fn datetest() {
      use chrono::prelude::*;
      assert_eq!(Utc::now().to_string().is_empty(), false);
      let dt_nano = NaiveDate::from_ymd_opt(2014, 11, 28).unwrap().and_hms_nano_opt(12, 0, 9, 1).unwrap().and_local_timezone(Utc).unwrap();
      assert_eq!(format!("{:?}", dt_nano), "2014-11-28T12:00:09.000000001Z");
    }

    #[test]
    fn sha3test1() {
      use crate::crypt_xchacha;
      let sample1 = b"testthis!";
      let sample2 = b"testagain";
      let shatest = crypt_xchacha::ciphertext_hash(sample1, sample2, 64);
      let compareme = crypt_xchacha::ciphertext_hash(sample1, sample2, 64);
      assert_eq!(shatest, compareme);
    }

    #[test]
    fn sha3test2() {
      use crate::crypt_xchacha;
      let sample1 = b"testthis!";
      let sample2 = b"testagain";
      let sample3 = b"testagain ";
      let shatest = crypt_xchacha::ciphertext_hash(sample1, sample2, 64);
      let compareme = crypt_xchacha::ciphertext_hash(sample1, sample3, 64);
      assert_ne!(shatest, compareme);
    }

    #[test]
    fn argontest1() {
      use crate::crypt_xchacha;
      let sample1 = b"testthis!";
      let sample2 = b"testagain";
      let argontest = crypt_xchacha::a3(sample1, sample2);
      let compareme = crypt_xchacha::a3(sample1, sample2);
      assert_eq!(argontest, compareme);
    }

    #[test]
    fn argontest2() {
      use crate::crypt_xchacha;
      let sample1 = b"testthis!";
      let sample2 = b"testagain";
      let sample3 = b"testagain ";
      let argontest = crypt_xchacha::a3(sample1, sample2);
      let compareme = crypt_xchacha::a3(sample1, sample3);
      assert_ne!(argontest, compareme);
    }

    #[test]
    fn crypttest1() {
      use base64::prelude::*;
      use zeroize::Zeroize;

      use std::fs::File;
      use std::io::{self, Read};

      use crate::crypt_xchacha::TUR;
      use crate::crypt_xchacha;

      let input = b"test-case12341234";
      let mut key = crypt_xchacha::a3(input, &TUR);
      let input_file = "./Cargo.toml";
      let output_file = "./test.e1";
      let _ = crypt_xchacha::encrypt_file(input_file, output_file, &key);
      let out_file = File::open(output_file).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the output file: {}", e)));
      let mut output_file_data = Vec::new();
      let _ = out_file.expect("failed to read test file").read_to_end(&mut output_file_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read {input_file}: {}", e)));
      let validate = crypt_xchacha::ciphertext_hash(&key, &output_file_data, 64);
      let validate_str = BASE64_STANDARD.encode(&validate);
      let _ = crypt_xchacha::encrypt_file(input_file, output_file, &key);
      let out_file = File::open(output_file).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the output file: {}", e)));
      let mut output_file_data = Vec::new();
      let _ = out_file.expect("failed to read test file").read_to_end(&mut output_file_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read {input_file}: {}", e)));
      let validate2 = crypt_xchacha::ciphertext_hash(&key, &output_file_data, 64);
      let checkme = BASE64_STANDARD.encode(&validate2);
      let _ = key.zeroize();
      assert_ne!(validate_str, checkme);
    }

    #[test]
    fn crypttest2() {
      use base64::prelude::*;
      use std::fs::File;
      use std::io::{self, Read};
      use crate::crypt_xchacha::TUR;
      use crate::crypt_xchacha;

      let input = b"test-case12341234";
      let key = crypt_xchacha::a3(input, &TUR);
      let input_file = "./Cargo.toml";
      let output_file = "./test.e2";
      let _ = crypt_xchacha::encrypt_file(input_file, output_file, &key);
      let out_file = File::open("./test.e2").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the output file: {}", e)));
      let mut output_file_data = Vec::new();
      let _ = out_file.expect("failed to read test file").read_to_end(&mut output_file_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read {input_file}: {}", e)));
      let _ = crypt_xchacha::ciphertext_hash(&key, &output_file_data, 64);
      let mut nonce = [0u8; 16];

      let _ = File::create("./test.o2");
      let ciphertext_file = File::open("./test.e2");
      let validate_file = File::open("./test.o2");
      let mut input_file_data = Vec::new();
      let _ = ciphertext_file.as_ref().expect("failed to read file").read_exact(&mut nonce);
      let _ = ciphertext_file.expect("failed to read file").read_to_end(&mut input_file_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read {input_file}: {}", e)));
      let validate = crypt_xchacha::ciphertext_hash(&key, &input_file_data, 64);
      let validate_str = BASE64_STANDARD.encode(&validate);
      let checkme = &validate_str;
      if crypt_xchacha::checks(checkme, &validate_str) == true {
        let _ = crypt_xchacha::decrypt_file("./test.e2", "./test.o2", &key).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Decryption failed: {}", e)));
        println!("{{\"Result\": \"file decrypted\"}}");
      } else {
        println!("  \"Result\": \"Refusing to decrypt.\"\n}}");
      };
      let mut out_file_data = Vec::new();
      let _ = validate_file.expect("failed to read file").read_to_end(&mut out_file_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read test plaintext: {}", e)));
      let mut og_file_data = Vec::new();
      let input_file_o = File::open(input_file);
      let _ = input_file_o.expect("failed to read source file").read_to_end(&mut og_file_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read test source plaintext: {}", e)));

      assert_eq!(out_file_data, og_file_data);
    }

}

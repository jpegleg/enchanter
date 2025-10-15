use rpassword::read_password;
use serde::Deserialize;
use base64::prelude::*;
use chrono::prelude::*;
use zeroize::Zeroize;

use std::env;
use std::error::Error as StdError;
use std::fs::File;
use std::io::{self, Read, Write};
use std::process;
use std::path::Path;

mod crypt_xchacha;
use crate::crypt_xchacha::TUR;

/// Forces errors to JSON. This function is a wrapper for STDERR to JSON.
fn print_error_json(msg: &str) {
    // This is a simple wrapper for STDERR JSON error printing.
    eprintln!(r#"{{ "Error": "{}" }}"#, msg);
}

/// This macro rule is used to catch errors and force them to JSON.
/// The json_started variable is manually set when the printing of
/// a JSON body has already begun, so we can complete the printing
/// of a valid JSON body, catching mid-processing issues and ensuring
/// the output is always valid JSON.
macro_rules! try_print_json {
    ($expr:expr, $json_started:expr) => {
        match $expr {
            Ok(val) => val,
            Err(e) => {
                if $json_started {
                    println!("  \"Error\": \"{}\"", e);
                    println!(" }}");
                    println!("}}");
                    return Ok(());
                } else {
                    return Err(Box::new(e) as Box<dyn StdError>);
                }
            }
        }
    };
}

/// The Config struct is required, parsed from enchanter.toml.
#[derive(Deserialize)]
struct Config {
    ciphertext_hash: String,
}

/// The Keyfile struct is optionally used, parsed from file_password.toml.
#[derive(Deserialize)]
struct Keyfile {
    enchanter_password: String,
}

/// Write a config file each time we encrypt to enchanter.toml.
fn write_config(ciphertext_path: &str, ciphertext_hash: &str) -> Result<(), Box<dyn StdError>> {
    let readi: DateTime<Utc> = Utc::now();
    let config_content = format!(
        r#"ciphertext_path = "{}"
ciphertext_hash = "{}"
creation_time = "{}"
"#,
        ciphertext_path, ciphertext_hash, readi
    );
    let json_started = false;
    let mut file = try_print_json!(
        File::create("./enchanter.toml").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open enchanter.toml: {}", e))),
        json_started
    );
    let _ = try_print_json!(
        file.write_all(config_content.as_bytes()),
        json_started
    );
    Ok(())
}

/// The bulk of "main" is moved to "run" for error handling.
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
      eprintln!("{{\n  \"ERROR\": \"Usage: {} <input_file> <output_file> < -d, -e, -ee, -do, -de, -deo >\"\n}}", args[0]);
      process::exit(1);
    }
    let input_file = &args[1];
    if input_file == "-v" {
      println!("{{\"Version\": \"0.1.2\"}}");
      process::exit(0);
    }
    if args.len() != 4 {
      eprintln!("{{\n  \"ERROR\": \"Usage: {} <input_file> <output_file> < -d, -e, -ee, -do, -de, -deo >\"\n}}", args[0]);
      process::exit(1);
    }
    let output_file = &args[2];
    let flag = &args[3];

    if Path::new("./file_password.toml").exists() {

      match flag.as_str() {
        "-do" => {
          let mut file = File::open("./enchanter.toml").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open enchanter.toml: {e}")))?;
          let mut contents = String::new();
          file.read_to_string(&mut contents).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read enchanter.toml: {e}")))?;
          let config: Config = toml::from_str(&contents).map_err(|_| io::Error::new(io::ErrorKind::Other, format!("Failed to parse enchanter.toml")))?;

          let mut file = File::open(input_file)?;
          let mut nonce = [0u8; 16];
          file.read_exact(&mut nonce)?;
          let mut km = File::open("./file_password.toml").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the key material file file_password.toml: {e}")))?;
          let mut kcontents = String::new();
          km.read_to_string(&mut kcontents).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read file_password.toml: {e}")))?;
          let kmc: Keyfile = toml::from_str(&kcontents).map_err(|_| io::Error::new(io::ErrorKind::Other, format!("Failed to parse file_password.toml")))?;
          let kmstring = Some(kmc.enchanter_password);
          let kmbytes = match kmstring {
            Some(s) => s.into_bytes(),
            None => {
              eprintln!("{{\n  \"ERROR\": \"Failed to set key material bytes.\"\n}}");
              return Ok(());
            }
          };
          let mut key = crypt_xchacha::a3(&kmbytes, TUR);

          let mut in_file = File::open(input_file).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file {input_file}: {e}")))?;
          let mut input_file_data = Vec::new();
          in_file.read_to_end(&mut input_file_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read {input_file}: {e}")))?;
          let validate = crypt_xchacha::ciphertext_hash(&key, &input_file_data, 64);
          let validate_str = BASE64_STANDARD.encode(&validate);
          let checkme = &validate_str;
          if crypt_xchacha::checks(checkme, &config.ciphertext_hash) == true {
            crypt_xchacha::decrypt_stdout(input_file, &key).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Decryption failed: {e}")))?;
          } else {
            println!("  \"Result\": \"Refusing to decrypt.\"\n}}");
          };
          key.zeroize();
        },
        "-d" => {
          let mut file = File::open("./enchanter.toml").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open enchanter.toml: {e}")))?;
          let mut contents = String::new();
          file.read_to_string(&mut contents).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read enchanter.toml: {e}")))?;
          let config: Config = toml::from_str(&contents).map_err(|_| io::Error::new(io::ErrorKind::Other, format!("Failed to parse enchanter.toml")))?;

          let mut file = File::open(input_file)?;
          let mut nonce = [0u8; 16];
          file.read_exact(&mut nonce)?;
          let mut km = File::open("./file_password.toml").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the key material file file_password.toml: {e}")))?;
          let mut kcontents = String::new();
          km.read_to_string(&mut kcontents).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read file_password.toml: {e}")))?;
          let kmc: Keyfile = toml::from_str(&kcontents).map_err(|_| io::Error::new(io::ErrorKind::Other, format!("Failed to parse file_password.toml")))?;
          let kmstring = Some(kmc.enchanter_password);
          let kmbytes = match kmstring {
            Some(s) => s.into_bytes(),
            None => {
              eprintln!("{{\n  \"ERROR\": \"Failed to set key material bytes.\"\n}}");
              return Ok(());
            }
          };

          let mut key = crypt_xchacha::a3(&kmbytes, TUR);

          let mut in_file = File::open(input_file).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file {input_file}: {e}")))?;
          let mut input_file_data = Vec::new();
          in_file.read_to_end(&mut input_file_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read {input_file}: {e}")))?;
          let validate = crypt_xchacha::ciphertext_hash(&key, &input_file_data, 64);
          let validate_str = BASE64_STANDARD.encode(&validate);
          let checkme = &validate_str;
          if crypt_xchacha::checks(checkme, &config.ciphertext_hash) == true {
            crypt_xchacha::decrypt_file(input_file, output_file, &key).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Decryption failed: {e}")))?;
            println!("{{\"Result\": \"file decrypted\"}}");
          } else {
            println!("  \"Result\": \"Refusing to decrypt.\"\n}}");
          };
          key.zeroize();

        },
        "-e" => {
          let mut km = File::open("./file_password.toml").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the key material file file_password.toml: {e}")))?;
          let mut kcontents = String::new();
          km.read_to_string(&mut kcontents).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read file_password.toml: {e}")))?;
          let kmc: Keyfile = toml::from_str(&kcontents).map_err(|_| io::Error::new(io::ErrorKind::Other, format!("Failed to parse file_password.toml")))?;
          let kmstring = Some(kmc.enchanter_password);
          let kmbytes = match kmstring {
            Some(s) => s.into_bytes(),
            None => {
              eprintln!("{{\n  \"ERROR\": \"Failed to set key material bytes.\"\n}}");
              return Ok(());
            }
          };

          let mut key = crypt_xchacha::a3(&kmbytes, TUR);

          crypt_xchacha::encrypt_file(input_file, output_file, &key)?;
          let mut out_file = File::open(output_file).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the output file {output_file}: {e}")))?;
          let mut output_file_data = Vec::new();
          out_file.read_to_end(&mut output_file_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read {output_file}: {e}")))?;
          let validate = crypt_xchacha::ciphertext_hash(&key, &output_file_data, 64);
          let validate_str = BASE64_STANDARD.encode(&validate);
          println!("{{\"Validation string\": \"{validate_str}\"}}");
          let _ = write_config(output_file, &validate_str);
          key.zeroize();
        },
        "-ee" => {
            eprintln!("{{ \"ERROR\": \"Environment variable options are not availble if a file_password.toml is in use. A file_password.toml has been found.\"}} ");
            process::exit(1);
        },
        "-deo" => {
            eprintln!("{{ \"ERROR\": \"Environment variable options are not availble if a file_password.toml is in use. A file_password.toml has been found.\"}} ");
            process::exit(1);
        },
        "-de" => {
            eprintln!("{{ \"ERROR\": \"Environment variable options are not availble if a file_password.toml is in use. A file_password.toml has been found.\"}} ");
            process::exit(1);
        },
        _ => {
            eprintln!("{{ \"ERROR\": \"Invalid flag. Use -d for decryption or -e for encryption of a file using a supplied password. Use -ee to encrypt with an environment variable ENC, and -de to decrypt with an environment variable. Environment variable options are not availble if a file_password.toml is in use. Use -do to decrypt to STDOUT, and -deo to use an environment variable and decrypt to STDOUT. Use -v to print the version of enchanter.\"}} ");
            process::exit(1);
        }
      }

    } else {

      match flag.as_str() {
        "-deo" => {
          let mut file = File::open("./enchanter.toml").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open enchanter.toml: {e}")))?;
          let mut contents = String::new();
          file.read_to_string(&mut contents).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read enchanter.toml: {e}")))?;
          let config: Config = toml::from_str(&contents).map_err(|_| io::Error::new(io::ErrorKind::Other, format!("Failed to parse enchanter.toml")))?;

          let mut file = File::open(input_file)?;
          let mut nonce = [0u8; 16];
          file.read_exact(&mut nonce)?;
          let strpassword = env::var("ENC").map_err(|_| io::Error::new(io::ErrorKind::Other, format!("Environment variable ENC not set")))?;
          let password = strpassword.as_bytes();

          let mut key = crypt_xchacha::a3(password, TUR);
          let mut in_file = File::open(input_file).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file {input_file}: {e}")))?;
          let mut input_file_data = Vec::new();
          in_file.read_to_end(&mut input_file_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read {input_file}: {e}")))?;
          let validate = crypt_xchacha::ciphertext_hash(&key, &input_file_data, 64);
          let validate_str = BASE64_STANDARD.encode(&validate);
          let checkme = &validate_str;
          if crypt_xchacha::checks(checkme, &config.ciphertext_hash) == true {
            crypt_xchacha::decrypt_stdout(input_file, &key).map_err(|e|io::Error::new(io::ErrorKind::Other, format!("Decryption failed for {input_file}: {e}")))?;
          } else {
            println!("  \"Result\": \"Refusing to decrypt.\"\n}}");
          };
          key.zeroize();

        },
        "-do" => {
          let mut file = File::open("./enchanter.toml").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open enchanter.toml: {e}")))?;
          let mut contents = String::new();
          file.read_to_string(&mut contents).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read enchanter.toml: {e}")))?;
          let config: Config = toml::from_str(&contents).map_err(|_| io::Error::new(io::ErrorKind::Other, format!("Failed to parse enchanter.toml")))?;

          let mut file = File::open(input_file)?;
          let mut nonce = [0u8; 16];
          file.read_exact(&mut nonce)?;
          eprint!("Enter password: ");
          std::io::stdout().flush()?;
          let password = read_password()?;
          let bpassword = password.as_bytes();
          let mut key = crypt_xchacha::a3(bpassword, TUR);
          let mut in_file = File::open(input_file).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file {input_file}: {e}")))?;
          let mut input_file_data = Vec::new();
          in_file.read_to_end(&mut input_file_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read {input_file}: {e}")))?;
          let validate = crypt_xchacha::ciphertext_hash(&key, &input_file_data, 64);
          let validate_str = BASE64_STANDARD.encode(&validate);
          let checkme = &validate_str;
          if crypt_xchacha::checks(checkme, &config.ciphertext_hash) == true {
            crypt_xchacha::decrypt_stdout(input_file, &key).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Decryption failed: {e}")))?;
          } else {
            println!("  \"Result\": \"Refusing to decrypt.\"\n}}");
          };
          key.zeroize();

        },
        "-de" => {
          let mut file = File::open("./enchanter.toml").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open enchanter.toml: {e}")))?;
          let mut contents = String::new();
          file.read_to_string(&mut contents).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read enchanter.toml: {e}")))?;
          let config: Config = toml::from_str(&contents).map_err(|_| io::Error::new(io::ErrorKind::Other, format!("Failed to parse enchanter.toml")))?;

          let mut file = File::open(input_file)?;
          let mut nonce = [0u8; 16];
          file.read_exact(&mut nonce)?;
          let strpassword = env::var("ENC").map_err(|_| io::Error::new(io::ErrorKind::Other, format!("Environment variable ENC not set")))?;
          let password = strpassword.as_bytes();
          let mut key = crypt_xchacha::a3(password, TUR);
          let mut in_file = File::open(input_file).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file {input_file}: {e}")))?;
          let mut input_file_data = Vec::new();
          in_file.read_to_end(&mut input_file_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read {input_file}: {e}")))?;
          let validate = crypt_xchacha::ciphertext_hash(&key, &input_file_data, 64);
          let validate_str = BASE64_STANDARD.encode(&validate);
          let checkme = &validate_str;
          if crypt_xchacha::checks(checkme, &config.ciphertext_hash) == true {
            crypt_xchacha::decrypt_file(input_file, output_file, &key).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Decryption failed: {e}")))?;
            println!("{{\"Result\": \"file decrypted\"}}");
          } else {
            println!("  \"Result\": \"Refusing to decrypt.\"\n}}");
          };
          key.zeroize();

        },
        "-d" => {
          let mut file = File::open("./enchanter.toml").map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open enchanter.toml: {e}")))?;
          let mut contents = String::new();
          file.read_to_string(&mut contents).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read enchanter.toml: {e}")))?;
          let config: Config = toml::from_str(&contents).map_err(|_| io::Error::new(io::ErrorKind::Other, format!("Failed to parse enchanter.toml")))?;

          let mut file = File::open(input_file)?;
          let mut nonce = [0u8; 16];
          file.read_exact(&mut nonce)?;
          // Hide from STDOUT for output management, use STDERR for password prompt.
          eprint!("Enter password: ");
          std::io::stdout().flush()?;
          let password = read_password()?;
          let bpassword = password.as_bytes();
          let mut key = crypt_xchacha::a3(bpassword, TUR);
          let mut in_file = File::open(input_file).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the input file {input_file}: {e}")))?;
          let mut input_file_data = Vec::new();
          in_file.read_to_end(&mut input_file_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read {input_file}: {e}")))?;
          let validate = crypt_xchacha::ciphertext_hash(&key, &input_file_data, 64);
          let validate_str = BASE64_STANDARD.encode(&validate);
          let checkme = &validate_str;
          if crypt_xchacha::checks(checkme, &config.ciphertext_hash) == true {
            crypt_xchacha::decrypt_file(input_file, output_file, &key).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Decryption failed: {e}")))?;
            println!("{{\"Result\": \"file decrypted\"}}");
          } else {
            println!("  \"Result\": \"Refusing to decrypt.\"\n}}");
          };
          key.zeroize();

        },
        "-ee" => {
          let password = env::var("ENC").map_err(|_| io::Error::new(io::ErrorKind::Other, format!("Environment variable ENC not set")))?;
          let bpassword = password.as_bytes();
          let mut key = crypt_xchacha::a3(bpassword, TUR);
          crypt_xchacha::encrypt_file(input_file, output_file, &key)?;
          let mut out_file = File::open(output_file).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the output file {output_file}: {e}")))?;
          let mut output_file_data = Vec::new();
          out_file.read_to_end(&mut output_file_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read {output_file}: {e}")))?;
          let validate = crypt_xchacha::ciphertext_hash(&key, &output_file_data, 64);
          let validate_str = BASE64_STANDARD.encode(&validate);
          println!("{{\"Validation string\": \"{validate_str}\"}}");
          let _ = write_config(output_file, &validate_str);
          key.zeroize();
        },
        "-e" => {
          // Hide from STDOUT for output management, use STDERR for password prompt.
          eprint!("Enter password: ");
          std::io::stdout().flush()?;
          let password = read_password()?;
          let bpassword = password.as_bytes();
          let mut key = crypt_xchacha::a3(bpassword, TUR);
          crypt_xchacha::encrypt_file(input_file, output_file, &key)?;
          let mut out_file = File::open(output_file).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to open the output file {output_file}: {e}")))?;
          let mut output_file_data = Vec::new();
          out_file.read_to_end(&mut output_file_data).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read {output_file}: {e}")))?;
          let validate = crypt_xchacha::ciphertext_hash(&key, &output_file_data, 64);
          let validate_str = BASE64_STANDARD.encode(&validate);
          println!("{{\"Validation string\": \"{validate_str}\"}}");
          let _ = write_config(output_file, &validate_str);
          key.zeroize();
        },
        _ => {
            eprintln!("{{ \"ERROR\": \"Invalid flag. Use -d for decryption or -e for encryption of a file using a supplied password. Use -ee to encrypt with an environment variable ENC, and -de to decrypt with an environment variable. Environment variable options are not available if a file_password.toml is in use. Use -do to decrypt to STDOUT, and -deo to use an environment variable and decrypt to STDOUT. Use -v to print the version of enchanter.\"}} ");
            process::exit(1);
        }
      }
    }

    Ok(())
}

/// The main function is a wrapper for the run function, for error catching.
fn main() {
    if let Err(e) = run() {
        print_error_json(&e.to_string());
        std::process::exit(1);
    }
}

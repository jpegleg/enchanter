![cdlogo](https://carefuldata.com/images/cdlogo.png)

# Enchanter

Enchanter is a tool for XChaCha20Poly1305 AEAD file encryption.

There is an additional integrity checking mechanism with SHA3.

The integrity checking mechanism with SHA3 uses an XOF (expandable output function) with the ciphertext and password, to create a "validation_string", also referred to as the "ciphertext_hash",
that the tool uses to ensure that the ciphertext has not been tampered with and that the password is correct.

The password can optionally be supplied from a `file_password.toml` file instead of an interactive password or environment variable.

Encryptions are are recorded in an `enchanter.toml` which is needed for decryption with enchanter.

The key is generated based on a password processed in Argon2id:

```
Argon2 round 1: supplied password + fixed1 ->
  Argon2 round 2: result of round 1 + fixed2 ->
    Argon2 round 3: result of round 2 + fixed3 ->
      actual key material

```

This is an "overkill" amount of Argon2, as 1 round of Argon2 is already plenty in most situations.

The XChaCha20Poly1305 AEAD uses that final key material and a NONCE IV that has time data and random data from the system.

See [enchantress](https://crates.io/crates/enchantress) for AES-256 file encryption with a similar tool.

## Installing

Enchanter can be installed from crates.io:

```
cargo install enchanter
```

Or compiled from source:

```
cargo build --release
sudo cp target/release/enchanter /usr/local/bin/
```

Or installed from a release binary.


## Command options

There is one cipher modes, three key input modes, and two types of decryption modes.

```
The first mode is with a supplied password interactively supplied in the terminal: -e and -d 
The second mode is with a password set as the environment variable "ENC": -ee and -de
The two types of decryption are:
  decryption to a file: -d and -de
  decryption to STDOUT: -do and -deo
The third mode is if a file_password.toml is in the working directory of process execution, the enchanter_password value is used instead.

```

## Project promises

This project will never use AI-slop. All code is reviewed, tested, implemented by a human that is academically trained in cryptography and information security.
This repository and the crates.io repository is carefully managed and protected.

This project will never break backwards compatibility with released versions.

This project will be maintained as best as is reasonable.

## Ciphertext integrity

Because enchanter takes strong security measures, SHA3 and a serialized config file with hash comparison logic are used to provide an additional layer of integrity.
Even though XChaCha20Poly1305 is already an AEAD with non-malleability, this additional layer adds further protection. If the ciphertext or password are not correct, enchanter will print a message like so and exit:

```
{
  "ERROR": "Ciphertext and/or password are not as expected. The supplied password was wrong, the enchanter.toml was wrong, or the file was tampered with.",
  "Found hash": "zHuCjbtVtgUj/osukIU7Lfa/MuJXvOWsTwbyRdIb2sM7AvM7dE3JBlm4J+qIvjP6xnlarb/cgKgslbfsqPOGLw==",
  "Expected hash": "mX7aiGz8k2w7AXItnwNttL03xHed/dm1wZX/hi22DZcEqbpeBhMgeAKuxuJgOF1TJDFd3FoqlrNrLqcLCW0YWg==",
  "Result": "Refusing to decrypt."
}
```

This integrity check is a comparison of base64 encoded SHA3 64 byte XOFs. The hashes are constructed from the ciphertext and the key material being processed together, output as a 64 byte SHA3 XOF.

Even though g has it's own integrity mechanism within the ciphertext, enchanter still uses the additional integrity checking regardless of mode.

## The enchanter.toml file

With each encryption, an `enchanter.toml` file is created in the pwd of the command execution.

<b>WARNING: This file will be overwritten if one is already present and an encryption is run in the same directory!</b>

The config file contains the ciphertext path, the validation hash, and the time of the encryption.

Example:
```
ciphertext_path = "my_data.e"
ciphertext_hash = "xshPOXhtqGJtBoIj/vvxWSh55hryEOMYRqOeedH0hJJccH/edQSUqXxkGvvaFNeJfL9NOaAVUdav4z1tAkn+/A=="
creation_time = "2025-07-13 19:15:32.334352329 UTC"
```

The `ciphertext_hash` is not a secret itself and can be safely shared.

The only line actually required for decryption is the ciphertext_hash.
The ciphertext_path and creation_time items are for human/metadata use.
An enchanter.toml can be created/recreated manually. The "validation string" that the encryption outputs
is ciphertext_hash, and can be stored separately or shared, etc etc.

The password used is the secret to protect. The password is not stored and explicitly emptied from memory.

Weak passwords are weak security. Enchanter does not enforce "good" passwords, password security is up to you!

## Usage patterns

Because there can only be one `enchanter.toml` in the working directory, when working with multiple files we might either change directories or move the enchanter.toml files that are created to other names.

Here is an example of creating directories and then moving into them to encrypt each file.
In this example we also validate that the decryption is working before removing the plaintext.

```
mkdir data_1 data_2
cd data_1
enchanter /someplace/myfile /someplace/myfile.e -e
Enter password:
{"Validation string": "mX7aiGz8k2w7AXItnwNttL03xHed/dm1wZX/hi22DZcEqbpeBhMgeAKuxuJgOF1TJDFd3FoqlrNrLqcLCW0YWg=="}
enchanter /someplace/myfile.e . -do
Enter password:
test data
rm -f /someplace/myfile
cd ..
cd data_2
enchanter /someplace/anotherfile /someplace/anotherfile.e -e
Enter password:
{"Validation string": "7xzFsmth88L9YZwpHqUMBbNdx9IVHtAneshyDSqXi6IcT6SL9r8SxE6DjKg/bpzQargpfmo1/fzeKSA6Ve5QDg=="}
enchanter /someplace/anotherfile.e . -do
Enter password:
some other data
rm -f /someplace/anotherfile
cd ..
```

In this example we stay in the same directory, but move the enchanter.toml file to new file names after each encryption.

```
enchanter /someplace/myfile /someplace/myfile.e -e
Enter password:
{"Validation string": "fDtQiBLuMFZeebE7WmOkgHXbxHAbgbTUEEsx2fH2p8ZkR0LVTluzzwuYKVjobLLHyNUB50cMF57ftQPNcRyyYg=="}
enchanter /someplace/myfile.e . -do
Enter password:
test data
rm -f /someplace/myfile
mv enchanter.toml myfile_enchanter.toml
enchanter /someplace/anotherfile /someplace/anotherfile.e -e
Enter password:
{"Validation string": "BS40KBN66tTCs7GDBIThqT2UyJBR+bJhekUbkl8PfIvfrusk+0FkRohrAGcatBjwYM4GIyBOVvDY4FiKePjMfw=="}
enchanter /someplace/anotherfile.e . -do
Enter password:
some other data
rm -f /someplace/anotherfile
mv enchanter.toml anotherfile_enchanter.toml
```

When moving the enchanter.toml to new file names, we'll have to move them back to enchanter.toml to decrypt.

Notice how in these examples we have "." as the output file when using the "-do" option. The value of the output file can be anything when the decryption is going to STDOUT
because it is not written, so a period or any other single character is one way to do it.

Another technique is to use the same file for both input and output. This is not generally recommended as you don't have a chance to validate the decryption and the file name isn't changed.
But it is an option that can be used.

```
enchanter /someplace/myfile /someplace/myfile -e
Enter password:
{"Validation string": "/eOzNTiB/htZxl8DhdYzWkyw/WuDMERU6To09r85X72JWDalObKrBI88UkhSzBy1o1RT2h+lpurf7vtxn0MaSw=="}
```

When we decrypt files, we can either print to STDOUT or decrypt to a file. If the data is binary, then printing to STDOUT is not very useful and likely you should decrypt to a file.
If the data is text that needs to stay protected, they decrypting to STDOUT is useful as to not expose the plaintext to the disk and need to remove it again.

There are also options for using the environment variable "ENC" or `file_password.toml`. These are generally less secure, but provide ways for automation to utilize enchanter.
We can set a password as an environment variable so that systems that need to automatically encrypt can do so without an interactive prompt or exposed key file on the disk.

```
export ENC="RWw5XjBXQmhBLi43VGIwSCZfXl4xRm18T3RBNTZIOCQK and so it was my password blah"
enchanter /someplace/myfile /someplace/myfile.e -ee
{"Validation string": "/eOzNTiB/htZxl8DhdYzWkyw/WuDMERU6To09r85X72JWDalObKrBI88UkhSzBy1o1RT2h+lpurf7vtxn0MaSw=="}
rm -f /someplace/myfile
```

Then to decrypt with the "ENC" environment variable:

```
export ENC="RWw5XjBXQmhBLi43VGIwSCZfXl4xRm18T3RBNTZIOCQK and so it was my password blah"
enchanter /someplace/myfile.e /someplace/myfile -de
{"Result": "file decrypted"}
```

If we want to clear out the environment variable (in BASH), we can 'unset' it:

```
unset ENC
```

If we prefer to expose on the disk, then we can set the password in a file `./file_password.toml`.

Fun fact: emojis can be used in passwords in most cases and can create very strong passwords in some cases.


## The file_password.toml file

The optional key material file `file_password.toml` can be used instead of a password or environment variable.
If a file_password.toml is used for encryption, that same password from the file_password.toml will be required for decryption.

The file is constructed as a single key value pair:

```
enchanter_password = "OSs0cyY6LGQweTNmXDR3YyQ7aDc8NW9RfEQ6ajBlYCp3UTdVUyEsc2hoOjVfUyA0VnFRKXBkWnhNUG82Q0MrO3lFUzNMT3opa1hJV3JsNG1GOEo6ZyUpYkU4UEhUMWh0Cg"
```

While in most cases just the interactive password is sufficient and more secure, there are cases where enchanter is needed in automation and the environment variable and interactive password are not good options.
In such a case use the `file_password.toml` to store the key material on disk. Don't use double quotes in the value of enchanter_password.

When the `file_password.toml` is in place, the options for environment variables are not available and the prompt for a password is skipped.

## giant-spellbook tool

There is another tool named [giant-spellbook](https://github.com/jpegleg/giant-spellbook) that is compatible with enchanter because it imports enchanter as a library.
The encryption and decryption operations can be done with giant-spellbook as well, without any TOML config file.

If you prefer not to have an enchanter.toml, then giant-spellbook is the tool for you.

Enchanter uses [zeroize](https://docs.rs/zeroize/latest/zeroize/) to explicitly empty the key from memory. This technique is generally recommended to avoid the edge case where the compiler optimizes away an important aspect of "zeroizing" a value.

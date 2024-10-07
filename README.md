# ENCRYPTOR

## Installation

Install the dependencies 

```sh
cargo build
```

## Encrypt
```sh
cargo run -- encrypt hello.txt hello.enc "mi_contraseña_secreta"
```
## Decrypt
```sh
cargo run -- decrypt hello.enc hello_decrypted.txt "mi_contraseña_secreta"
```

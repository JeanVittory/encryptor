use std::{fs, path::PathBuf};
use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit, Nonce};
use base64::{engine::general_purpose, Engine}; 
use rand::Rng;
use sha2::{Sha256, Digest};
use clap::{Parser, Subcommand};
use std::fmt;
#[derive(Debug)]
enum MyError {
    IoError(std::io::Error),
    AesGcmError(aes_gcm::Error),
    Base64DecodeError(base64::DecodeError),
    InvalidFormatError(String),
}

impl fmt::Display for MyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MyError::IoError(err) => write!(f, "I/O error: {}", err),
            MyError::AesGcmError(err) => write!(f, "AES-GCM error: {}", err),
            MyError::Base64DecodeError(err) => write!(f, "Base64 decode error: {}", err),
            MyError::InvalidFormatError(msg) => write!(f, "Invalid format: {}", msg),
        }
    }
}

impl std::error::Error for MyError {}

impl From<std::io::Error> for MyError {
    fn from(err: std::io::Error) -> MyError {
        MyError::IoError(err)
    }
}

impl From<aes_gcm::Error> for MyError {
    fn from(err: aes_gcm::Error) -> MyError {
        MyError::AesGcmError(err)
    }
}

impl From<base64::DecodeError> for MyError {
    fn from(err: base64::DecodeError) -> MyError {
        MyError::Base64DecodeError(err)
    }
}

// Implementación de From<&str> para MyError
impl From<&str> for MyError {
    fn from(err: &str) -> MyError {
        MyError::InvalidFormatError(err.to_string())
    }
}

#[derive(Parser)]
#[command(name="encryptor")]
#[command(about="Tool to encrypt and decrypt data")]
struct Cli{
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands{
    Encrypt{
        input: PathBuf,
        output: PathBuf,
        password: String
    },
    Decrypt{
        input: PathBuf,
        output: PathBuf,
        password: String
    }
}

fn main() {
    let cli  = Cli::parse();

    match &cli.command {
        Commands::Encrypt { input, output, password } => {
            match encrypt_file(input, output, password) {
                Ok(_) => println!("Encryption successfully completed"),
                Err(err) => eprintln!("Error during encryption: {}", err)
            }
        },
        Commands::Decrypt { input, output, password } => {
            match decrypt_file(input, output, password) {
                Ok(_) => println!("Decryption successfully completed"),
                Err(err) => eprintln!("Error during decryption: {}", err)
            }
        }
    }
}

fn derive_key(password: &str) -> Key<Aes256Gcm> {
    // Deriva una clave de 256 bits usando SHA-256
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();

    // Crea la clave a partir del resultado hash (32 bytes = 256 bits)
    *Key::<Aes256Gcm>::from_slice(&result)
}


fn encrypt_file(input:&PathBuf, output: &PathBuf, password: &str) -> Result<(), MyError> {
    let data = fs::read(input)?;
    let key = derive_key(password);
    let iv = rand::thread_rng().gen::<[u8; 12]>();
    let nonce = Nonce::from_slice(&iv);
    let cipher = Aes256Gcm::new(&key);
    let cipher_text = cipher.encrypt(nonce, data.as_ref())?;

    let encoded_iv = general_purpose::STANDARD.encode(&iv);
    let encoded_ct = general_purpose::STANDARD.encode(&cipher_text);
    let combined = format!("{}:{}", encoded_iv, encoded_ct);

    fs::write(output, combined)?;

    Ok(())
}

fn decrypt_file(input: &PathBuf, output: &PathBuf, password: &str) -> Result<(), MyError> {
    // Lee el contenido del archivo encriptado
    let data = fs::read_to_string(input)?;

    // Separa el IV y el ciphertext
    let parts: Vec<&str> = data.split(':').collect();
    if parts.len() != 2 {
        return Err("Formato de archivo inválido".into());
    }

    let iv = general_purpose::STANDARD.decode(parts[0])?;
    let ciphertext = general_purpose::STANDARD.decode(parts[1])?;

    // Deriva la clave
    let key = derive_key(password);

    let nonce = Nonce::from_slice(&iv);

    // Crea el desencrypter
    let cipher = Aes256Gcm::new(&key);

    // Desencripta los datos
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())?;

    // Escribe el contenido desencriptado al archivo de salida
    fs::write(output, plaintext)?;

    Ok(())
}
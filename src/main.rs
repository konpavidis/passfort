use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce, AeadCore}; 
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, path::Path};
use rpassword::read_password;
use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use std::os::unix::fs::PermissionsExt; 

#[derive(Serialize, Deserialize, Debug)]
struct PasswordEntry {
    username: String,
    nonce: Vec<u8>,
    encrypted_password: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
struct PasswordStore {
    salt: String,
    passwords: HashMap<String, PasswordEntry>,
}

#[derive(Parser)]
#[command(name = "PassFort")]
#[command(version = "0.1", author = "Konstantinos Pavlakis", about = "A Secure CLI Password Manager")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Add { service: String, username: String, password: String },
    Get { service: String },
}

const FILE_PATH: &str = "passwords.json";

fn main() {
    let cli = Cli::parse();
    println!("Enter master password: ");
    let master_password = read_password().expect("Failed to read password");
    let (key, mut store) = load_or_init_store(&master_password);

    match &cli.command {
        Commands::Add { service, username, password } => {
            let (nonce, encrypted_password) = encrypt_password(password, &key);
            store.passwords.insert(service.clone(), PasswordEntry { 
                username: username.clone(), 
                nonce,
                encrypted_password 
            });
            save_store(&store);
            println!("✅ Password saved for {}", service);
        }
        Commands::Get { service } => {
            match store.passwords.get(service) {
                Some(entry) => {
                    match decrypt_password(&entry.encrypted_password, &entry.nonce, &key) {
                        Ok(decrypted) => println!("🔑 User: {}, Password: {}", entry.username, decrypted),
                        Err(_) => println!("❌ Failed to decrypt password!"),
                    }
                }
                None => println!("❌ No password found for {}", service),
            }
        }
    }
}

fn derive_key(master_password: &str, salt: &SaltString) -> Key<Aes256Gcm> {
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(master_password.as_bytes(), salt).unwrap();
    Key::<Aes256Gcm>::from_slice(&hash.hash.unwrap().as_bytes()[0..32]).clone()
}

fn load_or_init_store(master_password: &str) -> (Key<Aes256Gcm>, PasswordStore) {
    if Path::new(FILE_PATH).exists() {
        let data = fs::read_to_string(FILE_PATH).expect("Failed to read file");
        let store: PasswordStore = serde_json::from_str(&data).expect("Failed to deserialize");
        let salt = SaltString::from_b64(&store.salt).expect("Invalid salt");
        let key = derive_key(master_password, &salt);
        (key, store)
    } else {
        let salt = SaltString::generate(&mut OsRng);
        let key = derive_key(master_password, &salt);
        let store = PasswordStore {
            salt: salt.as_ref().to_string(),
            passwords: HashMap::new(),
        };
        save_store(&store);
        (key, store)
    }
}

fn encrypt_password(password: &str, key: &Key<Aes256Gcm>) -> (Vec<u8>, Vec<u8>) {
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // Now works with AeadCore
    let encrypted = cipher.encrypt(&nonce, password.as_bytes()).expect("Encryption failed");
    (nonce.to_vec(), encrypted)
}

fn decrypt_password(encrypted: &[u8], nonce: &[u8], key: &Key<Aes256Gcm>) -> Result<String, aes_gcm::Error> {
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce);
    let decrypted = cipher.decrypt(nonce, encrypted)?;
    Ok(String::from_utf8(decrypted).map_err(|_| aes_gcm::Error)?)
}

fn save_store(store: &PasswordStore) {
    let data = serde_json::to_string_pretty(store).expect("Failed to serialize");
    fs::write(FILE_PATH, data).expect("Failed to write to file");
    fs::set_permissions(FILE_PATH, fs::Permissions::from_mode(0o600)).expect("Failed to set permissions"); // Now works with PermissionsExt
}
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce, AeadCore};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, path::Path};
use rpassword::read_password;
use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use std::os::unix::fs::PermissionsExt;
use dialoguer::{Select, Input, Confirm};
use rand::Rng;
use rand::distributions::Alphanumeric;

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
#[command(name = "PassFort", bin_name = "pf, passfort")]
#[command(version = "0.2", author = "Konstantinos Pavlakis", about = "A Secure CLI Password Manager")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Add { 
        service: String, 
        username: String, 
        #[arg(long, default_value = "16")] length: usize,
    },
    Get { 
        service: String, 
    },
    List,
    Search { query: String }, // better implementation pending
    Ui,
}

const FILE_PATH: &str = "passwords.json";

fn main() {
    let cli = Cli::parse();
    println!("Enter master password: ");
    let master_password = read_password().expect("Failed to read password");
    let (key, mut store) = load_or_init_store(&master_password);

    match &cli.command {
        Commands::Add { service, username, length } => {
            let password = generate_password(*length);
            add_password(&mut store, service, username, &password, &key);
            println!("✅ Password saved for {}. Generated password: {}", service, password);
        }
        Commands::Get { service } => {
            get_password(&store, service, &key);
        }
        Commands::List => {
            list_services(&store);
        }
        Commands::Search { query } => {
            search_services(&store, query);
        }
        Commands::Ui => {
            run_interactive_ui(&key, &mut store);
        }
    }
}

fn add_password(store: &mut PasswordStore, service: &str, username: &str, password: &str, key: &Key<Aes256Gcm>) {
    let (nonce, encrypted_password) = encrypt_password(password, key);
    store.passwords.insert(service.to_string(), PasswordEntry { 
        username: username.to_string(), 
        nonce,
        encrypted_password 
    });
    save_store(store);
}

fn get_password(store: &PasswordStore, service: &str, key: &Key<Aes256Gcm>) {
    match store.passwords.get(service) {
        Some(entry) => {
            match decrypt_password(&entry.encrypted_password, &entry.nonce, key) {
                Ok(decrypted) => {
                    println!("🔑 User: {}, Password: {}", entry.username, decrypted);
                }
                Err(_) => println!("❌ Failed to decrypt password!"),
            }
        }
        None => println!("❌ No password found for {}", service),
    }
}

fn list_services(store: &PasswordStore) {
    if store.passwords.is_empty() {
        println!("📭 No saved passwords.");
    } else {
        println!("📜 Stored services:");
        for (index, service) in store.passwords.keys().enumerate() {
            println!("  {}. {}", index + 1, service);
        }
    }
}

fn search_services(store: &PasswordStore, query: &str) {
    let matches: Vec<&String> = store.passwords.keys()
        .filter(|service| service.to_lowercase().contains(&query.to_lowercase()))
        .collect();
    if matches.is_empty() {
        println!("🔍 No services found matching '{}'.", query);
    } else {
        println!("🔍 Found services matching '{}':", query);
        for (index, service) in matches.iter().enumerate() {
            println!("  {}. {}", index + 1, service);
        }
    }
}

fn generate_password(length: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

// Create better ui function or to remove generally
fn run_interactive_ui(key: &Key<Aes256Gcm>, store: &mut PasswordStore) {
    let options = vec![
        "➕ Add Password",
        "🔑 Get Password",
        "📜 List Services",
        "🔍 Search Services",
        "❌ Exit",
    ];

    loop {
        let selection = Select::new()
            .with_prompt("Choose an option")
            .items(&options)
            .default(0)
            .interact()
            .expect("Failed to read selection");

        match selection {
            0 => { 
                let service: String = Input::new()
                    .with_prompt("Enter service name")
                    .interact_text()
                    .expect("Failed to read service");
                let username: String = Input::new()
                    .with_prompt("Enter username")
                    .interact_text()
                    .expect("Failed to read username");
                let use_generated = Confirm::new()
                    .with_prompt("Generate a strong password?")
                    .default(true)
                    .interact()
                    .expect("Failed to read confirmation");
                let password = if use_generated {
                    let length: usize = Input::new()
                        .with_prompt("Enter password length")
                        .default("16".to_string())
                        .interact_text()
                        .expect("Failed to read length")
                        .parse()
                        .unwrap_or(16);
                    let pwd = generate_password(length);
                    println!("Generated password: {}", pwd);
                    pwd
                } else {
                    println!("Enter password: ");
                    read_password().expect("Failed to read password")
                };
                add_password(store, &service, &username, &password, key);
                println!("✅ Password saved for {}", service);
            }
            1 => { 
                let services: Vec<&String> = store.passwords.keys().collect();
                if services.is_empty() {
                    println!("📭 No saved passwords.");
                } else {
                    let selection = Select::new()
                        .with_prompt("Select a service")
                        .items(&services)
                        .interact()
                        .expect("Failed to read selection");
                    let service = services[selection];
                    get_password(store, service, key);
                }
            }
            2 => { 
                list_services(store);
            }
            3 => { 
                let query: String = Input::new()
                    .with_prompt("Enter search query")
                    .interact_text()
                    .expect("Failed to read query");
                search_services(store, &query);
            }
            4 => { 
                println!("👋 Goodbye!");
                break;
            }
            _ => unreachable!(),
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
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
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
    fs::set_permissions(FILE_PATH, fs::Permissions::from_mode(0o600)).expect("Failed to set permissions");
}
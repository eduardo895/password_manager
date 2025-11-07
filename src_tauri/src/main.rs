#![cfg_attr(all(not(debug_assertions), target_os = "windows"), windows_subsystem = "windows")]

use std::{fs, path::{self, PathBuf}};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand::rngs::OsRng;
use rand::{Rng, RngCore};
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use tauri::{Manager, State};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroize;

const MASTER_FILE: &str = "master.hash";

#[derive(Debug, Error)]
pub enum PasswordError {
    #[error("application data directory is unavailable")]
    AppDirUnavailable,
    #[error("failed to read or write password store: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to serialize password store: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("password entry not found")]
    NotFound,
    #[error("crypto error: {0}")]
    Crypto(String),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PasswordEntry {
    pub id: Uuid,
    pub service: String,
    pub username: String,
    pub password: String,
}

impl PasswordEntry {
    fn new(service: String, username: String, password: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            service,
            username,
            password,
        }
    }
}

#[derive(Default)]
struct PasswordStore {
    entries: Vec<PasswordEntry>,
    path: Option<PathBuf>,
    master_key: Option<String>,
}

// ---------- 🔐 Derivação e Criptografia ----------
fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let argon2 = Argon2::default();
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("Falha na derivação de chave: {e}"))?;
    Ok(key)
}

fn encrypt(data: &str, passphrase: &str) -> Result<String> {
    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let key = derive_key(passphrase, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| anyhow!(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, data.as_bytes())
        .map_err(|e| anyhow!(e.to_string()))?;

    let mut key_mut = key;
    key_mut.zeroize();

    Ok(format!(
        "{}:{}:{}",
        general_purpose::STANDARD.encode(nonce_bytes),
        general_purpose::STANDARD.encode(salt),
        general_purpose::STANDARD.encode(ciphertext)
    ))
}

fn decrypt(serialized: &str, passphrase: &str) -> Result<String> {
    let parts: Vec<&str> = serialized.split(':').collect();
    if parts.len() != 3 {
        return Err(anyhow!("Formato inválido do ficheiro cifrado"));
    }

    let nonce_bytes = general_purpose::STANDARD.decode(parts[0])?;
    let salt = general_purpose::STANDARD.decode(parts[1])?;
    let ciphertext = general_purpose::STANDARD.decode(parts[2])?;

    let key = derive_key(passphrase, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| anyhow!(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| anyhow!("Falha na decifração (passphrase errada ou ficheiro corrompido)."))?;

    let mut key_mut = key;
    key_mut.zeroize();

    Ok(String::from_utf8(plaintext)?)
}
// -------------------------------------------------

impl PasswordStore {
    fn load(handle: &tauri::AppHandle, master: &str) -> Result<Self, PasswordError> {
        let mut store = PasswordStore::default();
        let data_dir = handle
            .path()
            .app_data_dir()
            .map_err(|_| PasswordError::AppDirUnavailable)?;
        let path = data_dir.join("passwords.enc");
        store.path = Some(path.clone());
        store.master_key = Some(master.to_string());

        if let Ok(data) = fs::read_to_string(&path) {
            let decrypted =
                decrypt(&data, master).map_err(|e| PasswordError::Crypto(e.to_string()))?;
            let entries: Vec<PasswordEntry> = serde_json::from_str(&decrypted)?;
            store.entries = entries;
        }

        Ok(store)
    }

    fn save(&self) -> Result<(), PasswordError> {
        if let Some(path) = &self.path {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let json = serde_json::to_string_pretty(&self.entries)?;
            let master = self
                .master_key
                .clone()
                .ok_or_else(|| PasswordError::Crypto("Master key não definida".into()))?;
            let encrypted =
                encrypt(&json, &master).map_err(|e| PasswordError::Crypto(e.to_string()))?;
            fs::write(path, encrypted)?;
        }
        Ok(())
    }

    fn list(&self) -> Vec<PasswordEntry> {
        self.entries.clone()
    }

    fn add(&mut self, service: String, username: String, password: String) -> PasswordEntry {
        let entry = PasswordEntry::new(service, username, password);
        self.entries.push(entry.clone());
        entry
    }

    fn update(
        &mut self,
        id: Uuid,
        service: String,
        username: String,
        password: String,
    ) -> Result<PasswordEntry, PasswordError> {
        let entry = self
            .entries
            .iter_mut()
            .find(|item| item.id == id)
            .ok_or(PasswordError::NotFound)?;

        entry.service = service;
        entry.username = username;
        entry.password = password;

        Ok(entry.clone())
    }

    fn remove(&mut self, id: Uuid) -> Result<(), PasswordError> {
        let original_len = self.entries.len();
        self.entries.retain(|item| item.id != id);
        if self.entries.len() == original_len {
            return Err(PasswordError::NotFound);
        }
        Ok(())
    }
}

struct Store(tauri::async_runtime::Mutex<Option<PasswordStore>>);

#[tauri::command]
async fn load_store(handle: tauri::AppHandle, store: State<'_, Store>, master: String) -> Result<(), String> {
    let new_store = PasswordStore::load(&handle, &master).map_err(|e| e.to_string())?;
    let mut locked = store.0.lock().await;
    *locked = Some(new_store);
    Ok(())
}

#[tauri::command]
async fn list_passwords(store: State<'_, Store>) -> Result<Vec<PasswordEntry>, String> {
    let store = store.0.lock().await;
    if let Some(ref s) = *store {
        Ok(s.list())
    } else {
        Err("Store não carregado".into())
    }
}

#[tauri::command]
async fn add_password(
    store: State<'_, Store>,
    service: String,
    username: String,
    password: String,
) -> Result<PasswordEntry, String> {
    let mut store = store.0.lock().await;
    let s = store.as_mut().ok_or("Store não carregado")?;
    let entry = s.add(service, username, password);
    s.save().map(|_| entry).map_err(|err| err.to_string())
}

#[tauri::command]
async fn update_password(
    store: State<'_, Store>,
    id: Uuid,
    service: String,
    username: String,
    password: String,
) -> Result<PasswordEntry, String> {
    let mut store = store.0.lock().await;
    let s = store.as_mut().ok_or("Store não carregado")?;
    let entry = s
        .update(id, service, username, password)
        .map_err(|err| err.to_string())?;
    s.save().map(|_| entry).map_err(|err| err.to_string())
}

#[tauri::command]
async fn delete_password(store: State<'_, Store>, id: Uuid) -> Result<(), String> {
    let mut store = store.0.lock().await;
    let s = store.as_mut().ok_or("Store não carregado")?;
    s.remove(id).map_err(|err| err.to_string())?;
    s.save().map_err(|err| err.to_string())
}

// ---------- 🔐 Master password setup ----------
#[tauri::command]
async fn set_master_password(handle: tauri::AppHandle, password: String) -> Result<(), String> {
    let data_dir = handle.path().app_data_dir().map_err(|_| "Sem diretório de dados")?;
    fs::create_dir_all(&data_dir).map_err(|e| e.to_string())?;
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(password.as_bytes(), &salt).map_err(|e| e.to_string())?;
    fs::write(data_dir.join(MASTER_FILE), hash.to_string()).map_err(|e| e.to_string())?;
    println!("Master password criada em {:?}:",data_dir.join(MASTER_FILE) );

    Ok(())
}

#[tauri::command]
async fn verify_master_password(handle: tauri::AppHandle, password: String) -> Result<bool, String> {
    let data_dir = handle.path().app_data_dir().map_err(|_| "Sem diretório de dados")?;
    let hash_path = data_dir.join(MASTER_FILE);
    if !hash_path.exists() {
        return Ok(false);
    }
    let saved_hash = fs::read_to_string(hash_path).map_err(|e| e.to_string())?;
    let parsed_hash = PasswordHash::new(&saved_hash).map_err(|e| e.to_string())?;
    let argon2 = Argon2::default();
    Ok(argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok())
}

// ---------- 🎲 Gerador de senhas ----------
#[tauri::command]
async fn generate_password(
    length: usize,
    use_uppercase: bool,
    use_lowercase: bool,
    use_numbers: bool,
    use_symbols: bool,
) -> Result<String, String> {
    let mut charset = String::new();
    if use_lowercase {
        charset.push_str("abcdefghijklmnopqrstuvwxyz");
    }
    if use_uppercase {
        charset.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }
    if use_numbers {
        charset.push_str("0123456789");
    }
    if use_symbols {
        charset.push_str("!@#$%^&*()-_=+[]{};:,.<>?");
    }

    if charset.is_empty() {
        return Err("Selecione pelo menos um tipo de caractere".into());
    }

    let mut rng = rand::thread_rng();
    let password: String = (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..charset.len());
            charset.chars().nth(idx).unwrap()
        })
        .collect();

    Ok(password)
}

// ---------- 🚀 Main ----------
fn main() {
    tauri::Builder::default()
        .manage(Store(tauri::async_runtime::Mutex::new(None)))
        .invoke_handler(tauri::generate_handler![
            load_store,
            list_passwords,
            add_password,
            update_password,
            delete_password,
            set_master_password,
            verify_master_password,
            generate_password
        ])
        .run(tauri::generate_context!())
        .expect("erro ao iniciar aplicação");
}

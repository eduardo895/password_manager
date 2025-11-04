use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tauri::{Manager, State};
use thiserror::Error;
use uuid::Uuid;

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
}

impl PasswordStore {
    fn load(handle: &tauri::AppHandle) -> Result<Self, PasswordError> {
        let mut store = PasswordStore::default();
        let data_dir = handle
            .path_resolver()
            .app_data_dir()
            .ok_or(PasswordError::AppDirUnavailable)?;
        let path = data_dir.join("passwords.json");
        store.path = Some(path.clone());

        if let Ok(data) = fs::read_to_string(&path) {
            let entries: Vec<PasswordEntry> = serde_json::from_str(&data)?;
            store.entries = entries;
        }

        Ok(store)
    }

    fn save(&self) -> Result<(), PasswordError> {
        if let Some(path) = &self.path {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let data = serde_json::to_string_pretty(&self.entries)?;
            fs::write(path, data)?;
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

struct Store(tauri::async_runtime::Mutex<PasswordStore>);

#[tauri::command]
async fn list_passwords(store: State<'_, Store>) -> Result<Vec<PasswordEntry>, String> {
    let store = store.0.lock().await;
    Ok(store.list())
}

#[tauri::command]
async fn add_password(
    store: State<'_, Store>,
    service: String,
    username: String,
    password: String,
) -> Result<PasswordEntry, String> {
    let mut store = store.0.lock().await;
    let entry = store.add(service, username, password);
    store.save().map(|_| entry).map_err(|err| err.to_string())
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
    let entry = store
        .update(id, service, username, password)
        .map_err(|err| err.to_string())?;
    store.save().map(|_| entry).map_err(|err| err.to_string())
}

#[tauri::command]
async fn delete_password(store: State<'_, Store>, id: Uuid) -> Result<(), String> {
    let mut store = store.0.lock().await;
    store.remove(id).map_err(|err| err.to_string())?;
    store.save().map_err(|err| err.to_string())
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let store = PasswordStore::load(&app.handle())?;
            app.manage(Store(tauri::async_runtime::Mutex::new(store)));
            Ok(())
        })

        .invoke_handler(tauri::generate_handler![
            list_passwords,
            add_password,
            update_password,
            delete_password
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
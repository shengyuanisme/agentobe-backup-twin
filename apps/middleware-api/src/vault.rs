use crate::error::AppError;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use async_trait::async_trait;
use aws_config::{BehaviorVersion, Region};
use aws_credential_types::Credentials;
use aws_sdk_s3::{Client, primitives::ByteStream};
use axum::http::StatusCode;
use base64::{Engine, engine::general_purpose::STANDARD};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, RwLock},
};
use tokio::fs;

#[async_trait]
pub trait BlobStore: Send + Sync {
    fn driver(&self) -> &'static str;
    async fn put(&self, key: &str, data: Vec<u8>) -> anyhow::Result<()>;
    async fn get(&self, key: &str) -> anyhow::Result<Vec<u8>>;
    async fn delete(&self, key: &str) -> anyhow::Result<()>;
}

pub struct FileBlobStore {
    root: PathBuf,
}
impl FileBlobStore {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }
}
#[async_trait]
impl BlobStore for FileBlobStore {
    fn driver(&self) -> &'static str {
        "file"
    }
    async fn put(&self, key: &str, data: Vec<u8>) -> anyhow::Result<()> {
        let path = self.root.join(key);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            options.mode(0o600);
        }
        use tokio::io::AsyncWriteExt;
        let mut file = options.open(path).await?;
        file.write_all(&data).await?;
        Ok(())
    }
    async fn get(&self, key: &str) -> anyhow::Result<Vec<u8>> {
        Ok(fs::read(self.root.join(key)).await?)
    }
    async fn delete(&self, key: &str) -> anyhow::Result<()> {
        match fs::remove_file(self.root.join(key)).await {
            Ok(_) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

#[derive(Default)]
pub struct MemoryBlobStore {
    objects: RwLock<HashMap<String, Vec<u8>>>,
}
#[async_trait]
impl BlobStore for MemoryBlobStore {
    fn driver(&self) -> &'static str {
        "memory"
    }
    async fn put(&self, key: &str, data: Vec<u8>) -> anyhow::Result<()> {
        let mut objects = self.objects.write().unwrap();
        anyhow::ensure!(!objects.contains_key(key), "object already exists");
        objects.insert(key.into(), data);
        Ok(())
    }
    async fn get(&self, key: &str) -> anyhow::Result<Vec<u8>> {
        self.objects
            .read()
            .unwrap()
            .get(key)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("object not found"))
    }
    async fn delete(&self, key: &str) -> anyhow::Result<()> {
        self.objects.write().unwrap().remove(key);
        Ok(())
    }
}

pub struct SpacesBlobStore {
    client: Client,
    bucket: String,
}
impl SpacesBlobStore {
    pub async fn new(
        bucket: String,
        region: String,
        access_key: String,
        secret_key: String,
    ) -> Self {
        let credentials = Credentials::new(access_key, secret_key, None, None, "agentobe-spaces");
        let shared = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(region.clone()))
            .credentials_provider(credentials)
            .endpoint_url(format!("https://{region}.digitaloceanspaces.com"))
            .load()
            .await;
        Self {
            client: Client::new(&shared),
            bucket,
        }
    }
}
#[async_trait]
impl BlobStore for SpacesBlobStore {
    fn driver(&self) -> &'static str {
        "spaces"
    }
    async fn put(&self, key: &str, data: Vec<u8>) -> anyhow::Result<()> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(data))
            .content_type("application/vnd.agentobe.encrypted+json")
            .send()
            .await?;
        Ok(())
    }
    async fn get(&self, key: &str) -> anyhow::Result<Vec<u8>> {
        Ok(self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await?
            .body
            .collect()
            .await?
            .into_bytes()
            .to_vec())
    }
    async fn delete(&self, key: &str) -> anyhow::Result<()> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultObjectMetadata {
    pub object_key: String,
    pub storage_driver: String,
    pub encryption_algorithm: String,
    pub key_wrap_algorithm: String,
    pub key_version: String,
    pub plaintext_hash: String,
    pub ciphertext_hash: String,
    pub size_bytes: i64,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Envelope {
    format: String,
    key_version: String,
    wrapped_key: CipherPayload,
    content: CipherPayload,
}
#[derive(Serialize, Deserialize)]
struct CipherPayload {
    iv: String,
    tag: String,
    ciphertext: String,
}

#[derive(Clone)]
pub struct EncryptedSourceVault {
    store: Arc<dyn BlobStore>,
    master_key: [u8; 32],
    key_version: String,
}
impl EncryptedSourceVault {
    pub fn new(
        store: Arc<dyn BlobStore>,
        master_key_base64: &str,
        key_version: String,
    ) -> anyhow::Result<Self> {
        let decoded = STANDARD.decode(master_key_base64)?;
        let master_key: [u8; 32] = decoded.try_into().map_err(|_| {
            anyhow::anyhow!("VAULT_MASTER_KEY must be a base64-encoded 32-byte key")
        })?;
        Ok(Self {
            store,
            master_key,
            key_version,
        })
    }
    pub async fn put(
        &self,
        workspace_id: uuid::Uuid,
        batch_id: uuid::Uuid,
        value: &Value,
    ) -> Result<VaultObjectMetadata, AppError> {
        let plaintext = agentobe_contracts::canonical_json(value).into_bytes();
        let mut data_key = [0u8; 32];
        OsRng.fill_bytes(&mut data_key);
        let envelope = Envelope {
            format: "agentobe.source-vault.v1".into(),
            key_version: self.key_version.clone(),
            wrapped_key: encrypt(&self.master_key, &data_key)?,
            content: encrypt(&data_key, &plaintext)?,
        };
        let encoded = agentobe_contracts::canonical_json(&serde_json::to_value(envelope).unwrap())
            .into_bytes();
        let object_key = format!("source-vault/{workspace_id}/{batch_id}.json.enc");
        self.store
            .put(&object_key, encoded.clone())
            .await
            .map_err(internal)?;
        Ok(VaultObjectMetadata {
            object_key,
            storage_driver: self.store.driver().into(),
            encryption_algorithm: "AES-256-GCM".into(),
            key_wrap_algorithm: "AES-256-GCM".into(),
            key_version: self.key_version.clone(),
            plaintext_hash: agentobe_contracts::sha256_bytes(&plaintext),
            ciphertext_hash: agentobe_contracts::sha256_bytes(&encoded),
            size_bytes: encoded.len() as i64,
        })
    }
    pub async fn verify(&self, metadata: &VaultObjectMetadata) -> Result<Value, AppError> {
        let encoded = self
            .store
            .get(&metadata.object_key)
            .await
            .map_err(internal)?;
        let envelope: Envelope = serde_json::from_slice(&encoded).map_err(internal)?;
        let key = decrypt(&self.master_key, &envelope.wrapped_key)?;
        let plaintext = decrypt(
            key.as_slice()
                .try_into()
                .map_err(|_| internal("bad wrapped key"))?,
            &envelope.content,
        )?;
        let ciphertext_hash = agentobe_contracts::sha256_bytes(&encoded);
        let plaintext_hash = agentobe_contracts::sha256_bytes(&plaintext);
        Ok(
            json!({"status":if ciphertext_hash==metadata.ciphertext_hash && plaintext_hash==metadata.plaintext_hash {"healthy"} else {"failed"},"ciphertextHash":ciphertext_hash,"plaintextHash":plaintext_hash,"keyVersion":envelope.key_version,"encryptionAlgorithm":metadata.encryption_algorithm}),
        )
    }
    pub async fn delete(&self, key: &str) {
        let _ = self.store.delete(key).await;
    }
}

fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<CipherPayload, AppError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(internal)?;
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);
    let mut combined = cipher
        .encrypt(Nonce::from_slice(&iv), plaintext)
        .map_err(internal)?;
    let tag = combined.split_off(combined.len() - 16);
    Ok(CipherPayload {
        iv: STANDARD.encode(iv),
        tag: STANDARD.encode(tag),
        ciphertext: STANDARD.encode(combined),
    })
}
fn decrypt(key: &[u8; 32], payload: &CipherPayload) -> Result<Vec<u8>, AppError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(internal)?;
    let mut ciphertext = STANDARD.decode(&payload.ciphertext).map_err(internal)?;
    ciphertext.extend(STANDARD.decode(&payload.tag).map_err(internal)?);
    cipher
        .decrypt(
            Nonce::from_slice(&STANDARD.decode(&payload.iv).map_err(internal)?),
            ciphertext.as_slice(),
        )
        .map_err(internal)
}
fn internal(error: impl std::fmt::Display) -> AppError {
    tracing::error!(%error, "vault operation failed");
    AppError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "INTERNAL_ERROR",
        "Unexpected middleware failure.",
    )
}

//! Private-bus Secret Service used when the host has no `org.freedesktop.secrets`.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use serde_json::Value;
use zbus::zvariant::{Array, ObjectPath, OwnedObjectPath, OwnedValue, Value as ZValue};
use zbus::{connection, interface};

const SERVICE_NAME: &str = "org.freedesktop.secrets";
const SERVICE_PATH: &str = "/org/freedesktop/secrets";
const COLLECTION_PATH: &str = "/org/freedesktop/secrets/collection/login";
const EMPTY_PROMPT: &str = "/";
const MAX_ITEMS: u32 = 32;

pub struct MockSecretService {
    daemon: Child,
    stop: Option<std::sync::mpsc::Sender<()>>,
    service: Option<JoinHandle<()>>,
    pub address: String,
}

impl Drop for MockSecretService {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let _ = self.daemon.kill();
        let _ = self.daemon.wait();
        if let Some(handle) = self.service.take() {
            let _ = handle.join();
        }
    }
}

struct KillOnDrop(Option<Child>);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn resolve_host_binary(name: &str) -> PathBuf {
    let path = std::env::var_os("PATH").expect("test-process PATH to resolve host binaries");
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return candidate;
        }
    }
    panic!("{name} not found on the test-process PATH");
}

fn hermetic_command(path: &Path) -> Command {
    let mut cmd = Command::new(path);
    cmd.env_clear();
    cmd.env("LANG", "C.UTF-8");
    cmd.env("LC_ALL", "C.UTF-8");
    cmd
}

pub fn start_mock_secret_service() -> MockSecretService {
    let dbus = resolve_host_binary("dbus-daemon");
    let daemon = hermetic_command(&dbus)
        .args(["--session", "--nofork", "--print-address=1"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn dbus-daemon for mock secret service");
    let mut daemon = KillOnDrop(Some(daemon));
    let mut address = String::new();
    BufReader::new(
        daemon
            .0
            .as_mut()
            .expect("dbus-daemon child")
            .stdout
            .take()
            .expect("dbus-daemon stdout"),
    )
    .read_line(&mut address)
    .expect("read dbus-daemon address");
    let address = address.trim().to_string();
    assert!(
        !address.is_empty(),
        "dbus-daemon printed no session address"
    );

    let address_for_thread = address.clone();
    let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let ready_flag = Arc::clone(&ready);
    let (stop_tx, stop_rx) = std::sync::mpsc::channel();
    let handle = std::thread::Builder::new()
        .name("cockpit-e2e-secret-service".into())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("secret-service runtime");
            runtime.block_on(async move {
                serve(&address_for_thread, ready_flag, stop_rx).await;
            });
        })
        .expect("spawn secret-service thread");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !ready.load(std::sync::atomic::Ordering::SeqCst) {
        assert!(
            std::time::Instant::now() < deadline,
            "mock secret service failed to claim the bus"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    MockSecretService {
        daemon: daemon.0.take().expect("dbus-daemon child"),
        stop: Some(stop_tx),
        service: Some(handle),
        address,
    }
}

async fn serve(
    address: &str,
    ready: Arc<std::sync::atomic::AtomicBool>,
    stop_rx: std::sync::mpsc::Receiver<()>,
) {
    let state = Arc::new(Mutex::new(ServiceState::new()));
    let mut builder = connection::Builder::address(address)
        .expect("session bus builder")
        .name(SERVICE_NAME)
        .expect("request secret service name")
        .serve_at(
            SERVICE_PATH,
            SecretIface {
                state: Arc::clone(&state),
            },
        )
        .expect("serve secret service")
        .serve_at(
            COLLECTION_PATH,
            CollectionIface {
                state: Arc::clone(&state),
            },
        )
        .expect("serve default collection");
    for idx in 1..=MAX_ITEMS {
        let path = format!("{COLLECTION_PATH}/{idx}");
        builder = builder
            .serve_at(
                path.clone(),
                ItemIface {
                    state: Arc::clone(&state),
                    path,
                },
            )
            .expect("serve item slot");
    }
    let _conn = builder.build().await.expect("start mock secret service");
    ready.store(true, std::sync::atomic::Ordering::SeqCst);
    while stop_rx.try_recv().is_err() {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

struct ServiceState {
    crypto: CryptoHelper,
    sessions: HashMap<String, String>,
    items: HashMap<String, StoredItem>,
    next_item: u32,
}

struct StoredItem {
    attributes: HashMap<String, String>,
    secret: Vec<u8>,
    content_type: String,
    path: String,
}

impl ServiceState {
    fn new() -> Self {
        Self {
            crypto: CryptoHelper::spawn(),
            sessions: HashMap::new(),
            items: HashMap::new(),
            next_item: 1,
        }
    }
}

struct SecretIface {
    state: Arc<Mutex<ServiceState>>,
}

struct CollectionIface {
    state: Arc<Mutex<ServiceState>>,
}

struct ItemIface {
    state: Arc<Mutex<ServiceState>>,
    path: String,
}

#[interface(name = "org.freedesktop.Secret.Service")]
impl SecretIface {
    fn open_session(
        &mut self,
        algorithm: &str,
        input: ZValue<'_>,
    ) -> zbus::fdo::Result<(OwnedValue, OwnedObjectPath)> {
        if algorithm != "dh-ietf1024-sha256-aes128-cbc-pkcs7" {
            return Err(zbus::fdo::Error::NotSupported(algorithm.into()));
        }
        let bytes = input_bytes(&input)?;
        let mut state = self.state.lock().expect("secret state");
        let reply = state.crypto.call(&serde_json::json!({
            "op": "open",
            "client_pub": encode_hex(&bytes),
        }));
        let server_pub = decode_hex(reply["server_pub"].as_str().unwrap_or_default());
        let id = reply["id"].as_str().unwrap_or("s0").to_string();
        let path = format!("/org/freedesktop/secrets/session/{id}");
        state.sessions.insert(path.clone(), id);
        let output = Array::from(server_pub);
        let output = OwnedValue::try_from(ZValue::from(output))
            .map_err(|err| zbus::fdo::Error::Failed(err.to_string()))?;
        let result = OwnedObjectPath::try_from(path)
            .map_err(|err| zbus::fdo::Error::Failed(err.to_string()))?;
        Ok((output, result))
    }

    fn create_collection(
        &self,
        _properties: HashMap<String, ZValue<'_>>,
        _alias: &str,
    ) -> (OwnedObjectPath, OwnedObjectPath) {
        (owned_path(COLLECTION_PATH), owned_path(EMPTY_PROMPT))
    }

    fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) {
        (matching_items(&self.state, &attributes), Vec::new())
    }

    fn unlock(&self, objects: Vec<OwnedObjectPath>) -> (Vec<OwnedObjectPath>, OwnedObjectPath) {
        (objects, owned_path(EMPTY_PROMPT))
    }

    fn lock(&self, _objects: Vec<OwnedObjectPath>) -> (Vec<OwnedObjectPath>, OwnedObjectPath) {
        (Vec::new(), owned_path(EMPTY_PROMPT))
    }

    fn get_secrets(
        &self,
        _objects: Vec<OwnedObjectPath>,
    ) -> HashMap<OwnedObjectPath, (OwnedObjectPath, Vec<u8>, Vec<u8>, String)> {
        HashMap::new()
    }

    fn read_alias(&self, _name: &str) -> OwnedObjectPath {
        owned_path(COLLECTION_PATH)
    }

    fn set_alias(&self, _name: &str, _collection: OwnedObjectPath) {}

    #[zbus(property)]
    fn collections(&self) -> Vec<OwnedObjectPath> {
        vec![owned_path(COLLECTION_PATH)]
    }
}

#[interface(name = "org.freedesktop.Secret.Collection")]
impl CollectionIface {
    fn delete(&self) -> OwnedObjectPath {
        owned_path(EMPTY_PROMPT)
    }

    fn search_items(&self, attributes: HashMap<String, String>) -> Vec<OwnedObjectPath> {
        matching_items(&self.state, &attributes)
    }

    fn create_item(
        &mut self,
        properties: HashMap<String, ZValue<'_>>,
        secret: (OwnedObjectPath, Vec<u8>, Vec<u8>, String),
        replace: bool,
    ) -> zbus::fdo::Result<(OwnedObjectPath, OwnedObjectPath)> {
        let attributes = properties
            .get("org.freedesktop.Secret.Item.Attributes")
            .and_then(value_as_str_map)
            .unwrap_or_default();
        let (session, iv, data, content_type) = secret;
        let mut state = self.state.lock().expect("secret state");
        let session_id = state
            .sessions
            .get(session.as_str())
            .cloned()
            .unwrap_or_default();
        let reply = state.crypto.call(&serde_json::json!({
            "op": "decrypt",
            "id": session_id,
            "iv": encode_hex(&iv),
            "data": encode_hex(&data),
        }));
        let plain = decode_hex(reply["plain"].as_str().unwrap_or_default());
        if replace {
            state.items.retain(|_, item| {
                !attributes
                    .iter()
                    .all(|(k, v)| item.attributes.get(k) == Some(v))
            });
        }
        if state.next_item > MAX_ITEMS {
            return Err(zbus::fdo::Error::Failed("item slots exhausted".into()));
        }
        let idx = state.next_item;
        state.next_item += 1;
        let path = format!("{COLLECTION_PATH}/{idx}");
        state.items.insert(
            path.clone(),
            StoredItem {
                attributes,
                secret: plain,
                content_type,
                path: path.clone(),
            },
        );
        Ok((owned_path(&path), owned_path(EMPTY_PROMPT)))
    }

    #[zbus(property)]
    fn items(&self) -> Vec<OwnedObjectPath> {
        let state = self.state.lock().expect("secret state");
        state
            .items
            .values()
            .map(|item| owned_path(&item.path))
            .collect()
    }

    #[zbus(property)]
    fn label(&self) -> String {
        "login".into()
    }

    #[zbus(property)]
    fn set_label(&self, _new_label: &str) {}

    #[zbus(property)]
    fn locked(&self) -> bool {
        false
    }

    #[zbus(property)]
    fn created(&self) -> u64 {
        0
    }

    #[zbus(property)]
    fn modified(&self) -> u64 {
        0
    }
}

#[interface(name = "org.freedesktop.Secret.Item")]
impl ItemIface {
    fn delete(&self) -> OwnedObjectPath {
        owned_path(EMPTY_PROMPT)
    }

    fn get_secret(
        &self,
        session: ObjectPath<'_>,
    ) -> zbus::fdo::Result<(OwnedObjectPath, Vec<u8>, Vec<u8>, String)> {
        let mut state = self.state.lock().expect("secret state");
        let item = state
            .items
            .get(&self.path)
            .ok_or_else(|| zbus::fdo::Error::Failed("missing item".into()))?;
        let session_id = state
            .sessions
            .get(session.as_str())
            .cloned()
            .unwrap_or_default();
        let secret = item.secret.clone();
        let content_type = item.content_type.clone();
        let reply = state.crypto.call(&serde_json::json!({
            "op": "encrypt",
            "id": session_id,
            "plain": encode_hex(&secret),
        }));
        Ok((
            owned_path(session.as_str()),
            decode_hex(reply["iv"].as_str().unwrap_or_default()),
            decode_hex(reply["data"].as_str().unwrap_or_default()),
            content_type,
        ))
    }

    fn set_secret(
        &self,
        secret: (OwnedObjectPath, Vec<u8>, Vec<u8>, String),
    ) -> zbus::fdo::Result<()> {
        let (session, iv, data, content_type) = secret;
        let mut state = self.state.lock().expect("secret state");
        let session_id = state
            .sessions
            .get(session.as_str())
            .cloned()
            .unwrap_or_default();
        let reply = state.crypto.call(&serde_json::json!({
            "op": "decrypt",
            "id": session_id,
            "iv": encode_hex(&iv),
            "data": encode_hex(&data),
        }));
        let plain = decode_hex(reply["plain"].as_str().unwrap_or_default());
        let item = state
            .items
            .get_mut(&self.path)
            .ok_or_else(|| zbus::fdo::Error::Failed("missing item".into()))?;
        item.secret = plain;
        item.content_type = content_type;
        Ok(())
    }

    #[zbus(property)]
    fn locked(&self) -> bool {
        false
    }

    #[zbus(property)]
    fn attributes(&self) -> HashMap<String, String> {
        let state = self.state.lock().expect("secret state");
        state
            .items
            .get(&self.path)
            .map(|item| item.attributes.clone())
            .unwrap_or_default()
    }

    #[zbus(property)]
    fn set_attributes(&self, attributes: HashMap<String, String>) {
        let mut state = self.state.lock().expect("secret state");
        if let Some(item) = state.items.get_mut(&self.path) {
            item.attributes = attributes;
        }
    }

    #[zbus(property)]
    fn label(&self) -> String {
        "item".into()
    }

    #[zbus(property)]
    fn set_label(&self, _new_label: &str) {}

    #[zbus(property)]
    fn created(&self) -> u64 {
        0
    }

    #[zbus(property)]
    fn modified(&self) -> u64 {
        0
    }
}

struct CryptoHelper {
    child: Child,
    stdin: std::process::ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
}

impl CryptoHelper {
    fn spawn() -> Self {
        let script =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/e2e/support/secret_crypto.py");
        let python = resolve_host_binary("python3");
        let mut child = hermetic_command(&python)
            .arg(script)
            .env("PYTHONNOUSERSITE", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn secret_crypto.py");
        let stdin = child.stdin.take().expect("crypto stdin");
        let stdout = BufReader::new(child.stdout.take().expect("crypto stdout"));
        Self {
            child,
            stdin,
            stdout,
        }
    }

    fn call(&mut self, req: &Value) -> Value {
        writeln!(self.stdin, "{req}").expect("write crypto request");
        self.stdin.flush().expect("flush crypto request");
        let mut line = String::new();
        self.stdout.read_line(&mut line).expect("read crypto reply");
        serde_json::from_str(&line).unwrap_or_else(|_| serde_json::json!({"error": line}))
    }
}

impl Drop for CryptoHelper {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn matching_items(
    state: &Arc<Mutex<ServiceState>>,
    attributes: &HashMap<String, String>,
) -> Vec<OwnedObjectPath> {
    let state = state.lock().expect("secret state");
    state
        .items
        .values()
        .filter(|item| {
            attributes
                .iter()
                .all(|(k, v)| item.attributes.get(k) == Some(v))
        })
        .map(|item| owned_path(&item.path))
        .collect()
}

fn owned_path(path: &str) -> OwnedObjectPath {
    OwnedObjectPath::try_from(path.to_string()).expect("object path")
}

fn input_bytes(value: &ZValue<'_>) -> zbus::fdo::Result<Vec<u8>> {
    if let Ok(bytes) = Vec::<u8>::try_from(value.clone()) {
        return Ok(bytes);
    }
    let array: Array<'_> = value
        .clone()
        .try_into()
        .map_err(|err: zbus::zvariant::Error| zbus::fdo::Error::InvalidArgs(err.to_string()))?;
    let mut out = Vec::new();
    for item in array.iter() {
        let byte: u8 = item
            .try_into()
            .map_err(|err: zbus::zvariant::Error| zbus::fdo::Error::InvalidArgs(err.to_string()))?;
        out.push(byte);
    }
    Ok(out)
}

fn value_as_str_map(value: &ZValue<'_>) -> Option<HashMap<String, String>> {
    let dict: zbus::zvariant::Dict<'_, '_> = value.clone().try_into().ok()?;
    let mut out = HashMap::new();
    for (key, val) in dict.iter() {
        let key: String = key.try_into().ok()?;
        let val: String = val.try_into().ok()?;
        out.insert(key, val);
    }
    Some(out)
}

fn decode_hex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok())
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

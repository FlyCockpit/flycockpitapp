//! The sealed-value-only credential compartment.
//!
//! Project and Global literals live here, **not** in the generic named-secret
//! namespace of [`crate::credentials::CredentialStore`]. Keeping them in a
//! separate file with a separate API is what makes the non-enumeration claim
//! structural rather than conventional: there is no list, count, prefix,
//! existence, status, debug, doctor, or export path into this compartment.
//! The entire read surface is one exact-key lookup.
//!
//! Keys are random opaque 32-byte values drawn from the OS CSPRNG. A key is a
//! *locator*, never key material and never derived from the literal, so
//! holding every key in the database still reveals nothing about any literal's
//! content, length, or encoding — and guessing one is a 256-bit search.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use rand::Rng;

/// Opaque exact key length in bytes.
pub const SEALED_COMPARTMENT_KEY_BYTES: usize = 32;

/// Cap on the best-effort overwrite of an orphaned temp file.
const MAX_SWEEP_OVERWRITE_BYTES: u64 = 4 * 1024 * 1024;

/// Exclusive-create lock retry budget (non-Unix). Roughly five seconds total.
#[cfg(not(unix))]
const SEALED_LOCK_ATTEMPTS: u32 = 100;
/// Delay between exclusive-create lock attempts (non-Unix).
#[cfg(not(unix))]
const SEALED_LOCK_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(50);

/// A random opaque exact key into the sealed compartment.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SealedCompartmentKey(String);

impl SealedCompartmentKey {
    /// Draw a fresh locator from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; SEALED_COMPARTMENT_KEY_BYTES];
        rand::rng().fill_bytes(&mut bytes);
        let hex = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Self(hex)
    }

    pub fn parse(raw: &str) -> Result<Self> {
        if raw.len() != SEALED_COMPARTMENT_KEY_BYTES * 2
            || !raw.bytes().all(|b| b.is_ascii_hexdigit())
        {
            bail!(
                "sealed compartment key must be {SEALED_COMPARTMENT_KEY_BYTES} hex-encoded bytes"
            );
        }
        Ok(Self(raw.to_ascii_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A locator is a capability handle; never print it.
impl fmt::Debug for SealedCompartmentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SealedCompartmentKey(<locator>)")
    }
}

/// A resolved sealed literal.
///
/// Not `Debug`-printable, not `Display`, not `Serialize`, not `Clone`. The one
/// way to read it is [`SealedLiteralHandle::expose`], which only exists for
/// the duration of a compiled host action's `invoke` call.
pub struct SealedLiteral {
    /// Held as bytes rather than a `String` so `Drop` can zero the buffer in
    /// place without `unsafe`. The source `String`'s allocation is moved in,
    /// so no unscrubbed copy is left behind.
    bytes: Box<[u8]>,
}

impl SealedLiteral {
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            bytes: value.into().into_bytes().into_boxed_slice(),
        }
    }

    /// Borrow this literal for the duration of one host-action invocation.
    pub fn handle(&self) -> SealedLiteralHandle<'_> {
        SealedLiteralHandle {
            literal: self.as_str(),
        }
    }

    /// Crate-internal read, used by redaction registration and by the
    /// non-derivation guard. Not reachable from a tool or a model.
    pub(crate) fn expose_for_redaction(&self) -> &str {
        self.as_str()
    }

    fn as_str(&self) -> &str {
        // Constructed from a `String`, so this is always valid UTF-8.
        std::str::from_utf8(&self.bytes).unwrap_or_default()
    }
}

impl fmt::Debug for SealedLiteral {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SealedLiteral(<sealed>)")
    }
}

impl Drop for SealedLiteral {
    fn drop(&mut self) {
        // Best-effort scrub so a freed allocation does not linger in the heap
        // still holding a live literal.
        self.bytes.fill(0);
    }
}

/// A borrow of a sealed literal, valid only inside one host-action call.
///
/// This is the entire "opaque host-action interface" a compiled action sees.
/// It is not `Clone`, not `Copy`, and carries a lifetime, so an action cannot
/// stash the literal for later or hand it to anything outside its own call.
pub struct SealedLiteralHandle<'a> {
    literal: &'a str,
}

impl SealedLiteralHandle<'_> {
    /// The single raw-custody read point for a compiled host action.
    pub fn expose(&self) -> &str {
        self.literal
    }
}

impl fmt::Debug for SealedLiteralHandle<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SealedLiteralHandle(<sealed>)")
    }
}

/// Default compartment path: `$XDG_STATE_HOME/cockpit/sealed-compartment.json`.
///
/// A sibling of `credentials.json`, never a section inside it — a shared file
/// would put sealed literals back into the generic named-secret namespace that
/// redaction and diagnostics enumerate.
pub fn default_compartment_path() -> Option<PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_STATE_HOME")
        && !xdg.trim().is_empty()
    {
        return Some(PathBuf::from(xdg).join("cockpit/sealed-compartment.json"));
    }
    let home = dirs::home_dir()?;
    Some(home.join(".local/state/cockpit/sealed-compartment.json"))
}

/// The sealed-value-only compartment.
///
/// Every method is exact-key. There is intentionally no `len`, `is_empty`,
/// `keys`, `iter`, `contains`, `count`, `prefix`, `status`, or `export`.
#[derive(Clone)]
pub struct SealedCompartment {
    path: PathBuf,
}

impl SealedCompartment {
    pub fn at(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn open_default() -> Result<Self> {
        let path =
            default_compartment_path().context("could not locate $HOME for sealed compartment")?;
        Ok(Self::at(path))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Store a literal under an exact locator. Idempotent by locator, so a
    /// resumed saga may re-run it safely.
    pub(crate) fn put(&self, key: &SealedCompartmentKey, literal: &SealedLiteral) -> Result<()> {
        let _guard = self.lock_exclusive()?;
        let mut entries = self.load()?;
        entries.insert(
            key.as_str().to_string(),
            literal.expose_for_redaction().to_string(),
        );
        self.store(&entries)
    }

    /// Resolve one literal by exact locator.
    ///
    /// A miss is `None` — indistinguishable from every other miss, and callers
    /// fold it into the single content-free denial rather than branching on it.
    pub(crate) fn get_exact(&self, key: &SealedCompartmentKey) -> Result<Option<SealedLiteral>> {
        let _guard = self.lock_exclusive()?;
        let entries = self.load()?;
        Ok(entries.get(key.as_str()).map(SealedLiteral::new))
    }

    /// Reclaim one locator. Idempotent, so saga cleanup may re-run it.
    pub(crate) fn remove(&self, key: &SealedCompartmentKey) -> Result<()> {
        let _guard = self.lock_exclusive()?;
        let mut entries = self.load()?;
        if entries.remove(key.as_str()).is_some() {
            self.store(&entries)?;
        }
        Ok(())
    }

    /// Remove orphaned temp files left by a crash between write and rename.
    ///
    /// A temp file holds the **whole compartment**, including a staged
    /// literal, so a crash in that window strands raw plaintext that saga
    /// reclamation never sees — sagas track map locators, not temp files.
    ///
    /// Safe to run because it holds the exclusive lock: any writer holds that
    /// lock across create-and-rename, so every temp file visible here belongs
    /// to a dead process. Only names matching this compartment's strict
    /// `<basename>.<pid>.<64 hex>.tmp` pattern are touched.
    pub(crate) fn reclaim_stale_temporaries(&self) -> Result<usize> {
        let _guard = self.lock_exclusive()?;
        self.sweep_temporaries()
    }

    /// The sweep itself, assuming the caller already holds the lock.
    fn sweep_temporaries(&self) -> Result<usize> {
        let Some(parent) = self.path.parent() else {
            return Ok(0);
        };
        let base = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("sealed-compartment.json");
        let entries = match std::fs::read_dir(parent) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(error).context("scanning for stale sealed temporaries"),
        };
        let mut reclaimed = 0usize;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if !is_compartment_temp_name(name, base) {
                continue;
            }
            let path = entry.path();
            // Best-effort overwrite before unlinking. On a copy-on-write or
            // log-structured filesystem this does not guarantee the old blocks
            // are gone, so it is a mitigation and not a shred.
            if let Ok(meta) = std::fs::metadata(&path)
                && let Ok(mut file) = std::fs::OpenOptions::new().write(true).open(&path)
            {
                // Bounded: a compartment temp is small, and a corrupt length
                // must not turn cleanup into a huge allocation.
                let len = meta.len().min(MAX_SWEEP_OVERWRITE_BYTES) as usize;
                let _ = file.write_all(&vec![0u8; len]);
                let _ = file.sync_all();
            }
            if std::fs::remove_file(&path).is_ok() {
                reclaimed += 1;
            }
        }
        Ok(reclaimed)
    }

    /// Take a cross-process exclusive lock for one read-modify-write.
    ///
    /// Without this, two concurrent creates both read `{}` and the second
    /// `rename` silently discards the first literal — leaving a committed,
    /// resolvable record whose plaintext is gone, failing forever behind the
    /// content-free denial. Silent loss of a sealed value is not an acceptable
    /// degradation on any platform, so neither platform path is a no-op.
    ///
    /// The lock lives on a **sidecar** file, never on the compartment itself:
    /// the compartment is replaced by `rename`, which would detach a lock held
    /// on the old inode.
    ///
    /// This blocks the calling thread. Compartment access is Owner lifecycle
    /// work and is already synchronous file I/O, so it is never on a hot path.
    #[cfg(unix)]
    fn lock_exclusive(&self) -> Result<SealedCompartmentGuard> {
        let lock_path = self.prepare_lock_path()?;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .context("opening sealed compartment lock")?;
        restrict_handle_to_owner(&file)?;
        // SAFETY: `file` is a live descriptor for the duration of the call.
        let rc = unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&file), libc::LOCK_EX) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error()).context("locking sealed compartment");
        }
        Ok(SealedCompartmentGuard { _file: file })
    }

    /// Windows has no `flock`. An **atomic exclusive create** is the primitive
    /// that is available everywhere, so the lock is the existence of the
    /// sidecar file itself, removed when the guard drops.
    ///
    /// This deliberately **fails closed**: if the lock cannot be taken within
    /// the bounded retry window the write is refused with an error, rather
    /// than proceeding into a last-writer-wins race that would silently
    /// destroy a sealed value. A lock file left by a crashed process therefore
    /// surfaces as a loud, actionable failure instead of silent data loss.
    #[cfg(not(unix))]
    fn lock_exclusive(&self) -> Result<SealedCompartmentGuard> {
        let lock_path = self.prepare_lock_path()?;
        for attempt in 0..SEALED_LOCK_ATTEMPTS {
            match std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&lock_path)
            {
                Ok(file) => {
                    restrict_handle_to_owner(&file)?;
                    return Ok(SealedCompartmentGuard {
                        _file: file,
                        lock_path,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    if attempt + 1 < SEALED_LOCK_ATTEMPTS {
                        std::thread::sleep(SEALED_LOCK_RETRY_DELAY);
                    }
                }
                Err(error) => return Err(error).context("creating sealed compartment lock"),
            }
        }
        bail!(
            "could not acquire the sealed compartment lock at {}; refusing to write rather than \
             race a concurrent writer. If no other Cockpit process is running, remove that file.",
            lock_path.display()
        )
    }

    /// Ensure the compartment directory exists and return the sidecar path.
    fn prepare_lock_path(&self) -> Result<PathBuf> {
        let parent = self
            .path
            .parent()
            .context("sealed compartment path has no parent directory")?;
        std::fs::create_dir_all(parent).context("creating sealed compartment directory")?;
        restrict_to_owner(parent, true)?;
        Ok(self.path.with_extension("lock"))
    }

    fn load(&self) -> Result<BTreeMap<String, String>> {
        match std::fs::read(&self.path) {
            Ok(bytes) if bytes.is_empty() => Ok(BTreeMap::new()),
            Ok(bytes) => {
                serde_json::from_slice(&bytes).context("parsing sealed compartment contents")
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(error) => Err(error).context("reading sealed compartment"),
        }
    }

    fn store(&self, entries: &BTreeMap<String, String>) -> Result<()> {
        let parent = self
            .path
            .parent()
            .context("sealed compartment path has no parent directory")?;
        std::fs::create_dir_all(parent).context("creating sealed compartment directory")?;
        restrict_to_owner(parent, true)?;

        // We hold the lock, so any temp present now is a crashed writer's.
        self.sweep_temporaries()?;

        let serialized =
            serde_json::to_vec_pretty(entries).context("serializing sealed compartment")?;
        // A per-writer temp name created with `create_new`, so one writer can
        // never publish another's half-written bytes and a stale temp from a
        // crashed process is never adopted.
        let unique = format!(
            "{}.{}.{}.tmp",
            self.path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("sealed-compartment.json"),
            std::process::id(),
            SealedCompartmentKey::generate().as_str()
        );
        let temp = parent.join(unique);
        let write = (|| -> Result<()> {
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temp)
                .context("creating sealed compartment")?;
            restrict_handle_to_owner(&file)?;
            file.write_all(&serialized)
                .context("writing sealed compartment")?;
            file.sync_all().context("syncing sealed compartment")?;
            Ok(())
        })();
        if let Err(error) = write {
            let _ = std::fs::remove_file(&temp);
            return Err(error);
        }
        if let Err(error) = std::fs::rename(&temp, &self.path) {
            let _ = std::fs::remove_file(&temp);
            return Err(error).context("replacing sealed compartment");
        }
        restrict_to_owner(&self.path, false)?;
        Ok(())
    }
}

/// Does `name` match this compartment's strict temp pattern —
/// `<basename>.<pid digits>.<64 lowercase hex>.tmp`?
///
/// Deliberately strict: a loose `*.tmp` glob in a shared state directory would
/// delete other programs' files.
fn is_compartment_temp_name(name: &str, base: &str) -> bool {
    let Some(rest) = name.strip_prefix(base) else {
        return false;
    };
    let Some(rest) = rest.strip_prefix('.') else {
        return false;
    };
    let Some(rest) = rest.strip_suffix(".tmp") else {
        return false;
    };
    let Some((pid, locator)) = rest.split_once('.') else {
        return false;
    };
    !pid.is_empty()
        && pid.bytes().all(|b| b.is_ascii_digit())
        && locator.len() == SEALED_COMPARTMENT_KEY_BYTES * 2
        && locator.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Holds the compartment's exclusive lock for one read-modify-write.
struct SealedCompartmentGuard {
    _file: std::fs::File,
    /// The sidecar path to unlink on drop. Only the exclusive-create lock
    /// needs this; `flock` releases when the descriptor closes.
    #[cfg(not(unix))]
    lock_path: PathBuf,
}

/// Releasing the exclusive-create lock means removing the file.
#[cfg(not(unix))]
impl Drop for SealedCompartmentGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.lock_path);
    }
}

/// Compartment contents are never listed, so `Debug` shows only the location.
impl fmt::Debug for SealedCompartment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedCompartment")
            .field("path", &self.path)
            .finish()
    }
}

#[cfg(unix)]
fn restrict_to_owner(path: &Path, directory: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if directory { 0o700 } else { 0o600 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .context("restricting sealed compartment permissions")
}

#[cfg(not(unix))]
fn restrict_to_owner(_path: &Path, _directory: bool) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn restrict_handle_to_owner(file: &std::fs::File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .context("restricting sealed compartment file permissions")
}

#[cfg(not(unix))]
fn restrict_handle_to_owner(_file: &std::fs::File) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locators_are_opaque_random_and_never_printed() {
        let a = SealedCompartmentKey::generate();
        let b = SealedCompartmentKey::generate();
        assert_ne!(a, b);
        assert_eq!(a.as_str().len(), SEALED_COMPARTMENT_KEY_BYTES * 2);
        assert_eq!(format!("{a:?}"), "SealedCompartmentKey(<locator>)");
        assert!(SealedCompartmentKey::parse("short").is_err());
        assert_eq!(SealedCompartmentKey::parse(a.as_str()).unwrap(), a);
    }

    /// A crash between compartment write and rename strands a temp file that
    /// holds the whole compartment, staged literal included. No saga
    /// references it, so recovery has to find it by pattern.
    #[test]
    fn a_crash_between_write_and_rename_leaves_no_orphaned_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sealed-compartment.json");
        let compartment = SealedCompartment::at(path.clone());
        let key = SealedCompartmentKey::generate();
        compartment
            .put(&key, &SealedLiteral::new("live-compartment-literal"))
            .unwrap();

        // Simulate the crash: a temp file in this compartment's exact naming
        // pattern, holding raw plaintext, referenced by nothing.
        let orphan = dir.path().join(format!(
            "sealed-compartment.json.4242.{}.tmp",
            SealedCompartmentKey::generate().as_str()
        ));
        std::fs::write(&orphan, r#"{"aa":"stranded-plaintext-secret"}"#).unwrap();

        // Files that merely end in .tmp are somebody else's and must survive:
        // this runs in a shared state directory.
        let decoy_other = dir.path().join("something-else.tmp");
        std::fs::write(&decoy_other, "not ours").unwrap();
        let decoy_shape = dir.path().join("sealed-compartment.json.notapid.zz.tmp");
        std::fs::write(&decoy_shape, "not our shape").unwrap();

        let reclaimed = compartment.reclaim_stale_temporaries().unwrap();
        assert_eq!(reclaimed, 1, "exactly the orphan is reclaimed");
        assert!(!orphan.exists(), "stranded plaintext must not survive");
        assert!(decoy_other.exists(), "another program's temp is untouched");
        assert!(decoy_shape.exists(), "a non-matching name is untouched");

        // The live compartment is intact.
        assert_eq!(
            compartment
                .get_exact(&key)
                .unwrap()
                .unwrap()
                .handle()
                .expose(),
            "live-compartment-literal"
        );
    }

    #[test]
    fn temp_name_pattern_is_strict() {
        let base = "sealed-compartment.json";
        let hex = SealedCompartmentKey::generate().as_str().to_string();
        assert!(is_compartment_temp_name(
            &format!("{base}.17.{hex}.tmp"),
            base
        ));
        for bad in [
            format!("{base}.tmp"),
            format!("{base}.17.{hex}"),
            format!("{base}.pid.{hex}.tmp"),
            format!("{base}.17.nothex.tmp"),
            format!("other.17.{hex}.tmp"),
            format!("{base}.17.{}.tmp", &hex[..10]),
        ] {
            assert!(
                !is_compartment_temp_name(&bad, base),
                "must not match `{bad}`"
            );
        }
    }

    #[test]
    fn exact_lookup_is_the_only_read_and_literals_never_render() {
        let dir = tempfile::tempdir().unwrap();
        let compartment = SealedCompartment::at(dir.path().join("sealed-compartment.json"));
        let key = SealedCompartmentKey::generate();
        let other = SealedCompartmentKey::generate();
        compartment
            .put(&key, &SealedLiteral::new("high-entropy-literal-value"))
            .unwrap();

        let found = compartment.get_exact(&key).unwrap().unwrap();
        assert_eq!(found.handle().expose(), "high-entropy-literal-value");
        assert_eq!(format!("{found:?}"), "SealedLiteral(<sealed>)");
        assert_eq!(
            format!("{:?}", found.handle()),
            "SealedLiteralHandle(<sealed>)"
        );
        assert!(compartment.get_exact(&other).unwrap().is_none());

        compartment.remove(&key).unwrap();
        assert!(compartment.get_exact(&key).unwrap().is_none());
        // Removing an absent locator is a no-op, not an error or a signal.
        compartment.remove(&key).unwrap();
    }
}

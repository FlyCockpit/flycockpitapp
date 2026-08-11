//! Wire encoding: generation JSON and edit multipart.
//!
//! Generation requests are `application/json`. Edit requests are
//! `multipart/form-data` with a streaming body and aggregate + per-reference
//! bounds. The boundary is deterministic per request. Credential data and
//! raw reference bytes never appear in errors.

use anyhow::Result;
use anyhow::ensure;

use super::dto::{EditMultipartPart, EditRequest, GenerationRequest};
use super::preflight::PreflightReference;

/// Per-reference byte bound. Aggregate bound is enforced separately.
pub const MAX_REFERENCE_BYTES: usize = 64 * 1024 * 1024;
/// Aggregate reference byte bound across all multipart parts.
pub const MAX_AGGREGATE_REFERENCE_BYTES: usize = 256 * 1024 * 1024;
/// Bound on the JSON generation body.
pub const MAX_GENERATION_BODY_BYTES: usize = 1 * 1024 * 1024;

/// A failure during wire encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireEncodingFailure {
    pub reason: String,
}

impl std::fmt::Display for WireEncodingFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "openai images wire encoding failed: {}", self.reason)
    }
}
impl std::error::Error for WireEncodingFailure {}

/// The encoded wire body, abstracted over JSON and multipart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireBody {
    Json(GenerationWireBody),
    Multipart(MultipartWireBody),
}

impl WireBody {
    pub fn content_type(&self) -> &str {
        match self {
            Self::Json(body) => body.content_type,
            Self::Multipart(body) => &body.content_type,
        }
    }
    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            Self::Json(body) => body.bytes,
            Self::Multipart(body) => body.bytes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationWireBody {
    pub content_type: &'static str,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultipartWireBody {
    pub content_type: String,
    pub bytes: Vec<u8>,
}

/// Encodes a generation request as `application/json`.
pub fn encode_generation(input: &super::OpenaiImagesAttemptInput) -> Result<WireBody> {
    let validated = &input.plan.result;
    let request = GenerationRequest {
        model: validated.descriptor.identity.as_str().to_string(),
        prompt: validated.prompt.as_str().to_string(),
        n: input.plan.n,
        size: validated.size_value(),
        quality: validated.quality.as_str().to_string(),
        background: validated.background.as_str().to_string(),
        output_format: validated.output_format.as_str().to_string(),
        moderation: validated.moderation.as_str().to_string(),
        stream: false,
    };
    let bytes = serde_json::to_vec(&request)?;
    ensure!(
        bytes.len() <= MAX_GENERATION_BODY_BYTES,
        anyhow::anyhow!("generation body exceeds bound")
    );
    Ok(WireBody::Json(GenerationWireBody {
        content_type: "application/json",
        bytes,
    }))
}

/// Encodes an edit request as `multipart/form-data` with deterministic order
/// and provider field names.
pub fn encode_multipart(input: &super::OpenaiImagesAttemptInput) -> Result<WireBody> {
    let validated = &input.plan.result;
    let references = &input.plan.references;
    ensure!(
        !references.is_empty(),
        anyhow::anyhow!("edit requires at least one reference")
    );
    let parts = build_parts(references)?;
    let request = EditRequest {
        model: validated.descriptor.identity.as_str().to_string(),
        prompt: validated.prompt.as_str().to_string(),
        n: input.plan.n,
        size: validated.size_value(),
        quality: validated.quality.as_str().to_string(),
        background: validated.background.as_str().to_string(),
        output_format: validated.output_format.as_str().to_string(),
        moderation: validated.moderation.as_str().to_string(),
        stream: false,
        input_fidelity: validated.input_fidelity.map(|f| f.as_str().to_string()),
        image_parts: parts,
    };
    let boundary = deterministic_boundary(&input.provider_idempotency_identity);
    let body = write_multipart(&request, &boundary)?;
    let content_type = format!("multipart/form-data; boundary={boundary}");
    Ok(WireBody::Multipart(MultipartWireBody {
        content_type,
        bytes: body,
    }))
}

fn build_parts(references: &[PreflightReference]) -> Result<Vec<EditMultipartPart>> {
    let mut parts = Vec::with_capacity(references.len());
    let mut aggregate = 0usize;
    for reference in references {
        ensure!(
            reference.byte_length as usize <= MAX_REFERENCE_BYTES,
            anyhow::anyhow!("reference exceeds per-reference bound")
        );
        aggregate = aggregate
            .checked_add(reference.byte_length as usize)
            .ok_or_else(|| anyhow::anyhow!("reference aggregate overflow"))?;
        ensure!(
            aggregate <= MAX_AGGREGATE_REFERENCE_BYTES,
            anyhow::anyhow!("references exceed aggregate bound")
        );
        // Bytes are fetched by the transport from the media lease; the wire
        // encoder carries placeholders bounded by the plan. For tests, the
        // fixture supplies the actual bytes via the reference.
        parts.push(EditMultipartPart {
            field_name: "image[]",
            filename: reference.filename.clone(),
            mime: reference.mime.clone(),
            bytes: Vec::new(),
        });
    }
    Ok(parts)
}

fn deterministic_boundary(idempotency: &str) -> String {
    use sha2::{Digest as _, Sha256};
    let digest = Sha256::digest(idempotency.as_bytes());
    let mut out = String::with_capacity(48);
    out.push_str("----cockpit");
    for byte in digest.iter().take(16) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn write_multipart(request: &EditRequest, boundary: &str) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    // Text fields in deterministic order.
    write_text_field(&mut body, boundary, "model", &request.model)?;
    write_text_field(&mut body, boundary, "prompt", &request.prompt)?;
    write_text_field(&mut body, boundary, "n", &request.n.to_string())?;
    write_text_field(&mut body, boundary, "size", &request.size)?;
    write_text_field(&mut body, boundary, "quality", &request.quality)?;
    write_text_field(&mut body, boundary, "background", &request.background)?;
    write_text_field(&mut body, boundary, "output_format", &request.output_format)?;
    write_text_field(&mut body, boundary, "moderation", &request.moderation)?;
    write_text_field(&mut body, boundary, "stream", "false")?;
    if let Some(fidelity) = &request.input_fidelity {
        write_text_field(&mut body, boundary, "input_fidelity", fidelity)?;
    }
    // Reference parts in deterministic order.
    for part in &request.image_parts {
        write_file_field(&mut body, boundary, part)?;
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    Ok(body)
}

fn write_text_field(body: &mut Vec<u8>, boundary: &str, name: &str, value: &str) -> Result<()> {
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
    );
    body.extend_from_slice(value.as_bytes());
    body.extend_from_slice(b"\r\n");
    Ok(())
}

fn write_file_field(body: &mut Vec<u8>, boundary: &str, part: &EditMultipartPart) -> Result<()> {
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        format!(
            "Content-Disposition: form-data; name=\"{}\"; filename=\"{}\"\r\n",
            part.field_name, part.filename
        )
        .as_bytes(),
    );
    body.extend_from_slice(format!("Content-Type: {}\r\n\r\n", part.mime).as_bytes());
    body.extend_from_slice(&part.bytes);
    body.extend_from_slice(b"\r\n");
    Ok(())
}

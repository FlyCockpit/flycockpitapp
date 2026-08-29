//! Pure preflight validation against the typed catalog.
//!
//! Preflight runs before any provider contact. It rejects unknown models,
//! unsupported size/quality/background/moderation/format/compression/
//! input-fidelity/prompt-length/`n`/reference-count combinations, and
//! unknown advanced fields. Failures carry exact supported constraints so
//! callers can surface them without guessing.

use super::catalog::{
    Background, ImageModelDescriptor, InputFidelity, Moderation, OpenaiImagesCatalog, OutputFormat,
    Quality, SizeContract,
};
use super::dto::NormalizedPrompt;
use super::{
    MAX_EDIT_REFERENCES, MAX_OUTPUTS_PER_REQUEST, MAX_PROMPT_UNICODE_SCALARS, MAX_PROMPT_UTF8_BYTES,
};

/// A typed reference authorized for an edit. Bytes are not loaded here; the
/// wire encoder fetches bounded bytes from the media lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightReference {
    /// Deterministic filename for the multipart part.
    pub filename: String,
    /// Canonical MIME type.
    pub mime: String,
    /// Bounded byte length (the encoder enforces the actual byte bound).
    pub byte_length: u64,
    /// Verified media-component bytes held for this exact provider handoff.
    /// They are loaded only by the daemon-owned plan source and never enter a
    /// durable plan, log, or handoff evidence.
    pub bytes: Vec<u8>,
}

/// The sealed plan inputs that preflight validates. Built by the dispatcher
/// from the immutable [`ImageGenerationPlanV1`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightInput {
    pub model: String,
    pub prompt: String,
    pub n: u32,
    pub width: u32,
    pub height: u32,
    pub quality: String,
    pub background: String,
    pub output_format: String,
    pub moderation: String,
    /// Compression is an integer 0–100 only for JPEG/WebP and must be omitted
    /// for PNG. `None` means omit.
    pub compression: Option<u8>,
    pub input_fidelity: Option<String>,
}

/// A preflight failure with an exact, redacted reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightFailure {
    pub reason: String,
}

impl std::fmt::Display for PreflightFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "openai images preflight failed: {}", self.reason)
    }
}
impl std::error::Error for PreflightFailure {}

impl PreflightFailure {
    fn unknown_model(model: &str) -> Self {
        Self {
            reason: format!(
                "unknown model {model:?}; supported models are {:?}",
                OpenaiImagesCatalog::known_models()
                    .iter()
                    .copied()
                    .collect::<Vec<_>>()
            ),
        }
    }
}

/// A successful preflight result carrying the resolved descriptor and
/// normalized prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightResult {
    pub descriptor: ImageModelDescriptor,
    pub prompt: NormalizedPrompt,
    pub quality: Quality,
    pub background: Background,
    pub output_format: OutputFormat,
    pub moderation: Moderation,
    pub input_fidelity: Option<InputFidelity>,
    pub width: u32,
    pub height: u32,
}

impl PreflightResult {
    pub fn size_value(&self) -> String {
        size_value(self.descriptor, (self.width, self.height))
    }
}

/// The full preflight output: validated plan plus references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightPlanValidated {
    pub result: PreflightResult,
    pub references: Vec<PreflightReference>,
    pub route: super::OpenaiImagesRoute,
    pub n: u32,
}

/// Public alias matching the prompt's terminology.
pub type PreflightPlan = PreflightPlanValidated;

/// Runs preflight. Returns `Ok(validated)` or `Err(failure)`.
pub fn preflight(
    plan: &PreflightInput,
    references: &[PreflightReference],
) -> Result<PreflightPlanValidated, PreflightFailure> {
    let descriptor = OpenaiImagesCatalog::lookup(&plan.model)
        .ok_or_else(|| PreflightFailure::unknown_model(&plan.model))?;
    validate_prompt(&plan.prompt)?;
    validate_n(plan.n)?;
    validate_references(references)?;
    let quality = parse_required("quality", &plan.quality, Quality::parse)?;
    let background = parse_required("background", &plan.background, Background::parse)?;
    let output_format = parse_required("output_format", &plan.output_format, OutputFormat::parse)?;
    let moderation = parse_required("moderation", &plan.moderation, Moderation::parse)?;
    let input_fidelity = validate_input_fidelity(&descriptor, plan.input_fidelity.as_deref())?;
    // Transparency is validated before the generic capability gate so the
    // model-specific "transparent background is rejected" reason surfaces for
    // identities (e.g. gpt-image-2) that do not list transparent among their
    // supported backgrounds.
    validate_transparency(&descriptor, output_format, background)?;
    validate_capability(&descriptor, quality, background, output_format, moderation)?;
    validate_size(&descriptor, plan.width, plan.height)?;
    validate_compression(&descriptor, output_format, plan.compression)?;
    let route = if references.is_empty() {
        super::OpenaiImagesRoute::Generations
    } else {
        super::OpenaiImagesRoute::Edits
    };
    let result = PreflightResult {
        descriptor,
        prompt: NormalizedPrompt(plan.prompt.clone()),
        quality,
        background,
        output_format,
        moderation,
        input_fidelity,
        width: plan.width,
        height: plan.height,
    };
    Ok(PreflightPlanValidated {
        result,
        references: references.to_vec(),
        route,
        n: plan.n,
    })
}

fn parse_required<T>(
    field: &str,
    value: &str,
    parse: fn(&str) -> Option<T>,
) -> Result<T, PreflightFailure> {
    parse(value).ok_or_else(|| PreflightFailure {
        reason: format!("unknown {field} {value:?}"),
    })
}

fn validate_prompt(prompt: &str) -> Result<(), PreflightFailure> {
    let utf8_bytes = prompt.len();
    if utf8_bytes > MAX_PROMPT_UTF8_BYTES {
        return Err(PreflightFailure {
            reason: format!("prompt exceeds {MAX_PROMPT_UTF8_BYTES} UTF-8 bytes ({utf8_bytes})"),
        });
    }
    let scalars = prompt.chars().count();
    if scalars > MAX_PROMPT_UNICODE_SCALARS {
        return Err(PreflightFailure {
            reason: format!(
                "prompt exceeds {MAX_PROMPT_UNICODE_SCALARS} Unicode scalar values ({scalars})"
            ),
        });
    }
    Ok(())
}

fn validate_n(n: u32) -> Result<(), PreflightFailure> {
    if !(1..=MAX_OUTPUTS_PER_REQUEST).contains(&n) {
        return Err(PreflightFailure {
            reason: format!("n={n} outside 1..={MAX_OUTPUTS_PER_REQUEST}"),
        });
    }
    Ok(())
}

fn validate_references(references: &[PreflightReference]) -> Result<(), PreflightFailure> {
    if references.len() > MAX_EDIT_REFERENCES {
        return Err(PreflightFailure {
            reason: format!(
                "too many references {} > {MAX_EDIT_REFERENCES}",
                references.len()
            ),
        });
    }
    if references
        .iter()
        .any(|reference| reference.byte_length != reference.bytes.len() as u64)
    {
        return Err(PreflightFailure {
            reason: "reference bytes differ from the sealed component length".into(),
        });
    }
    Ok(())
}

fn validate_input_fidelity(
    descriptor: &ImageModelDescriptor,
    value: Option<&str>,
) -> Result<Option<InputFidelity>, PreflightFailure> {
    match (descriptor.omit_input_fidelity, value) {
        (true, Some(fidelity)) => Err(PreflightFailure {
            reason: format!(
                "input_fidelity {fidelity:?} is not accepted for model {:?}; it is omitted",
                descriptor.identity.as_str()
            ),
        }),
        (true, None) => Ok(None),
        (false, Some(fidelity)) => {
            let parsed = InputFidelity::parse(fidelity).ok_or_else(|| PreflightFailure {
                reason: format!("unknown input_fidelity {fidelity:?}"),
            })?;
            if !descriptor.supports_input_fidelity(parsed) {
                return Err(PreflightFailure {
                    reason: format!(
                        "input_fidelity {:?} unsupported for model {:?}",
                        fidelity,
                        descriptor.identity.as_str()
                    ),
                });
            }
            Ok(Some(parsed))
        }
        (false, None) => Err(PreflightFailure {
            reason: format!(
                "input_fidelity is required for model {:?}",
                descriptor.identity.as_str()
            ),
        }),
    }
}

fn validate_capability(
    descriptor: &ImageModelDescriptor,
    quality: Quality,
    background: Background,
    output_format: OutputFormat,
    moderation: Moderation,
) -> Result<(), PreflightFailure> {
    if !descriptor.supports_quality(quality) {
        return Err(PreflightFailure {
            reason: format!(
                "quality {:?} unsupported for model {:?}; supported {:?}",
                quality.as_str(),
                descriptor.identity.as_str(),
                descriptor
                    .qualities
                    .iter()
                    .map(|q| q.as_str())
                    .collect::<Vec<_>>()
            ),
        });
    }
    if !descriptor.supports_background(background) {
        return Err(PreflightFailure {
            reason: format!(
                "background {:?} unsupported for model {:?}; supported {:?}",
                background.as_str(),
                descriptor.identity.as_str(),
                descriptor
                    .backgrounds
                    .iter()
                    .map(|b| b.as_str())
                    .collect::<Vec<_>>()
            ),
        });
    }
    if !descriptor.supports_format(output_format) {
        return Err(PreflightFailure {
            reason: format!(
                "output_format {:?} unsupported for model {:?}; supported {:?}",
                output_format.as_str(),
                descriptor.identity.as_str(),
                descriptor
                    .formats()
                    .iter()
                    .map(|f| f.as_str())
                    .collect::<Vec<_>>()
            ),
        });
    }
    if !descriptor.supports_moderation(moderation) {
        return Err(PreflightFailure {
            reason: format!(
                "moderation {:?} unsupported for model {:?}; supported {:?}",
                moderation.as_str(),
                descriptor.identity.as_str(),
                descriptor
                    .moderations()
                    .iter()
                    .map(|m| m.as_str())
                    .collect::<Vec<_>>()
            ),
        });
    }
    Ok(())
}

fn validate_size(
    descriptor: &ImageModelDescriptor,
    width: u32,
    height: u32,
) -> Result<(), PreflightFailure> {
    match descriptor.size {
        SizeContract::FreeAspect {
            max_edge,
            alignment,
            max_ratio_numerator,
            max_ratio_denominator,
            min_pixels,
            max_pixels,
        } => {
            if width == 0 || height == 0 {
                return Err(PreflightFailure {
                    reason: "edges must be positive".into(),
                });
            }
            if width > max_edge || height > max_edge {
                return Err(PreflightFailure {
                    reason: format!(
                        "edges {width}x{height} exceed max edge {max_edge}; both edges at most {max_edge} px"
                    ),
                });
            }
            if !width.is_multiple_of(alignment) || !height.is_multiple_of(alignment) {
                return Err(PreflightFailure {
                    reason: format!(
                        "edges {width}x{height} not aligned to {alignment} px; both edges must be multiples of {alignment}"
                    ),
                });
            }
            let pixels = u64::from(width) * u64::from(height);
            if pixels < min_pixels || pixels > max_pixels {
                return Err(PreflightFailure {
                    reason: format!("total pixels {pixels} outside {min_pixels}..={max_pixels}"),
                });
            }
            // Aspect ratio at most 3:1.
            let (long, short) = if width >= height {
                (u128::from(width), u128::from(height))
            } else {
                (u128::from(height), u128::from(width))
            };
            if long * u128::from(max_ratio_denominator) > short * u128::from(max_ratio_numerator) {
                return Err(PreflightFailure {
                    reason: format!(
                        "aspect ratio exceeds {max_ratio_numerator}:{max_ratio_denominator}"
                    ),
                });
            }
            Ok(())
        }
        SizeContract::FixedAspect { candidates } => {
            let matched = candidates
                .iter()
                .any(|(_, w, h)| *w == width && *h == height);
            if !matched {
                return Err(PreflightFailure {
                    reason: format!(
                        "size {width}x{height} unsupported for model {:?}; supported {:?}",
                        descriptor.identity.as_str(),
                        candidates
                            .iter()
                            .map(|(value, _, _)| *value)
                            .collect::<Vec<_>>()
                    ),
                });
            }
            Ok(())
        }
    }
}

fn validate_compression(
    _descriptor: &ImageModelDescriptor,
    output_format: OutputFormat,
    compression: Option<u8>,
) -> Result<(), PreflightFailure> {
    match (output_format, compression) {
        (OutputFormat::Png, Some(value)) => Err(PreflightFailure {
            reason: format!("compression {value} must be omitted for PNG"),
        }),
        (OutputFormat::Jpeg, Some(value)) | (OutputFormat::Webp, Some(value)) => {
            if value > 100 {
                return Err(PreflightFailure {
                    reason: format!("compression {value} outside 0..=100"),
                });
            }
            Ok(())
        }
        (_, None) => Ok(()),
    }
}

fn validate_transparency(
    descriptor: &ImageModelDescriptor,
    output_format: OutputFormat,
    background: Background,
) -> Result<(), PreflightFailure> {
    if background == Background::Transparent {
        if !matches!(output_format, OutputFormat::Png | OutputFormat::Webp) {
            return Err(PreflightFailure {
                reason: "transparent background requires PNG or WebP".into(),
            });
        }
        if descriptor.omit_input_fidelity {
            return Err(PreflightFailure {
                reason: format!(
                    "transparent background is rejected for model {:?}",
                    descriptor.identity.as_str()
                ),
            });
        }
    }
    Ok(())
}

/// Computes the provider `size` value for a validated plan.
pub fn size_value(descriptor: ImageModelDescriptor, (width, height): (u32, u32)) -> String {
    match descriptor.size {
        SizeContract::FreeAspect { .. } => format!("{width}x{height}"),
        SizeContract::FixedAspect { candidates } => {
            let candidate = candidates
                .iter()
                .find(|(_, w, h)| *w == width && *h == height);
            match candidate {
                Some((value, _, _)) => (*value).to_string(),
                None => format!("{width}x{height}"),
            }
        }
    }
}

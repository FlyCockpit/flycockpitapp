//! Typed OpenAI Images model catalog with an explicit revision.
//!
//! The catalog is the single source of truth for which models, sizes,
//! qualities, backgrounds, formats, compression, moderation, and input
//! fidelities the adapter will serialize. Unknown or newly observed model
//! values are unavailable, not guessed or mapped to a similar model.
//! `gpt-image-1` is intentionally absent: official OpenAI guidance classifies
//! it as legacy compatibility only and pre-release Cockpit carries no legacy
//! compatibility role.

use std::collections::BTreeSet;

/// Catalog provenance: the verified documentation date.
pub const CATALOG_PROVENANCE_DATE: &str = "2026-08-04";

/// Monotonic catalog revision. Bumping this requires a fresh review.
pub const CATALOG_REVISION: u32 = 1;

/// The four checked-in catalog identities. The dated snapshot keeps its
/// identity distinct in plans, attempts, and evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum ImageModelIdentity {
    GptImage2,
    GptImage2Dated20260421,
    GptImage15,
    GptImage1Mini,
}

impl ImageModelIdentity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GptImage2 => "gpt-image-2",
            Self::GptImage2Dated20260421 => "gpt-image-2-2026-04-21",
            Self::GptImage15 => "gpt-image-1.5",
            Self::GptImage1Mini => "gpt-image-1-mini",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "gpt-image-2" => Some(Self::GptImage2),
            "gpt-image-2-2026-04-21" => Some(Self::GptImage2Dated20260421),
            "gpt-image-1.5" => Some(Self::GptImage15),
            "gpt-image-1-mini" => Some(Self::GptImage1Mini),
            _ => None,
        }
    }
}

/// Typed quality values. All four catalog entries support `auto`, `low`,
/// `medium`, `high`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum Quality {
    Auto,
    Low,
    Medium,
    High,
}

impl Quality {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "auto" => Some(Self::Auto),
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            _ => None,
        }
    }
}

/// Typed background values. Transparent requires PNG or WebP and is rejected
/// for both `gpt-image-2` identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum Background {
    Auto,
    Opaque,
    Transparent,
}

impl Background {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Opaque => "opaque",
            Self::Transparent => "transparent",
        }
    }
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "auto" => Some(Self::Auto),
            "opaque" => Some(Self::Opaque),
            "transparent" => Some(Self::Transparent),
            _ => None,
        }
    }
}

/// Typed moderation values. `auto` is the explicit adapter default and is
/// serialized; unknown moderation values fail preflight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum Moderation {
    Auto,
    Low,
}

impl Moderation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Low => "low",
        }
    }
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "auto" => Some(Self::Auto),
            "low" => Some(Self::Low),
            _ => None,
        }
    }
}

/// Typed output format. All four catalog entries support `png`, `jpeg`,
/// `webp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum OutputFormat {
    Png,
    Jpeg,
    Webp,
}

impl OutputFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Png => "png",
            Self::Jpeg => "jpeg",
            Self::Webp => "webp",
        }
    }
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "png" => Some(Self::Png),
            "jpeg" => Some(Self::Jpeg),
            "webp" => Some(Self::Webp),
            _ => None,
        }
    }
}

/// Typed edit input fidelity. `gpt-image-2` identities omit it (fixed high
/// provider behavior); `gpt-image-1.5` and `gpt-image-1-mini` accept `low` or
/// `high`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum InputFidelity {
    Low,
    High,
}

impl InputFidelity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::High => "high",
        }
    }
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "low" => Some(Self::Low),
            "high" => Some(Self::High),
            _ => None,
        }
    }
}

/// The size contract for a model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizeContract {
    /// `gpt-image-2` identities: both edges at most 3840 px and multiples of
    /// 16; aspect ratio at most 3:1; total pixels 655,360 through 8,294,400.
    FreeAspect {
        max_edge: u32,
        alignment: u32,
        max_ratio_numerator: u32,
        max_ratio_denominator: u32,
        min_pixels: u64,
        max_pixels: u64,
    },
    /// `gpt-image-1.5` / `gpt-image-1-mini`: `auto`, `1024x1024`,
    /// `1024x1536`, `1536x1024`.
    FixedAspect {
        candidates: &'static [(&'static str, u32, u32)],
    },
}

/// A typed model descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageModelDescriptor {
    pub identity: ImageModelIdentity,
    pub size: SizeContract,
    pub qualities: &'static [Quality],
    pub backgrounds: &'static [Background],
    pub input_fidelities: &'static [InputFidelity],
    /// `true` when edit input fidelity is omitted (fixed high provider
    /// behavior).
    pub omit_input_fidelity: bool,
}

impl ImageModelDescriptor {
    pub fn supports_quality(self, q: Quality) -> bool {
        self.qualities.iter().any(|value| *value == q)
    }
    pub fn supports_background(self, b: Background) -> bool {
        self.backgrounds.iter().any(|value| *value == b)
    }
    pub fn supports_format(self, f: OutputFormat) -> bool {
        self.formats().iter().any(|value| *value == f)
    }
    pub fn supports_moderation(self, m: Moderation) -> bool {
        self.moderations().iter().any(|value| *value == m)
    }
    pub fn supports_input_fidelity(self, f: InputFidelity) -> bool {
        self.input_fidelities.iter().any(|value| *value == f)
    }
    /// All four catalog entries support `png`, `jpeg`, `webp`.
    pub const fn formats(self) -> &'static [OutputFormat] {
        ALL_FORMATS
    }
    /// All four catalog entries support `auto` and `low`.
    pub const fn moderations(self) -> &'static [Moderation] {
        ALL_MODERATIONS
    }
}

const ALL_QUALITIES: &[Quality] = &[Quality::Auto, Quality::Low, Quality::Medium, Quality::High];
const ALL_MODERATIONS: &[Moderation] = &[Moderation::Auto, Moderation::Low];
const ALL_FORMATS: &[OutputFormat] = &[OutputFormat::Png, OutputFormat::Jpeg, OutputFormat::Webp];

const GPT_IMAGE_2_BACKGROUNDS: &[Background] = &[Background::Auto, Background::Opaque];
const GPT_IMAGE_15_BACKGROUNDS: &[Background] = &[
    Background::Auto,
    Background::Opaque,
    Background::Transparent,
];
const GPT_IMAGE_15_FIDELITIES: &[InputFidelity] = &[InputFidelity::Low, InputFidelity::High];
const FIXED_ASPECT_15: &[(&str, u32, u32)] = &[
    ("auto", 0, 0),
    ("1024x1024", 1024, 1024),
    ("1024x1536", 1024, 1536),
    ("1536x1024", 1536, 1024),
];

const GPT_IMAGE_2_DESCRIPTOR: ImageModelDescriptor = ImageModelDescriptor {
    identity: ImageModelIdentity::GptImage2,
    size: SizeContract::FreeAspect {
        max_edge: 3840,
        alignment: 16,
        max_ratio_numerator: 3,
        max_ratio_denominator: 1,
        min_pixels: 655_360,
        max_pixels: 8_294_400,
    },
    qualities: ALL_QUALITIES,
    backgrounds: GPT_IMAGE_2_BACKGROUNDS,
    input_fidelities: &[],
    omit_input_fidelity: true,
};

const GPT_IMAGE_2_DATED_DESCRIPTOR: ImageModelDescriptor = ImageModelDescriptor {
    identity: ImageModelIdentity::GptImage2Dated20260421,
    size: SizeContract::FreeAspect {
        max_edge: 3840,
        alignment: 16,
        max_ratio_numerator: 3,
        max_ratio_denominator: 1,
        min_pixels: 655_360,
        max_pixels: 8_294_400,
    },
    qualities: ALL_QUALITIES,
    backgrounds: GPT_IMAGE_2_BACKGROUNDS,
    input_fidelities: &[],
    omit_input_fidelity: true,
};

const GPT_IMAGE_15_DESCRIPTOR: ImageModelDescriptor = ImageModelDescriptor {
    identity: ImageModelIdentity::GptImage15,
    size: SizeContract::FixedAspect {
        candidates: FIXED_ASPECT_15,
    },
    qualities: ALL_QUALITIES,
    backgrounds: GPT_IMAGE_15_BACKGROUNDS,
    input_fidelities: GPT_IMAGE_15_FIDELITIES,
    omit_input_fidelity: false,
};

const GPT_IMAGE_1_MINI_DESCRIPTOR: ImageModelDescriptor = ImageModelDescriptor {
    identity: ImageModelIdentity::GptImage1Mini,
    size: SizeContract::FixedAspect {
        candidates: FIXED_ASPECT_15,
    },
    qualities: ALL_QUALITIES,
    backgrounds: GPT_IMAGE_15_BACKGROUNDS,
    input_fidelities: GPT_IMAGE_15_FIDELITIES,
    omit_input_fidelity: false,
};

/// The checked-in catalog. Lookup is exhaustive; unknown models are
/// unavailable.
#[derive(Debug, Clone, Copy)]
pub struct OpenaiImagesCatalog;

impl OpenaiImagesCatalog {
    pub const fn revision() -> u32 {
        CATALOG_REVISION
    }
    pub const fn provenance_date() -> &'static str {
        CATALOG_PROVENANCE_DATE
    }
    pub const fn descriptors() -> &'static [ImageModelDescriptor] {
        &[
            GPT_IMAGE_2_DESCRIPTOR,
            GPT_IMAGE_2_DATED_DESCRIPTOR,
            GPT_IMAGE_15_DESCRIPTOR,
            GPT_IMAGE_1_MINI_DESCRIPTOR,
        ]
    }
    pub fn lookup(model: &str) -> Option<ImageModelDescriptor> {
        Self::descriptors()
            .iter()
            .copied()
            .find(|descriptor| descriptor.identity.as_str() == model)
    }
    /// All known model names, for availability enumeration.
    pub fn known_models() -> BTreeSet<&'static str> {
        Self::descriptors()
            .iter()
            .map(|descriptor| descriptor.identity.as_str())
            .collect()
    }
}

#[cfg(test)]
impl ImageModelDescriptor {
    pub const fn gpt_image_2() -> Self {
        GPT_IMAGE_2_DESCRIPTOR
    }
    pub const fn gpt_image_2_dated() -> Self {
        GPT_IMAGE_2_DATED_DESCRIPTOR
    }
    pub const fn gpt_image_1_5() -> Self {
        GPT_IMAGE_15_DESCRIPTOR
    }
    pub const fn gpt_image_1_mini() -> Self {
        GPT_IMAGE_1_MINI_DESCRIPTOR
    }
}

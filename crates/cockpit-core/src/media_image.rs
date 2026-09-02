//! Shared bounded image pipeline: EXIF preflight, decode, crop, scale, PNG encode.
//!
//! Read-image, canonical media-storage derivatives, and screenshot processing
//! all go through this module. Callers pick an explicit [`ImageProfile`]; there
//! are no silent defaults that mix those settings.

use std::io::Cursor;

use anyhow::{Result, anyhow, bail, ensure};
use image::codecs::png::{CompressionType, FilterType};
use image::imageops::FilterType as ResizeFilter;
use image::metadata::Orientation;
use image::{
    ColorType, DynamicImage, ExtendedColorType, ImageDecoder as _, ImageEncoder, ImageFormat,
    ImageReader, Limits,
};

/// Pixel crop rectangle in **oriented-image** coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CropRect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

/// Explicit encode/decode/scale settings for one producer.
#[derive(Debug, Clone, Copy)]
pub struct ImageProfile {
    pub name: &'static str,
    pub max_input_bytes: usize,
    pub max_output_bytes: usize,
    pub max_width: Option<u32>,
    pub max_height: Option<u32>,
    pub max_pixels: Option<u64>,
    pub max_alloc: Option<u64>,
    pub png_compression: CompressionType,
    pub png_filter: FilterType,
    pub resize_filter: ResizeFilter,
    pub jpeg_quality: u8,
}

/// Maximum single RGBA allocation accepted by screenshot decode and resize
/// paths. Keep native computer zoom preflight on the same resource boundary as
/// the image pipeline that performs the allocation.
pub const SCREENSHOT_MAX_ALLOC_BYTES: u64 =
    crate::resource_limits::ResourceLimits::defaults().image_max_alloc_bytes;

impl ImageProfile {
    /// Read-image tool: 64 MiB in/out, Default/Adaptive PNG, Lanczos3 scale.
    pub fn read_image() -> Self {
        let limits = crate::resource_limits::ResourceLimits::defaults();
        Self {
            name: "read_image",
            max_input_bytes: limits.image_max_input_bytes,
            max_output_bytes: limits.image_max_output_bytes,
            max_width: Some(limits.image_max_width),
            max_height: Some(limits.image_max_height),
            max_pixels: Some(limits.image_max_pixels),
            max_alloc: Some(limits.image_max_alloc_bytes),
            png_compression: CompressionType::Default,
            png_filter: FilterType::Adaptive,
            resize_filter: ResizeFilter::Lanczos3,
            jpeg_quality: 90,
        }
    }

    /// Canonical storage derivatives: Level(6)/Paeth PNG, 8192 edge, 40M pixels.
    pub fn storage() -> Self {
        let limits = crate::resource_limits::ResourceLimits::defaults();
        Self {
            name: "storage",
            max_input_bytes: usize::MAX,
            max_output_bytes: usize::MAX,
            max_width: Some(limits.image_max_width),
            max_height: Some(limits.image_max_height),
            max_pixels: Some(limits.image_max_pixels),
            max_alloc: Some(limits.image_max_alloc_bytes),
            png_compression: CompressionType::Level(6),
            png_filter: FilterType::Paeth,
            resize_filter: ResizeFilter::Triangle,
            jpeg_quality: 90,
        }
    }

    /// Screenshot processing: nearest-neighbor resize.
    pub fn screenshot() -> Self {
        let limits = crate::resource_limits::ResourceLimits::defaults();
        Self {
            name: "screenshot",
            max_input_bytes: usize::MAX,
            max_output_bytes: usize::MAX,
            max_width: Some(limits.image_max_width),
            max_height: Some(limits.image_max_height),
            max_pixels: Some(limits.image_max_pixels),
            max_alloc: Some(SCREENSHOT_MAX_ALLOC_BYTES),
            png_compression: CompressionType::Default,
            png_filter: FilterType::Adaptive,
            resize_filter: ResizeFilter::Nearest,
            jpeg_quality: 90,
        }
    }

    /// Browser previews are bounded PNGs with a 256-pixel edge. An RGBA image
    /// at that bound is below 512 KiB even before compression.
    pub fn browser_thumbnail() -> Self {
        let limits = crate::resource_limits::ResourceLimits::defaults();
        Self {
            name: "browser_thumbnail",
            max_input_bytes: usize::MAX,
            max_output_bytes: 512 * 1024,
            max_width: Some(limits.image_max_width),
            max_height: Some(limits.image_max_height),
            max_pixels: Some(limits.image_max_pixels),
            max_alloc: Some(limits.image_max_alloc_bytes),
            png_compression: CompressionType::Level(6),
            png_filter: FilterType::Paeth,
            resize_filter: ResizeFilter::Triangle,
            jpeg_quality: 90,
        }
    }
}

/// Check the allocation required for an RGBA8 image before an image operation
/// is allowed to allocate it.
pub fn checked_rgba_allocation_bytes(
    width: u32,
    height: u32,
    profile: &ImageProfile,
) -> Result<usize> {
    let bytes = u64::from(width)
        .checked_mul(u64::from(height))
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or_else(|| anyhow!("resource_limit"))?;
    if profile.max_alloc.is_some_and(|limit| bytes > limit) {
        bail!("resource_limit");
    }
    usize::try_from(bytes).map_err(|_| anyhow!("resource_limit"))
}

pub fn browser_thumbnail(bytes: &[u8]) -> Result<(Vec<u8>, u32, u32)> {
    let profile = ImageProfile::browser_thumbnail();
    let decoded = decode_and_orient(bytes, &profile)?;
    let (width, height) = fit_dimensions(decoded.width(), decoded.height(), 256, 256)?;
    let scaled = scale(decoded, width, height, &profile);
    let encoded = encode_png(&scaled, &profile)?;
    Ok((encoded, width, height))
}

pub fn fit_dimensions(
    width: u32,
    height: u32,
    max_width: u32,
    max_height: u32,
) -> Result<(u32, u32)> {
    ensure!(
        width > 0 && height > 0 && max_width > 0 && max_height > 0,
        "invalid image dimensions"
    );
    let scale = (f64::from(max_width) / f64::from(width))
        .min(f64::from(max_height) / f64::from(height))
        .min(1.0);
    Ok((
        (f64::from(width) * scale).floor().max(1.0) as u32,
        (f64::from(height) * scale).floor().max(1.0) as u32,
    ))
}

/// Fail-closed EXIF orientation error. Stable spelling for callers and tests.
pub fn orientation_unsupported() -> anyhow::Error {
    anyhow!(
        "media_orientation_unsupported: EXIF orientation is malformed, truncated, or out of range"
    )
}

/// Read bounded orientation metadata from encoded bytes **before** full decode.
///
/// - No EXIF / no orientation tag → [`Orientation::NoTransforms`] (identity).
/// - Valid tag 1..=8 → [`Orientation::from_exif`].
/// - Malformed, truncated, or out-of-range EXIF → `media_orientation_unsupported`.
pub fn preflight_exif_orientation(bytes: &[u8]) -> Result<Orientation> {
    bump_exif_preflight();
    match extract_exif_payload(bytes)? {
        None => Ok(Orientation::NoTransforms),
        Some(payload) => parse_exif_orientation(&payload),
    }
}

/// Decode encoded bytes with the profile's bomb/dimension limits, applying
/// EXIF orientation. Preflight runs before the pixel decode.
pub fn decode_and_orient(bytes: &[u8], profile: &ImageProfile) -> Result<DynamicImage> {
    if bytes.len() > profile.max_input_bytes {
        bail!(
            "input image exceeds {} bytes (decompression bomb guard)",
            profile.max_input_bytes
        );
    }
    let orientation = preflight_exif_orientation(bytes)?;
    decode_with_orientation(bytes, profile, orientation)
}

/// Decode using orientation evidence already obtained by the caller's
/// pre-reservation preflight. This keeps the security-sensitive preflight
/// single-shot while still ensuring pixels are oriented before crop/scale.
pub fn decode_with_orientation(
    bytes: &[u8],
    profile: &ImageProfile,
    orientation: Orientation,
) -> Result<DynamicImage> {
    if bytes.len() > profile.max_input_bytes {
        bail!(
            "input image exceeds {} bytes (decompression bomb guard)",
            profile.max_input_bytes
        );
    }
    wait_decode_barrier();
    bump_decode();
    let mut decoded = decode_bounded(bytes, profile)?;
    decoded.apply_orientation(orientation);
    Ok(decoded)
}

/// Read decoder dimensions without allocating the pixel buffer and apply the
/// already-preflighted orientation to the dimension pair.
pub fn oriented_dimensions(bytes: &[u8], orientation: Orientation) -> Result<(u32, u32)> {
    let format = image::guess_format(bytes).map_err(|e| anyhow!("failed to inspect image: {e}"))?;
    let decoder = ImageReader::with_format(Cursor::new(bytes), format)
        .into_decoder()
        .map_err(|e| anyhow!("failed to inspect image: {e}"))?;
    let (width, height) = decoder.dimensions();
    ensure!(
        width > 0 && height > 0,
        "decoded source has zero dimensions"
    );
    if matches!(
        orientation,
        Orientation::Rotate90
            | Orientation::Rotate270
            | Orientation::Rotate90FlipH
            | Orientation::Rotate270FlipH
    ) {
        Ok((height, width))
    } else {
        Ok((width, height))
    }
}

/// Crop `img` to `rect` (oriented-image coordinates). Rejects, does not clamp.
pub fn crop(img: DynamicImage, rect: CropRect) -> Result<DynamicImage> {
    bump_crop();
    if rect.width == 0 || rect.height == 0 {
        bail!("region width and height must be positive");
    }
    let right = rect
        .x
        .checked_add(rect.width)
        .ok_or_else(|| anyhow!("region x+width overflows u32"))?;
    let bottom = rect
        .y
        .checked_add(rect.height)
        .ok_or_else(|| anyhow!("region y+height overflows u32"))?;
    if right > img.width() {
        bail!("region x+width exceeds source width");
    }
    if bottom > img.height() {
        bail!("region y+height exceeds source height");
    }
    if rect.x == 0 && rect.y == 0 && rect.width == img.width() && rect.height == img.height() {
        return Ok(img);
    }
    Ok(img.crop_imm(rect.x, rect.y, rect.width, rect.height))
}

/// Scale with the profile's resize filter. No-ops when dimensions already match.
pub fn scale(img: DynamicImage, width: u32, height: u32, profile: &ImageProfile) -> DynamicImage {
    if width == img.width() && height == img.height() {
        return img;
    }
    bump_scale();
    img.resize_exact(width, height, profile.resize_filter)
}

/// PNG-encode `img` with the profile's compression/filter.
///
/// Read-image preserves RGB vs RGBA. Storage always writes RGBA8.
pub fn encode_png(img: &DynamicImage, profile: &ImageProfile) -> Result<Vec<u8>> {
    bump_write();
    let mut bytes = Vec::new();
    let encoder = image::codecs::png::PngEncoder::new_with_quality(
        &mut bytes,
        profile.png_compression,
        profile.png_filter,
    );
    if profile.name == "storage" {
        let rgba = img.to_rgba8();
        encoder.write_image(
            rgba.as_raw(),
            rgba.width(),
            rgba.height(),
            ExtendedColorType::Rgba8,
        )?;
        return check_output(bytes, profile);
    }
    let has_alpha = matches!(img.color(), ColorType::Rgba8 | ColorType::La8);
    if has_alpha {
        let png_img = img.to_rgba8();
        encoder.write_image(
            png_img.as_raw(),
            png_img.width(),
            png_img.height(),
            ExtendedColorType::Rgba8,
        )?;
    } else {
        let png_img = img.to_rgb8();
        encoder.write_image(
            png_img.as_raw(),
            png_img.width(),
            png_img.height(),
            ExtendedColorType::Rgb8,
        )?;
    }
    check_output(bytes, profile)
}

/// PNG-encode an RGBA buffer with the profile's compression/filter.
pub fn encode_png_rgba(image: &image::RgbaImage, profile: &ImageProfile) -> Result<Vec<u8>> {
    bump_write();
    let mut bytes = Vec::new();
    image::codecs::png::PngEncoder::new_with_quality(
        &mut bytes,
        profile.png_compression,
        profile.png_filter,
    )
    .write_image(
        image,
        image.width(),
        image.height(),
        ExtendedColorType::Rgba8,
    )?;
    check_output(bytes, profile)
}

/// Decode, nearest-scale, and PNG-encode a screenshot.
pub fn scale_png_nearest(png: &[u8], width: u32, height: u32) -> Result<Vec<u8>> {
    let profile = ImageProfile::screenshot();
    let decoded = decode_and_orient(png, &profile)?;
    let scaled = scale(decoded, width, height, &profile);
    encode_png(&scaled, &profile)
}

/// True when `input` is a multi-frame GIF (additional frames will be ignored).
pub fn is_animated_gif(input: &[u8]) -> bool {
    let Some(header) = input.get(..13) else {
        return false;
    };
    if &header[..6] != b"GIF87a" && &header[..6] != b"GIF89a" {
        return false;
    }
    let packed = header[10];
    let global_table = if packed & 0x80 != 0 {
        3usize << (usize::from(packed & 0x07) + 1)
    } else {
        0
    };
    let mut offset = 13usize.saturating_add(global_table);
    let mut images = 0u8;
    while let Some(&kind) = input.get(offset) {
        offset += 1;
        match kind {
            0x2c => {
                images = images.saturating_add(1);
                if images > 1 {
                    return true;
                }
                let Some(descriptor) = input.get(offset..offset.saturating_add(9)) else {
                    return false;
                };
                offset += 9;
                if descriptor[8] & 0x80 != 0 {
                    offset =
                        offset.saturating_add(3usize << (usize::from(descriptor[8] & 0x07) + 1));
                }
                // LZW minimum code size, followed by data sub-blocks.
                offset = offset.saturating_add(1);
                if !skip_gif_sub_blocks(input, &mut offset) {
                    return false;
                }
            }
            0x21 => {
                // Extension label followed by data sub-blocks.
                offset = offset.saturating_add(1);
                if !skip_gif_sub_blocks(input, &mut offset) {
                    return false;
                }
            }
            0x3b => return false,
            _ => return false,
        }
    }
    false
}

fn skip_gif_sub_blocks(input: &[u8], offset: &mut usize) -> bool {
    loop {
        let Some(&length) = input.get(*offset) else {
            return false;
        };
        *offset += 1;
        if length == 0 {
            return true;
        }
        let Some(next) = offset.checked_add(usize::from(length)) else {
            return false;
        };
        if next > input.len() {
            return false;
        }
        *offset = next;
    }
}

fn check_output(bytes: Vec<u8>, profile: &ImageProfile) -> Result<Vec<u8>> {
    if bytes.len() > profile.max_output_bytes {
        bail!(
            "output image exceeds {} bytes (central limit)",
            profile.max_output_bytes
        );
    }
    Ok(bytes)
}

fn decode_bounded(bytes: &[u8], profile: &ImageProfile) -> Result<DynamicImage> {
    let format = image::guess_format(bytes).map_err(|e| anyhow!("failed to decode image: {e}"))?;
    let mut reader = ImageReader::with_format(Cursor::new(bytes), format);
    let mut limits = Limits::default();
    limits.max_image_width = profile.max_width;
    limits.max_image_height = profile.max_height;
    limits.max_alloc = profile.max_alloc;
    reader.limits(limits);
    let decoder = reader
        .into_decoder()
        .map_err(|e| anyhow!("failed to decode image: {e}"))?;
    let (width, height) = decoder.dimensions();
    if let Some(max_w) = profile.max_width {
        ensure!(width > 0 && width <= max_w, "resource_limit");
    }
    if let Some(max_h) = profile.max_height {
        ensure!(height > 0 && height <= max_h, "resource_limit");
    }
    if let Some(max_pixels) = profile.max_pixels {
        ensure!(
            u64::from(width)
                .checked_mul(u64::from(height))
                .is_some_and(|p| p <= max_pixels),
            "resource_limit"
        );
    }
    DynamicImage::from_decoder(decoder).map_err(|e| anyhow!("failed to decode image: {e}"))
}

/// Locate a raw EXIF TIFF payload without decoding pixels.
///
/// `Ok(None)` means the container has no EXIF marker. `Err` is reserved for
/// truncated/malformed **markers** (declared length past end of buffer).
fn extract_exif_payload(bytes: &[u8]) -> Result<Option<Vec<u8>>> {
    if bytes.len() >= 3 && bytes[0] == 0xff && bytes[1] == 0xd8 {
        return extract_jpeg_exif(bytes);
    }
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return extract_png_exif(bytes);
    }
    if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        return extract_webp_exif(bytes);
    }
    Ok(None)
}

fn extract_jpeg_exif(bytes: &[u8]) -> Result<Option<Vec<u8>>> {
    let mut offset = 2usize;
    let mut exif = None;
    while offset + 4 <= bytes.len() {
        if bytes[offset] != 0xff {
            return Ok(None);
        }
        let marker = bytes[offset + 1];
        offset += 2;
        if marker == 0xd9 || marker == 0xda {
            return Ok(exif);
        }
        if matches!(marker, 0x01 | 0xd0..=0xd7) {
            continue;
        }
        if offset + 2 > bytes.len() {
            return Err(orientation_unsupported());
        }
        let length = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        if length < 2 || offset + length > bytes.len() {
            // A truncated APP1 Exif is fail-closed; other truncated markers
            // are left to the decoder.
            if marker == 0xe1 {
                return Err(orientation_unsupported());
            }
            return Ok(None);
        }
        let payload = &bytes[offset + 2..offset + length];
        if marker == 0xe1 && payload.starts_with(b"Exif") {
            if !payload.starts_with(b"Exif\0\0") {
                return Err(orientation_unsupported());
            }
            if exif.replace(payload[6..].to_vec()).is_some() {
                return Err(orientation_unsupported());
            }
        }
        offset += length;
    }
    if offset < bytes.len()
        && bytes[offset] == 0xff
        && bytes.get(offset + 1).is_some_and(|marker| *marker == 0xe1)
    {
        return Err(orientation_unsupported());
    }
    Ok(exif)
}

fn extract_png_exif(bytes: &[u8]) -> Result<Option<Vec<u8>>> {
    let mut offset = 8usize;
    let mut exif = None;
    while offset.checked_add(12).is_some_and(|end| end <= bytes.len()) {
        let length = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        let end = offset
            .checked_add(12)
            .and_then(|v| v.checked_add(length))
            .ok_or_else(orientation_unsupported)?;
        if end > bytes.len() {
            let kind = &bytes[offset + 4..offset + 8];
            if kind == b"eXIf" {
                return Err(orientation_unsupported());
            }
            return Ok(None);
        }
        let kind = &bytes[offset + 4..offset + 8];
        if kind == b"eXIf" {
            let expected_crc = u32::from_be_bytes(bytes[end - 4..end].try_into().unwrap());
            if png_crc32(&bytes[offset + 4..end - 4]) != expected_crc {
                return Err(orientation_unsupported());
            }
            if exif
                .replace(bytes[offset + 8..offset + 8 + length].to_vec())
                .is_some()
            {
                return Err(orientation_unsupported());
            }
        }
        if kind == b"IEND" {
            break;
        }
        offset = end;
    }
    if offset < bytes.len()
        && bytes
            .get(offset + 4..offset + 8)
            .is_some_and(|kind| kind == b"eXIf")
    {
        return Err(orientation_unsupported());
    }
    Ok(exif)
}

fn extract_webp_exif(bytes: &[u8]) -> Result<Option<Vec<u8>>> {
    let declared = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
    let declared_end = declared
        .checked_add(8)
        .ok_or_else(orientation_unsupported)?;
    if declared_end != bytes.len() && bytes.windows(4).any(|window| window == b"EXIF") {
        return Err(orientation_unsupported());
    }
    let mut offset = 12usize;
    let mut exif = None;
    while offset + 8 <= bytes.len() {
        let kind = &bytes[offset..offset + 4];
        let length = u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap()) as usize;
        let start = offset + 8;
        let end = start
            .checked_add(length)
            .ok_or_else(orientation_unsupported)?;
        if end > bytes.len() {
            if kind == b"EXIF" {
                return Err(orientation_unsupported());
            }
            return Ok(None);
        }
        if kind == b"EXIF" {
            let payload = &bytes[start..end];
            let tiff = payload.strip_prefix(b"Exif\0\0").unwrap_or(payload);
            if exif.replace(tiff.to_vec()).is_some() {
                return Err(orientation_unsupported());
            }
        }
        let padded_end = end
            .checked_add(length & 1)
            .ok_or_else(orientation_unsupported)?;
        if padded_end > bytes.len() {
            if kind == b"EXIF" {
                return Err(orientation_unsupported());
            }
            return Ok(exif);
        }
        offset = padded_end;
    }
    if offset < bytes.len() && bytes[offset..].starts_with(b"EXIF") {
        return Err(orientation_unsupported());
    }
    Ok(exif)
}

fn png_crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

fn parse_exif_orientation(tiff: &[u8]) -> Result<Orientation> {
    if tiff.len() < 8 {
        return Err(orientation_unsupported());
    }
    let little = match &tiff[..2] {
        b"II" => true,
        b"MM" => false,
        _ => return Err(orientation_unsupported()),
    };
    let u16_at = |o: usize| -> Result<u16> {
        let b: [u8; 2] = tiff
            .get(o..o + 2)
            .ok_or_else(orientation_unsupported)?
            .try_into()
            .map_err(|_| orientation_unsupported())?;
        Ok(if little {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        })
    };
    let u32_at = |o: usize| -> Result<u32> {
        let b: [u8; 4] = tiff
            .get(o..o + 4)
            .ok_or_else(orientation_unsupported)?
            .try_into()
            .map_err(|_| orientation_unsupported())?;
        Ok(if little {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    };
    if u16_at(2)? != 42 {
        return Err(orientation_unsupported());
    }
    let ifd = usize::try_from(u32_at(4)?).map_err(|_| orientation_unsupported())?;
    let count = usize::from(u16_at(ifd)?);
    if count > 256 {
        return Err(orientation_unsupported());
    }
    let mut orientation = None;
    for index in 0..count {
        let entry = ifd
            .checked_add(2)
            .and_then(|v| index.checked_mul(12).and_then(|off| v.checked_add(off)))
            .ok_or_else(orientation_unsupported)?;
        let tag = u16_at(entry)?;
        if tag != 0x0112 {
            continue;
        }
        let format = u16_at(entry + 2)?;
        let n = u32_at(entry + 4)?;
        if format != 3 || n != 1 {
            return Err(orientation_unsupported());
        }
        let value = u16_at(entry + 8)?;
        if !(1..=8).contains(&value) {
            return Err(orientation_unsupported());
        }
        if orientation
            .replace(u8::try_from(value).map_err(|_| orientation_unsupported())?)
            .is_some()
        {
            return Err(orientation_unsupported());
        }
    }
    match orientation {
        None => Ok(Orientation::NoTransforms),
        Some(value) => Orientation::from_exif(value).ok_or_else(orientation_unsupported),
    }
}

fn bump_exif_preflight() {
    #[cfg(test)]
    test_hooks::bump(|c| {
        c.exif_preflight
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    });
}

fn bump_decode() {
    #[cfg(test)]
    test_hooks::bump(|c| {
        c.decode.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    });
}

fn bump_crop() {
    #[cfg(test)]
    test_hooks::bump(|c| {
        c.crop.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    });
}

fn bump_scale() {
    #[cfg(test)]
    test_hooks::bump(|c| {
        c.scale.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    });
}

fn bump_write() {
    #[cfg(test)]
    test_hooks::bump(|c| {
        c.write.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    });
}

fn wait_decode_barrier() {
    #[cfg(test)]
    test_hooks::wait_decode_barrier();
}

#[cfg(test)]
pub(crate) mod test_hooks {
    use super::*;
    use std::cell::RefCell;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::mpsc::{self, Receiver, Sender};

    /// Deterministic decode barrier used by cleanup/cancellation tests.
    pub struct DecodeBarrier {
        entered: (MutexSender, AtomicBool),
        wait: std::sync::Mutex<Option<Receiver<()>>>,
    }

    struct MutexSender(std::sync::Mutex<Option<Sender<()>>>);

    impl DecodeBarrier {
        pub fn new() -> (Arc<Self>, Sender<()>, Receiver<()>) {
            let (enter_tx, enter_rx) = mpsc::channel();
            let (continue_tx, continue_rx) = mpsc::channel();
            let barrier = Arc::new(Self {
                entered: (
                    MutexSender(std::sync::Mutex::new(Some(enter_tx))),
                    AtomicBool::new(false),
                ),
                wait: std::sync::Mutex::new(Some(continue_rx)),
            });
            (barrier, continue_tx, enter_rx)
        }

        pub fn has_entered(&self) -> bool {
            self.entered.1.load(Ordering::SeqCst)
        }
    }

    #[derive(Debug, Default)]
    pub struct PipelineCounters {
        pub exif_preflight: AtomicU64,
        pub decode: AtomicU64,
        pub crop: AtomicU64,
        pub scale: AtomicU64,
        pub write: AtomicU64,
        pub reservation: AtomicU64,
        pub derivative_write: AtomicU64,
    }

    thread_local! {
        static COUNTERS: RefCell<Option<Arc<PipelineCounters>>> = const { RefCell::new(None) };
        static BARRIER: RefCell<Option<Arc<DecodeBarrier>>> = const { RefCell::new(None) };
        static PUBLICATION_BARRIER: RefCell<Option<Arc<DecodeBarrier>>> = const { RefCell::new(None) };
    }

    pub fn install_counters(counters: Arc<PipelineCounters>) {
        COUNTERS.with(|slot| *slot.borrow_mut() = Some(counters));
    }

    pub fn install_barrier(barrier: Arc<DecodeBarrier>) {
        BARRIER.with(|slot| *slot.borrow_mut() = Some(barrier));
    }

    pub fn install_publication_barrier(barrier: Arc<DecodeBarrier>) {
        PUBLICATION_BARRIER.with(|slot| *slot.borrow_mut() = Some(barrier));
    }

    pub fn clear() {
        COUNTERS.with(|slot| *slot.borrow_mut() = None);
        BARRIER.with(|slot| *slot.borrow_mut() = None);
        PUBLICATION_BARRIER.with(|slot| *slot.borrow_mut() = None);
    }

    pub fn bump(f: impl FnOnce(&PipelineCounters)) {
        COUNTERS.with(|slot| {
            if let Some(counters) = slot.borrow().as_ref() {
                f(counters);
            }
        });
    }

    fn wait_named_barrier(slot: &RefCell<Option<Arc<DecodeBarrier>>>) {
        let barrier = slot.borrow().clone();
        if let Some(barrier) = barrier {
            barrier.entered.1.store(true, Ordering::SeqCst);
            if let Some(tx) = barrier.entered.0.0.lock().unwrap().take() {
                let _ = tx.send(());
            }
            if let Some(rx) = barrier.wait.lock().unwrap().take() {
                let _ = rx.recv();
            }
        }
    }

    pub fn wait_decode_barrier() {
        BARRIER.with(wait_named_barrier);
    }

    pub fn wait_publication_barrier() {
        PUBLICATION_BARRIER.with(wait_named_barrier);
    }

    /// Build a JPEG whose pixels encode a unique (x,y) pattern, with EXIF orientation 6.
    pub fn jpeg_orientation_6_fixture(width: u32, height: u32) -> Vec<u8> {
        jpeg_with_exif_orientation(pattern_image(width, height), 6)
    }

    /// JPEG with a truncated APP1 Exif segment (fail-closed preflight).
    pub fn jpeg_malformed_exif_fixture() -> Vec<u8> {
        let jpeg = encode_jpeg(pattern_image(4, 4));
        let mut out = Vec::new();
        out.extend_from_slice(&jpeg[..2]);
        out.extend_from_slice(&[0xff, 0xe1, 0x00, 0x20]); // declared length 32
        out.extend_from_slice(b"Exif\0\0");
        out.extend_from_slice(&[0x49, 0x49]); // truncated TIFF
        out.extend_from_slice(&jpeg[2..]);
        out
    }

    /// JPEG with EXIF orientation tag 9 (out of range).
    pub fn jpeg_out_of_range_exif_fixture() -> Vec<u8> {
        jpeg_with_exif_orientation(pattern_image(4, 4), 9)
    }

    pub fn pattern_image(width: u32, height: u32) -> DynamicImage {
        let mut img = image::ImageBuffer::new(width, height);
        for (x, y, pixel) in img.enumerate_pixels_mut() {
            *pixel = image::Rgba([(x % 256) as u8, (y % 256) as u8, ((x + y) % 256) as u8, 255]);
        }
        DynamicImage::ImageRgba8(img)
    }

    pub fn jpeg_with_exif_orientation(img: DynamicImage, orientation: u8) -> Vec<u8> {
        let jpeg = encode_jpeg(img);
        inject_jpeg_exif_orientation(&jpeg, orientation)
    }

    pub fn png_with_exif_orientation(img: DynamicImage, orientation: u8) -> Vec<u8> {
        let mut png = Vec::new();
        img.write_to(&mut Cursor::new(&mut png), ImageFormat::Png)
            .expect("png encode");
        inject_png_exif_orientation(&png, orientation)
    }

    fn inject_png_exif_orientation(png: &[u8], orientation: u8) -> Vec<u8> {
        assert!(png.len() >= 33 && &png[12..16] == b"IHDR");
        let tiff = tiff_orientation(orientation);
        let mut chunk = Vec::new();
        chunk.extend_from_slice(&(tiff.len() as u32).to_be_bytes());
        chunk.extend_from_slice(b"eXIf");
        chunk.extend_from_slice(&tiff);
        let mut crc_input = Vec::from(*b"eXIf");
        crc_input.extend_from_slice(&tiff);
        chunk.extend_from_slice(&png_crc32(&crc_input).to_be_bytes());
        let mut out = Vec::with_capacity(png.len() + chunk.len());
        out.extend_from_slice(&png[..33]);
        out.extend_from_slice(&chunk);
        out.extend_from_slice(&png[33..]);
        out
    }

    fn tiff_orientation(orientation: u8) -> Vec<u8> {
        let mut tiff = b"II\x2a\0\x08\0\0\0".to_vec();
        tiff.extend_from_slice(&1u16.to_le_bytes());
        tiff.extend_from_slice(&0x0112u16.to_le_bytes());
        tiff.extend_from_slice(&3u16.to_le_bytes());
        tiff.extend_from_slice(&1u32.to_le_bytes());
        tiff.extend_from_slice(&(orientation as u16).to_le_bytes());
        tiff.extend_from_slice(&[0, 0]);
        tiff.extend_from_slice(&0u32.to_le_bytes());
        tiff
    }

    fn png_crc32(bytes: &[u8]) -> u32 {
        let mut crc = u32::MAX;
        for byte in bytes {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
            }
        }
        !crc
    }

    fn encode_jpeg(img: DynamicImage) -> Vec<u8> {
        let mut bytes = Vec::new();
        img.write_to(&mut Cursor::new(&mut bytes), ImageFormat::Jpeg)
            .expect("jpeg encode");
        bytes
    }

    fn inject_jpeg_exif_orientation(jpeg: &[u8], orientation: u8) -> Vec<u8> {
        assert!(jpeg.len() >= 2 && jpeg[0] == 0xff && jpeg[1] == 0xd8);
        let tiff = tiff_orientation(orientation);
        let mut app1 = Vec::new();
        app1.extend_from_slice(&[0xff, 0xe1]);
        let payload_len = 2 + 6 + tiff.len();
        app1.extend_from_slice(&(payload_len as u16).to_be_bytes());
        app1.extend_from_slice(b"Exif\0\0");
        app1.extend_from_slice(&tiff);
        let mut out = Vec::with_capacity(jpeg.len() + app1.len());
        out.extend_from_slice(&jpeg[..2]);
        out.extend_from_slice(&app1);
        out.extend_from_slice(&jpeg[2..]);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::GenericImage;
    use image::codecs::png::{CompressionType, FilterType};
    use image::imageops::FilterType as ResizeFilter;

    /// Production text of `relative` with every test-only item removed.
    ///
    /// `media_storage.rs` and `computer/mod.rs` declare `#[cfg(test)]` helpers
    /// before the production derivative encoder and screenshot scaler.
    /// Truncating at the first column-0 `#[cfg(test)]` would leave those
    /// functions unaudited.
    fn production_source(relative: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path:?}: {e}"));
        strip_test_gated_items(&text)
    }

    fn strip_test_gated_items(src: &str) -> String {
        let mut out = String::with_capacity(src.len());
        let mut i = 0;
        while i < src.len() {
            if let Some(rel) = src[i..].find("#[cfg(") {
                out.push_str(&src[i..i + rel]);
                let attr_at = i + rel;
                if let Some(end) = skip_test_gated_item(&src[attr_at..]) {
                    i = attr_at + end;
                    continue;
                }
                out.push_str(&src[attr_at..attr_at + "#[cfg(".len()]);
                i = attr_at + "#[cfg(".len();
                continue;
            }
            out.push_str(&src[i..]);
            break;
        }
        out
    }

    /// Byte length of a test-only item starting at `#[cfg(...)]`, including
    /// stacked attributes. Struct fields, statements, and expr-position
    /// `#[cfg(test)]` are not items and must stay so later production is not
    /// swallowed.
    fn skip_test_gated_item(src: &str) -> Option<usize> {
        let attr_len = test_only_cfg_attr_len(src)?;
        let header = skip_to_item_start(src, attr_len)?;
        Some(skip_braced_or_semicolon_item(src, header))
    }

    fn skip_to_item_start(src: &str, mut i: usize) -> Option<usize> {
        loop {
            i = skip_ws(src, i);
            if src[i..].starts_with("#[") {
                i = skip_attribute(src, i)?;
                continue;
            }
            break;
        }
        i = skip_visibility(src, i);
        i = skip_ws(src, i);
        item_starts_at(src, i).then_some(i)
    }

    fn skip_ws(src: &str, mut i: usize) -> usize {
        let bytes = src.as_bytes();
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        i
    }

    fn skip_attribute(src: &str, start: usize) -> Option<usize> {
        if !src[start..].starts_with("#[") {
            return None;
        }
        let bytes = src.as_bytes();
        let mut depth = 0usize;
        let mut i = start;
        while i < bytes.len() {
            match bytes[i] {
                b'[' => depth += 1,
                b']' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return Some(i + 1);
                    }
                }
                _ => {}
            }
            i += 1;
        }
        None
    }

    fn ident_at(src: &str, i: usize) -> Option<&str> {
        let bytes = src.as_bytes();
        if i >= bytes.len() || !(bytes[i].is_ascii_alphabetic() || bytes[i] == b'_') {
            return None;
        }
        let mut end = i + 1;
        while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
            end += 1;
        }
        Some(&src[i..end])
    }

    fn skip_visibility(src: &str, i: usize) -> usize {
        if ident_at(src, i) != Some("pub") {
            return i;
        }
        let mut j = skip_ws(src, i + 3);
        let bytes = src.as_bytes();
        if bytes.get(j) != Some(&b'(') {
            return i + 3;
        }
        let mut depth = 0usize;
        while j < bytes.len() {
            match bytes[j] {
                b'(' => depth += 1,
                b')' => {
                    depth = depth.saturating_sub(1);
                    j += 1;
                    if depth == 0 {
                        return j;
                    }
                    continue;
                }
                _ => {}
            }
            j += 1;
        }
        i + 3
    }

    fn item_starts_at(src: &str, i: usize) -> bool {
        matches!(
            ident_at(src, i),
            Some(
                "fn" | "mod"
                    | "impl"
                    | "struct"
                    | "enum"
                    | "union"
                    | "trait"
                    | "type"
                    | "const"
                    | "static"
                    | "use"
                    | "extern"
                    | "async"
                    | "unsafe"
            )
        )
    }

    fn skip_braced_or_semicolon_item(src: &str, from: usize) -> usize {
        let bytes = src.as_bytes();
        let mut cursor = from;
        while cursor < bytes.len() {
            match bytes[cursor] {
                b'{' => return matching_brace_end(src, cursor),
                b';' => return cursor + 1,
                _ => cursor += 1,
            }
        }
        src.len()
    }

    fn test_only_cfg_attr_len(src: &str) -> Option<usize> {
        let rest = src.strip_prefix("#[cfg(")?;
        let bytes = rest.as_bytes();
        let mut depth = 1usize;
        let mut i = 0usize;
        while i < bytes.len() {
            match bytes[i] {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        if rest.get(i + 1..i + 2) != Some("]") {
                            return None;
                        }
                        let pred = rest[..i].trim();
                        return cfg_requires_test(pred).then_some("#[cfg(".len() + i + 2);
                    }
                }
                _ => {}
            }
            i += 1;
        }
        None
    }

    fn cfg_requires_test(pred: &str) -> bool {
        let pred = pred.trim();
        if pred == "test" {
            return true;
        }
        if let Some(inner) = pred.strip_prefix("all(").and_then(|s| s.strip_suffix(')')) {
            return split_cfg_args(inner)
                .into_iter()
                .any(|arg| cfg_requires_test(arg));
        }
        if let Some(inner) = pred.strip_prefix("any(").and_then(|s| s.strip_suffix(')')) {
            let args = split_cfg_args(inner);
            return !args.is_empty() && args.iter().all(|arg| cfg_requires_test(arg));
        }
        false
    }

    fn split_cfg_args(inner: &str) -> Vec<&str> {
        let mut args = Vec::new();
        let mut start = 0usize;
        let mut depth = 0usize;
        for (i, ch) in inner.char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => depth = depth.saturating_sub(1),
                ',' if depth == 0 => {
                    args.push(inner[start..i].trim());
                    start = i + 1;
                }
                _ => {}
            }
        }
        let last = inner[start..].trim();
        if !last.is_empty() {
            args.push(last);
        }
        args
    }

    fn matching_brace_end(src: &str, open: usize) -> usize {
        let bytes = src.as_bytes();
        let mut depth = 0usize;
        let mut j = open;
        while j < bytes.len() {
            match bytes[j] {
                b'{' => depth += 1,
                b'}' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return j + 1;
                    }
                }
                _ => {}
            }
            j += 1;
        }
        src.len()
    }

    fn production_fn<'a>(src: &'a str, signature: &str) -> &'a str {
        let start = src
            .find(signature)
            .unwrap_or_else(|| panic!("production scan missed `{signature}`"));
        let from = &src[start..];
        let open = from
            .find('{')
            .unwrap_or_else(|| panic!("`{signature}` has no body"));
        let end = matching_brace_end(from, open);
        &from[..end]
    }

    fn png_with_ihdr_dimensions(width: u32, height: u32) -> Vec<u8> {
        fn crc32(data: &[u8]) -> u32 {
            let mut crc = 0xFFFF_FFFFu32;
            for &byte in data {
                crc ^= u32::from(byte);
                for _ in 0..8 {
                    crc = if crc & 1 != 0 {
                        (crc >> 1) ^ 0xEDB8_8320
                    } else {
                        crc >> 1
                    };
                }
            }
            !crc
        }
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(b"IHDR");
        ihdr.extend_from_slice(&width.to_be_bytes());
        ihdr.extend_from_slice(&height.to_be_bytes());
        ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
        let crc = crc32(&ihdr);
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png.extend_from_slice(&13u32.to_be_bytes());
        png.extend_from_slice(&ihdr);
        png.extend_from_slice(&crc.to_be_bytes());
        png.extend_from_slice(&0u32.to_be_bytes());
        png.extend_from_slice(b"IEND");
        png.extend_from_slice(&crc32(b"IEND").to_be_bytes());
        png
    }

    #[test]
    fn decode_rejects_width_and_height_over_the_central_limit() {
        let limits = crate::resource_limits::ResourceLimits::defaults();
        let over_width = png_with_ihdr_dimensions(limits.image_max_width + 1, 1);
        let err = decode_and_orient(&over_width, &ImageProfile::read_image()).unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("resource_limit") || text.contains("decode"),
            "width over the cap must fail closed, got {text}"
        );
        let over_height = png_with_ihdr_dimensions(1, limits.image_max_height + 1);
        let err = decode_and_orient(&over_height, &ImageProfile::read_image()).unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("resource_limit") || text.contains("decode"),
            "height over the cap must fail closed, got {text}"
        );
    }

    #[test]
    fn media_image_profiles() {
        let read = ImageProfile::read_image();
        let storage = ImageProfile::storage();
        let screenshot = ImageProfile::screenshot();
        assert_eq!(read.png_compression, CompressionType::Default);
        assert_eq!(read.png_filter, FilterType::Adaptive);
        assert_eq!(read.resize_filter, ResizeFilter::Lanczos3);
        let limits = crate::resource_limits::ResourceLimits::defaults();
        assert_eq!(read.max_input_bytes, 64 * 1024 * 1024);
        assert_eq!(read.max_width, Some(limits.image_max_width));
        assert_eq!(read.max_height, Some(limits.image_max_height));
        assert_eq!(read.max_pixels, Some(limits.image_max_pixels));
        assert_eq!(read.max_alloc, Some(limits.image_max_alloc_bytes));
        assert_eq!(screenshot.max_width, Some(limits.image_max_width));
        assert_eq!(storage.png_compression, CompressionType::Level(6));
        assert_eq!(storage.png_filter, FilterType::Paeth);
        assert_eq!(screenshot.resize_filter, ResizeFilter::Nearest);

        let jpeg = test_hooks::jpeg_orientation_6_fixture(4, 2);
        assert_eq!(
            preflight_exif_orientation(&jpeg).unwrap(),
            image::metadata::Orientation::Rotate90
        );

        let mut img = image::ImageBuffer::new(2, 2);
        img.put_pixel(0, 0, image::Rgba([255, 0, 0, 255]));
        img.put_pixel(1, 0, image::Rgba([0, 255, 0, 255]));
        img.put_pixel(0, 1, image::Rgba([0, 0, 255, 255]));
        img.put_pixel(1, 1, image::Rgba([255, 255, 255, 255]));
        let fixture =
            test_hooks::png_with_exif_orientation(image::DynamicImage::ImageRgba8(img), 6);

        let read_oriented = decode_and_orient(&fixture, &ImageProfile::read_image()).unwrap();
        let storage_norm = crate::media_storage::normalize_image(&fixture, "png").unwrap();
        assert_eq!(read_oriented.width(), storage_norm.width);
        assert_eq!(read_oriented.height(), storage_norm.height);
        let storage_pixels = image::load_from_memory(&storage_norm.model_png)
            .unwrap()
            .to_rgba8();
        assert_eq!(
            read_oriented.to_rgba8().dimensions(),
            storage_pixels.dimensions()
        );
        assert_eq!(
            read_oriented.to_rgba8().get_pixel(0, 0).0,
            storage_pixels.get_pixel(0, 0).0
        );

        let mut checker = image::ImageBuffer::new(2, 2);
        checker.put_pixel(0, 0, image::Rgba([255, 255, 255, 255]));
        checker.put_pixel(1, 0, image::Rgba([0, 0, 0, 255]));
        checker.put_pixel(0, 1, image::Rgba([0, 0, 0, 255]));
        checker.put_pixel(1, 1, image::Rgba([255, 255, 255, 255]));
        let nearest = scale(
            image::DynamicImage::ImageRgba8(checker),
            4,
            4,
            &ImageProfile::screenshot(),
        )
        .to_rgba8();
        assert_eq!(nearest.get_pixel(0, 0).0, [255, 255, 255, 255]);
        assert_eq!(nearest.get_pixel(1, 1).0, [255, 255, 255, 255]);
        assert_eq!(nearest.get_pixel(2, 0).0, [0, 0, 0, 255]);

        let truncation_fixture = concat!(
            "fn early() {}\n",
            "#[cfg(test)]\n",
            "mod target_tests;\n",
            "struct S { #[cfg(test)] av_runtime_override: bool }\n",
            "fn scale_png() { crate::media_image::encode_png(); }\n",
            "#[cfg(test)]\n",
            "pub(crate) fn media_upload_reservation_digest() { img.write_to(); }\n",
            "fn encode_canonical_png() { crate::media_image::encode_png_rgba(); }\n",
            "#[cfg(all(test, unix))]\n",
            "mod tests { img.write_to(); PngEncoder::new_with_quality(); }\n",
        );
        let stripped_fixture = strip_test_gated_items(truncation_fixture);
        assert!(
            stripped_fixture.contains("fn scale_png"),
            "scan must keep production after an early #[cfg(test)] mod ...;"
        );
        assert!(
            stripped_fixture.contains("fn encode_canonical_png"),
            "scan must keep production after an early #[cfg(test)] fn"
        );
        assert!(
            !stripped_fixture.contains("write_to"),
            "scan must drop test-only write_to, including #[cfg(all(test, ...))] modules"
        );
        assert!(
            !stripped_fixture.contains("PngEncoder::new_with_quality"),
            "scan must drop test-only PngEncoder calls"
        );
        assert!(!stripped_fixture.contains("target_tests"));
        assert!(!stripped_fixture.contains("media_upload_reservation_digest"));
        assert!(
            stripped_fixture.contains("av_runtime_override"),
            "field-level #[cfg(test)] must not be treated as an item that swallows later production"
        );

        for path in [
            "src/tools/read_image.rs",
            "src/media_storage.rs",
            "src/computer/mod.rs",
        ] {
            let src = production_source(path);
            assert!(
                !src.contains("PngEncoder::new_with_quality"),
                "{path} must not call PngEncoder::new_with_quality outside media_image"
            );
            assert!(
                !src.contains(".write_to("),
                "{path} must not use generic write_to on the production image path"
            );
        }

        let storage = production_source("src/media_storage.rs");
        let encoder = production_fn(&storage, "fn encode_canonical_png(");
        assert!(
            encoder.contains("media_image::encode_png_rgba"),
            "storage derivative encoder must call media_image"
        );
        assert!(
            !encoder.contains("PngEncoder::new_with_quality") && !encoder.contains(".write_to("),
            "encode_canonical_png must not bypass media_image"
        );
        assert!(
            production_fn(&storage, "fn normalize_image(")
                .contains("media_image::decode_and_orient"),
            "normalize_image must call media_image"
        );

        let computer = production_source("src/computer/mod.rs");
        let scaler = production_fn(&computer, "fn scale_png(");
        assert!(
            scaler.contains("media_image::decode_and_orient")
                && scaler.contains("media_image::encode_png")
                && scaler.contains("ImageProfile::screenshot"),
            "screenshot scaler must call media_image with the screenshot profile"
        );
        assert!(
            !scaler.contains("PngEncoder::new_with_quality") && !scaler.contains(".write_to("),
            "scale_png must not bypass media_image"
        );

        let shared = production_source("src/media_image.rs");
        assert!(
            shared.contains("PngEncoder::new_with_quality"),
            "media_image must own PNG encoding"
        );
    }

    #[test]
    fn truncated_jpeg_exif_signature_fails_closed() {
        let bytes = [
            0xff, 0xd8, 0xff, 0xe1, 0x00, 0x07, b'E', b'x', b'i', b'f', 0,
        ];
        let error = preflight_exif_orientation(&bytes).unwrap_err();
        assert!(error.to_string().contains("media_orientation_unsupported"));
    }
}

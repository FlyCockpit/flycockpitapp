//! Bounded, no-follow normalization for browser typed-file paste paths.

use std::fs::{File, Metadata, OpenOptions};
use std::io::{Cursor, Read};
use std::path::Path;

use image::{DynamicImage, GenericImageView, ImageDecoder, ImageFormat, ImageReader, Limits};

const MAX_INPUT_BYTES: u64 = 10 * 1024 * 1024;
const MAX_DIMENSION: u32 = 8_192;
const MAX_PIXELS: u64 = 40_000_000;
const MAX_DECODED_BYTES: u64 = 160_000_000;

#[derive(Debug, thiserror::Error)]
pub enum ImageProbeError {
    #[error("paste image is unavailable")]
    PasteUnavailable,
}

/// Open one regular file without following its final symlink, verify it did
/// not change while read, decode only the closed browser format allowlist, and
/// return a metadata-free RGBA PNG.
pub fn normalize_private_image(path: &Path) -> Result<Vec<u8>, ImageProbeError> {
    if !is_generation_scoped(path) {
        return Err(ImageProbeError::PasteUnavailable);
    }
    let mut file = open_no_follow(path)?;
    let before = file
        .metadata()
        .map_err(|_| ImageProbeError::PasteUnavailable)?;
    validate_metadata(&before)?;
    let mut bytes = Vec::with_capacity(before.len() as usize);
    file.by_ref()
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ImageProbeError::PasteUnavailable)?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(ImageProbeError::PasteUnavailable);
    }
    let after = file
        .metadata()
        .map_err(|_| ImageProbeError::PasteUnavailable)?;
    if !same_file(&before, &after) || after.len() != bytes.len() as u64 {
        return Err(ImageProbeError::PasteUnavailable);
    }

    let format = browser_format(&bytes)?;
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
        .ok_or(ImageProbeError::PasteUnavailable)?;
    let extension_matches = match format {
        ImageFormat::Png => extension == "png",
        ImageFormat::Jpeg => matches!(extension.as_str(), "jpg" | "jpeg"),
        ImageFormat::Gif => extension == "gif",
        ImageFormat::WebP => extension == "webp",
        _ => false,
    };
    if !extension_matches {
        return Err(ImageProbeError::PasteUnavailable);
    }
    reject_animation(format, &bytes)?;
    let mut reader = ImageReader::with_format(Cursor::new(bytes), format);
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_DIMENSION);
    limits.max_image_height = Some(MAX_DIMENSION);
    limits.max_alloc = Some(MAX_DECODED_BYTES);
    reader.limits(limits);
    let mut decoder = reader
        .into_decoder()
        .map_err(|_| ImageProbeError::PasteUnavailable)?;
    let orientation = decoder
        .orientation()
        .map_err(|_| ImageProbeError::PasteUnavailable)?;
    let mut image =
        DynamicImage::from_decoder(decoder).map_err(|_| ImageProbeError::PasteUnavailable)?;
    image.apply_orientation(orientation);
    let (width, height) = image.dimensions();
    let pixels = u64::from(width)
        .checked_mul(u64::from(height))
        .ok_or(ImageProbeError::PasteUnavailable)?;
    if pixels > MAX_PIXELS {
        return Err(ImageProbeError::PasteUnavailable);
    }
    let rgba = image.into_rgba8();
    let mut normalized = Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(rgba)
        .write_to(&mut normalized, ImageFormat::Png)
        .map_err(|_| ImageProbeError::PasteUnavailable)?;
    Ok(normalized.into_inner())
}

fn is_generation_scoped(path: &Path) -> bool {
    let text = path.to_string_lossy();
    let components = text
        .split(['/', '\\'])
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    let Some(file) = components.last() else {
        return false;
    };
    let Some((stem, extension)) = file.rsplit_once('.') else {
        return false;
    };
    let opaque = |component: &str| {
        component.len() == 26
            && component
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || matches!(byte, b'2'..=b'7'))
    };
    components.len() >= 3
        && opaque(stem)
        && matches!(extension, "png" | "jpg" | "jpeg" | "gif" | "webp")
        && opaque(components[components.len() - 2])
        && opaque(components[components.len() - 3])
}

fn browser_format(bytes: &[u8]) -> Result<ImageFormat, ImageProbeError> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Ok(ImageFormat::Png)
    } else if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        Ok(ImageFormat::Jpeg)
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Ok(ImageFormat::Gif)
    } else if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        Ok(ImageFormat::WebP)
    } else {
        Err(ImageProbeError::PasteUnavailable)
    }
}

fn reject_animation(format: ImageFormat, bytes: &[u8]) -> Result<(), ImageProbeError> {
    let animated = match format {
        ImageFormat::Png => bytes.windows(4).any(|chunk| chunk == b"acTL"),
        ImageFormat::WebP => bytes
            .windows(4)
            .any(|chunk| chunk == b"ANIM" || chunk == b"ANMF"),
        ImageFormat::Gif => gif_has_multiple_frames(bytes),
        ImageFormat::Jpeg => false,
        _ => true,
    };
    if animated {
        Err(ImageProbeError::PasteUnavailable)
    } else {
        Ok(())
    }
}

fn gif_has_multiple_frames(bytes: &[u8]) -> bool {
    let Some(packed) = bytes.get(10).copied() else {
        return true;
    };
    let global_table = if packed & 0x80 != 0 {
        3usize << (usize::from(packed & 0x07) + 1)
    } else {
        0
    };
    let Some(mut cursor) = 13usize.checked_add(global_table) else {
        return true;
    };
    let mut frames = 0;
    while let Some(marker) = bytes.get(cursor).copied() {
        cursor += 1;
        match marker {
            0x3b => return frames > 1,
            0x2c => {
                frames += 1;
                let Some(descriptor) = bytes.get(cursor..cursor + 9) else {
                    return true;
                };
                cursor += 9;
                if descriptor[8] & 0x80 != 0 {
                    cursor =
                        match cursor.checked_add(3usize << (usize::from(descriptor[8] & 7) + 1)) {
                            Some(cursor) => cursor,
                            None => return true,
                        };
                }
                if bytes.get(cursor).is_none() {
                    return true;
                }
                cursor += 1; // LZW minimum code size.
                if !skip_gif_sub_blocks(bytes, &mut cursor) {
                    return true;
                }
            }
            0x21 => {
                if bytes.get(cursor).is_none() {
                    return true;
                }
                cursor += 1; // extension label
                if !skip_gif_sub_blocks(bytes, &mut cursor) {
                    return true;
                }
            }
            _ => return true,
        }
    }
    true
}

fn skip_gif_sub_blocks(bytes: &[u8], cursor: &mut usize) -> bool {
    loop {
        let Some(size) = bytes.get(*cursor).copied().map(usize::from) else {
            return false;
        };
        *cursor += 1;
        if size == 0 {
            return true;
        }
        *cursor = match (*cursor).checked_add(size) {
            Some(next) if next <= bytes.len() => next,
            _ => return false,
        };
    }
}

fn validate_metadata(metadata: &Metadata) -> Result<(), ImageProbeError> {
    if !metadata.is_file() || metadata.len() > MAX_INPUT_BYTES {
        return Err(ImageProbeError::PasteUnavailable);
    }
    Ok(())
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> Result<File, ImageProbeError> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| ImageProbeError::PasteUnavailable)
}

#[cfg(windows)]
fn open_no_follow(path: &Path) -> Result<File, ImageProbeError> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| ImageProbeError::PasteUnavailable)
}

#[cfg(not(any(unix, windows)))]
fn open_no_follow(_path: &Path) -> Result<File, ImageProbeError> {
    Err(ImageProbeError::PasteUnavailable)
}

#[cfg(unix)]
fn same_file(before: &Metadata, after: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

#[cfg(windows)]
fn same_file(before: &Metadata, after: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    before.file_size() == after.file_size() && before.last_write_time() == after.last_write_time()
}

#[cfg(not(any(unix, windows)))]
fn same_file(_before: &Metadata, _after: &Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tui_browser_paste_format_policy() {
        assert_eq!(
            browser_format(b"\x89PNG\r\n\x1a\nrest").unwrap(),
            ImageFormat::Png
        );
        assert_eq!(
            browser_format(b"\xff\xd8\xffrest").unwrap(),
            ImageFormat::Jpeg
        );
        assert_eq!(browser_format(b"GIF87arest").unwrap(), ImageFormat::Gif);
        assert_eq!(browser_format(b"GIF89arest").unwrap(), ImageFormat::Gif);
        assert_eq!(
            browser_format(b"RIFF0000WEBPrest").unwrap(),
            ImageFormat::WebP
        );
        for bytes in [b"BMrest".as_slice(), b"II*\0rest", b"MM\0*rest"] {
            assert!(browser_format(bytes).is_err());
        }
    }

    #[test]
    fn browser_shell_image_path_interop() {
        let root = tempfile::tempdir().unwrap();
        let generation = root.path().join("a234567a234567a234567a2345");
        let binding = generation.join("b234567b234567b234567b2345");
        std::fs::create_dir_all(&binding).unwrap();
        let path = binding.join("c234567c234567c234567c2345.png");
        let image = image::RgbaImage::from_pixel(1, 1, image::Rgba([1, 2, 3, 255]));
        image::DynamicImage::ImageRgba8(image)
            .save_with_format(&path, ImageFormat::Png)
            .unwrap();
        let normalized = normalize_private_image(&path).unwrap();
        assert!(normalized.starts_with(b"\x89PNG\r\n\x1a\n"));
        let literal = format!("'{}'", path.display());
        assert_eq!(
            crate::tui::structured_paste::parse_private_image_path_literal(&literal),
            Some(path)
        );
    }
}

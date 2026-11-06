//! Lossless removal of what a picture says about itself (EXIF with the camera and the
//! place it was taken, XMP, IPTC, comments, text chunks) from JPEG, PNG and WebP, before
//! it is uploaded. No pixel is decoded: the segments or chunks that carry metadata are
//! left out and every other byte is copied as it is, so nothing is recompressed.
//!
//! Colour profiles stay (without them the colours shift). A JPEG keeps its orientation
//! in a minimal EXIF of its own, or a phone photo would arrive on its side; PNG and WebP
//! lose theirs with the rest (shortcut: only phones write it there, and they write JPEG
//! or HEIC; keep it there too if such files turn up). Data after a JPEG's end (a phone's
//! second picture, with an EXIF of its own) goes too. Anything else (HEIC, GIF, TIFF, a
//! malformed or truncated file) is left alone.

const PNG_SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";

/// Whether a file starting with these bytes is one [`strip`] reads (the first 12 bytes
/// decide).
pub fn is_supported(head: &[u8]) -> bool {
    head.starts_with(&[0xFF, 0xD8, 0xFF]) || head.starts_with(PNG_SIGNATURE) || is_webp(head)
}

fn is_webp(head: &[u8]) -> bool {
    head.len() >= 12 && &head[..4] == b"RIFF" && &head[8..12] == b"WEBP"
}

/// The picture without its metadata, or `None` when there was nothing to remove or the
/// file is not one this reads (it is then sent as it is).
pub fn strip(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.starts_with(&[0xFF, 0xD8]) {
        jpeg(bytes)
    } else if bytes.starts_with(PNG_SIGNATURE) {
        png(bytes)
    } else if is_webp(bytes) {
        webp(bytes)
    } else {
        None
    }
}

// ------------------------------------------------------------------ JPEG

fn jpeg(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(bytes.len());
    out.extend_from_slice(&[0xFF, 0xD8]);
    let mut removed = false;
    let mut orientation_written = false;
    let mut at = 2;
    loop {
        // A marker: 0xFF, any fill bytes, then its code.
        if bytes.get(at) != Some(&0xFF) {
            return None;
        }
        while bytes.get(at) == Some(&0xFF) {
            at += 1;
        }
        let code = *bytes.get(at)?;
        at += 1;
        match code {
            0xD9 => {
                out.extend_from_slice(&[0xFF, 0xD9]);
                removed |= at < bytes.len();
                break;
            }
            // Markers without a length.
            0x01 | 0xD0..=0xD7 => {
                out.extend_from_slice(&[0xFF, code]);
                continue;
            }
            _ => {}
        }
        let length = u16::from_be_bytes([*bytes.get(at)?, *bytes.get(at + 1)?]) as usize;
        if length < 2 {
            return None;
        }
        let end = at.checked_add(length)?;
        let payload = bytes.get(at + 2..end)?;
        let keep = match code {
            0xE0 => payload.starts_with(b"JFIF\0"),
            0xE2 => payload.starts_with(b"ICC_PROFILE\0"),
            // The colour transform of CMYK and YCCK pictures.
            0xEE => payload.starts_with(b"Adobe"),
            0xE1..=0xEF | 0xFE => false,
            _ => true,
        };
        if keep {
            out.extend_from_slice(&[0xFF, code]);
            out.extend_from_slice(&bytes[at..end]);
        } else {
            let mut replaced = false;
            if code == 0xE1
                && !orientation_written
                && let Some(value) = payload
                    .strip_prefix(b"Exif\0\0")
                    .and_then(exif_orientation)
            {
                // In the removed EXIF's place, where readers look for it.
                let written = orientation_segment(value);
                // Already nothing but the orientation: not a removal.
                replaced = written[4..] == *payload;
                out.extend_from_slice(&written);
                orientation_written = true;
            }
            removed |= !replaced;
        }
        at = end;
        if code == 0xDA {
            // Entropy-coded data: up to the next marker that is not a stuffed 0xFF or a
            // restart.
            let mut scan = at;
            loop {
                let ff = scan + bytes.get(scan..)?.iter().position(|&b| b == 0xFF)?;
                match *bytes.get(ff + 1)? {
                    0x00 | 0xD0..=0xD7 => scan = ff + 2,
                    _ => {
                        out.extend_from_slice(&bytes[at..ff]);
                        at = ff;
                        break;
                    }
                }
            }
        }
    }
    removed.then_some(out)
}

/// The orientation in an EXIF's first directory, when it turns the picture (2 to 8).
fn exif_orientation(tiff: &[u8]) -> Option<u16> {
    let little = match tiff.get(..2)? {
        b"II" => true,
        b"MM" => false,
        _ => return None,
    };
    let u16_at = |i: usize| {
        let b: [u8; 2] = tiff.get(i..i + 2)?.try_into().ok()?;
        Some(if little {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        })
    };
    let b: [u8; 4] = tiff.get(4..8)?.try_into().ok()?;
    let directory = if little {
        u32::from_le_bytes(b)
    } else {
        u32::from_be_bytes(b)
    } as usize;
    let count = u16_at(directory)? as usize;
    for n in 0..count {
        let entry = directory + 2 + n * 12;
        if u16_at(entry)? == 0x0112 {
            // A SHORT, in the first two bytes of the value field.
            let value = u16_at(entry + 8)?;
            return (2..=8).contains(&value).then_some(value);
        }
    }
    None
}

/// An APP1 segment holding an EXIF with the orientation and nothing else.
fn orientation_segment(value: u16) -> Vec<u8> {
    let mut exif = b"Exif\0\0II*\0".to_vec();
    exif.extend_from_slice(&8u32.to_le_bytes());
    exif.extend_from_slice(&1u16.to_le_bytes());
    exif.extend_from_slice(&0x0112u16.to_le_bytes());
    exif.extend_from_slice(&3u16.to_le_bytes());
    exif.extend_from_slice(&1u32.to_le_bytes());
    exif.extend_from_slice(&value.to_le_bytes());
    exif.extend_from_slice(&[0, 0]);
    exif.extend_from_slice(&0u32.to_le_bytes());
    let mut segment = vec![0xFF, 0xE1];
    segment.extend_from_slice(&((exif.len() + 2) as u16).to_be_bytes());
    segment.extend_from_slice(&exif);
    segment
}

// ------------------------------------------------------------------ PNG

fn png(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut out = PNG_SIGNATURE.to_vec();
    let mut removed = false;
    let mut at = PNG_SIGNATURE.len();
    loop {
        let length = u32::from_be_bytes(bytes.get(at..at + 4)?.try_into().ok()?) as usize;
        let kind = bytes.get(at + 4..at + 8)?;
        let end = at.checked_add(12)?.checked_add(length)?;
        let chunk = bytes.get(at..end)?;
        if matches!(kind, b"tEXt" | b"zTXt" | b"iTXt" | b"eXIf" | b"tIME") {
            removed = true;
        } else {
            out.extend_from_slice(chunk);
        }
        at = end;
        if kind == b"IEND" {
            removed |= at < bytes.len();
            break;
        }
    }
    removed.then_some(out)
}

// ------------------------------------------------------------------ WebP

/// The extended header's flags for an EXIF and an XMP chunk.
const WEBP_EXIF_FLAG: u8 = 0x08;
const WEBP_XMP_FLAG: u8 = 0x04;

fn webp(bytes: &[u8]) -> Option<Vec<u8>> {
    // RIFF, its size, WEBP, then chunks: a FourCC, a little-endian size, the data and a
    // pad byte to an even length.
    let declared = u32::from_le_bytes(bytes.get(4..8)?.try_into().ok()?) as usize;
    let end = 8usize.checked_add(declared)?;
    bytes.get(..end)?;
    let mut out = b"RIFF\0\0\0\0WEBP".to_vec();
    let mut removed = end < bytes.len();
    let mut at = 12;
    while at < end {
        let kind = bytes.get(at..at + 4)?;
        let size = u32::from_le_bytes(bytes.get(at + 4..at + 8)?.try_into().ok()?) as usize;
        let data_end = at.checked_add(8)?.checked_add(size)?;
        if data_end > end {
            return None;
        }
        if matches!(kind, b"EXIF" | b"XMP ") {
            removed = true;
        } else {
            let start = out.len();
            out.extend_from_slice(&bytes[at..data_end]);
            if kind == b"VP8X" && size > 0 {
                out[start + 8] &= !(WEBP_EXIF_FLAG | WEBP_XMP_FLAG);
            }
            if size % 2 == 1 {
                out.push(0);
            }
        }
        at = data_end + size % 2;
    }
    if !removed {
        return None;
    }
    let size = (out.len() - 8) as u32;
    out[4..8].copy_from_slice(&size.to_le_bytes());
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageFormat, RgbImage};

    fn picture() -> RgbImage {
        RgbImage::from_fn(16, 8, |x, y| image::Rgb([x as u8 * 15, y as u8 * 30, 128]))
    }

    fn encoded(format: ImageFormat) -> Vec<u8> {
        let mut out = std::io::Cursor::new(Vec::new());
        picture().write_to(&mut out, format).unwrap();
        out.into_inner()
    }

    fn segment(code: u8, payload: &[u8]) -> Vec<u8> {
        let mut s = vec![0xFF, code];
        s.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
        s.extend_from_slice(payload);
        s
    }

    /// A big-endian EXIF with the orientation and a GPS pointer, as cameras write it.
    fn camera_exif(orientation: u16) -> Vec<u8> {
        let mut e = b"Exif\0\0MM\0*".to_vec();
        e.extend_from_slice(&8u32.to_be_bytes());
        e.extend_from_slice(&2u16.to_be_bytes());
        e.extend_from_slice(&[0x01, 0x12, 0, 3, 0, 0, 0, 1]);
        e.extend_from_slice(&orientation.to_be_bytes());
        e.extend_from_slice(&[0, 0]);
        e.extend_from_slice(&[0x88, 0x25, 0, 4, 0, 0, 0, 1, 0, 0, 0, 0]);
        e.extend_from_slice(&0u32.to_be_bytes());
        e.extend_from_slice(b"Canon EOS secret place");
        e
    }

    fn decoded(bytes: &[u8]) -> image::RgbImage {
        image::load_from_memory(bytes).unwrap().to_rgb8()
    }

    #[test]
    fn a_jpeg_loses_its_metadata_but_not_its_pixels_or_orientation() {
        let plain = encoded(ImageFormat::Jpeg);
        assert_eq!(strip(&plain), None, "the app's own JPEG carries nothing");
        let mut marked = plain[..2].to_vec();
        marked.extend(segment(0xE1, &camera_exif(6)));
        marked.extend(segment(0xE1, b"http://ns.adobe.com/xap/1.0/\0<x:xmpmeta secret/>"));
        marked.extend(segment(0xED, b"Photoshop 3.0\0secret"));
        marked.extend(segment(0xFE, b"secret comment"));
        marked.extend_from_slice(&plain[2..]);
        marked.extend_from_slice(b"\xFF\xD8 a second picture with a secret EXIF");
        assert!(is_supported(&marked));
        let clean = strip(&marked).unwrap();
        assert_eq!(decoded(&clean), decoded(&plain));
        assert!(!clean.windows(6).any(|w| w == b"secret"));
        assert!(clean.ends_with(&[0xFF, 0xD9]));
        let exif = clean
            .windows(6)
            .position(|w| w == b"Exif\0\0")
            .expect("the orientation stays");
        assert_eq!(exif_orientation(&clean[exif + 6..]), Some(6));
        assert_eq!(strip(&clean), None, "stripping twice changes nothing more");
    }

    #[test]
    fn an_upright_jpeg_keeps_no_exif_at_all() {
        let plain = encoded(ImageFormat::Jpeg);
        let mut marked = plain[..2].to_vec();
        marked.extend(segment(0xE1, &camera_exif(1)));
        marked.extend_from_slice(&plain[2..]);
        let clean = strip(&marked).unwrap();
        assert!(!clean.windows(4).any(|w| w == b"Exif"));
        assert_eq!(clean, plain);
    }

    #[test]
    fn a_png_loses_its_text_and_exif_chunks_and_nothing_else() {
        let plain = encoded(ImageFormat::Png);
        assert_eq!(strip(&plain), None);
        // After IHDR (8 + 25 bytes); the CRCs of chunks that go are never read.
        let chunk = |kind: &[u8], data: &[u8]| {
            let mut c = (data.len() as u32).to_be_bytes().to_vec();
            c.extend_from_slice(kind);
            c.extend_from_slice(data);
            c.extend_from_slice(&[0; 4]);
            c
        };
        let mut marked = plain[..33].to_vec();
        marked.extend(chunk(b"tEXt", b"Author\0secret"));
        marked.extend(chunk(b"eXIf", b"MM\0*secret"));
        marked.extend(chunk(b"iTXt", b"XML:com.adobe.xmp\0\0\0\0\0secret"));
        marked.extend_from_slice(&plain[33..]);
        marked.extend_from_slice(b"secret after the end");
        assert!(is_supported(&marked));
        assert_eq!(strip(&marked).unwrap(), plain);
    }

    #[test]
    fn a_webp_loses_its_exif_and_xmp_and_their_flags() {
        let simple = encoded(ImageFormat::WebP);
        assert_eq!(strip(&simple), None);
        let bitstream = &simple[12..];
        let chunk = |kind: &[u8], data: &[u8]| {
            let mut c = kind.to_vec();
            c.extend_from_slice(&(data.len() as u32).to_le_bytes());
            c.extend_from_slice(data);
            if data.len() % 2 == 1 {
                c.push(0);
            }
            c
        };
        let mut vp8x = vec![WEBP_EXIF_FLAG | WEBP_XMP_FLAG, 0, 0, 0];
        vp8x.extend_from_slice(&15u32.to_le_bytes()[..3]);
        vp8x.extend_from_slice(&7u32.to_le_bytes()[..3]);
        let mut marked = b"RIFF\0\0\0\0WEBP".to_vec();
        marked.extend(chunk(b"VP8X", &vp8x));
        marked.extend_from_slice(bitstream);
        marked.extend(chunk(b"EXIF", b"MM\0*odd secret"));
        marked.extend(chunk(b"XMP ", b"<x:xmpmeta secret/>"));
        let size = (marked.len() - 8) as u32;
        marked[4..8].copy_from_slice(&size.to_le_bytes());
        assert!(is_supported(&marked));
        let clean = strip(&marked).unwrap();
        assert!(!clean.windows(6).any(|w| w == b"secret"));
        assert_eq!(clean[20] & (WEBP_EXIF_FLAG | WEBP_XMP_FLAG), 0);
        assert_eq!(
            u32::from_le_bytes(clean[4..8].try_into().unwrap()) as usize,
            clean.len() - 8
        );
        assert_eq!(decoded(&clean), decoded(&simple));
    }

    #[test]
    fn other_and_broken_files_are_left_alone() {
        assert!(!is_supported(b"GIF89a\x01\0\x01\0"));
        assert_eq!(strip(b"GIF89a\x01\0\x01\0"), None);
        let mut marked = vec![0xFF, 0xD8];
        marked.extend(segment(0xFE, b"comment"));
        let truncated = &marked[..marked.len() - 3];
        assert_eq!(strip(truncated), None);
        assert_eq!(strip(&marked), None, "no end of image: not touched");
        assert_eq!(strip(b"RIFF\xFF\xFF\xFF\x7FWEBPVP8X"), None);
    }
}

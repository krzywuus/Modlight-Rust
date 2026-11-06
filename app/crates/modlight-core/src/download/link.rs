//! An address the Download tab is willing to hand to yt-dlp (`DownloadLink`).
//!
//! "The person typed something" and "we are about to put this on a command line" are
//! different types, and the only way from one to the other is [`DownloadLink::parse`].
//! A whitelist: absolute http or https with a real host, or nothing - yt-dlp accepts far
//! more than http (`file:` would read local files, the search prefixes do things nobody
//! pasting a video link asked for). No site list: yt-dlp knows eighteen hundred
//! extractors, and a client-side list could only refuse links that would have worked.

use url::Url;

/// Longer than any real address, short enough that a paste accident cannot become a
/// command line the system has to think about.
pub const MAX_LENGTH: usize = 2048;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DownloadLink {
    /// The address, exactly as it will be passed to yt-dlp (the parsed, normalised form).
    pub url: String,
    /// The site, for the queue row: "youtube.com", "tiktok.com".
    pub source: String,
    /// Decides the codec preference and whether the YouTube sign-in is used.
    pub is_youtube: bool,
    /// fuckingfast.co: fetched by `filehost`, not by yt-dlp.
    pub is_file_host: bool,
}

impl DownloadLink {
    pub fn parse(input: &str) -> Option<DownloadLink> {
        let value = input.trim();
        if value.is_empty() || value.chars().count() > MAX_LENGTH {
            return None;
        }
        let url = Url::parse(value).ok()?;
        if url.scheme() != "http" && url.scheme() != "https" {
            return None;
        }
        let host = url.host_str()?.to_ascii_lowercase();
        if host.is_empty() {
            return None;
        }
        // userinfo is not part of a video address and has no business on a command line.
        if !url.username().is_empty() || url.password().is_some() {
            return None;
        }
        let source = host.strip_prefix("www.").unwrap_or(&host).to_string();
        Some(DownloadLink {
            url: url.to_string(),
            is_youtube: is_youtube_host(&host),
            is_file_host: super::filehost::is_host(&host),
            source,
        })
    }
}

/// Every address in a pasted text, in order, each once (`load_links` of ff_dl.py): a
/// line starting with `#` is a comment, and around an address anything may stand (a
/// list's numbering, a file name after a tab).
pub fn links_in(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let mut rest = line;
        while let Some(at) = [rest.find("http://"), rest.find("https://")]
            .into_iter()
            .flatten()
            .min()
        {
            let tail = &rest[at..];
            let end = tail
                .find(|c: char| c.is_whitespace() || matches!(c, '<' | '>' | '"' | '\''))
                .unwrap_or(tail.len());
            let link = tail[..end].trim_end_matches([')', ',', '.', ';']);
            if !out.iter().any(|seen| seen == link) {
                out.push(link.to_string());
            }
            rest = &tail[end..];
        }
    }
    out
}

/// Suffix matching with the dot included, never `contains`: "youtube.com.example.org"
/// belongs to somebody else.
pub fn is_youtube_host(host: &str) -> bool {
    ["youtube.com", "youtu.be", "youtube-nocookie.com"]
        .iter()
        .any(|domain| host == *domain || host.ends_with(&format!(".{domain}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn video_addresses_are_accepted_and_normalised() {
        let link = DownloadLink::parse("  https://www.YouTube.com/watch?v=dQw4w9WgXcQ  ").unwrap();
        assert_eq!(link.url, "https://www.youtube.com/watch?v=dQw4w9WgXcQ");
        assert_eq!(link.source, "youtube.com");
        assert!(link.is_youtube);
        let short = DownloadLink::parse("https://youtu.be/dQw4w9WgXcQ").unwrap();
        assert!(short.is_youtube);
        let music = DownloadLink::parse("https://music.youtube.com/watch?v=x").unwrap();
        assert!(music.is_youtube);
        let tiktok = DownloadLink::parse("https://www.tiktok.com/@a/video/1").unwrap();
        assert_eq!(tiktok.source, "tiktok.com");
        assert!(!tiktok.is_youtube);
        let bare = DownloadLink::parse("http://example.com").unwrap();
        assert_eq!(bare.url, "http://example.com/");
    }

    #[test]
    fn everything_else_is_refused() {
        for bad in [
            "",
            "   ",
            "youtube.com/watch?v=x",
            "file:///etc/passwd",
            "ftp://example.com/a.mp4",
            "ytsearch:never gonna",
            "-o /tmp/x https://example.com",
            "--exec=rm https://example.com",
            "javascript:alert(1)",
            "http://",
            "https://user:secret@example.com/v",
            "data:text/plain,hi",
        ] {
            assert!(DownloadLink::parse(bad).is_none(), "accepted {bad:?}");
        }
        let long = format!("https://example.com/{}", "a".repeat(MAX_LENGTH));
        assert!(DownloadLink::parse(&long).is_none());
    }

    #[test]
    fn pasted_lists_give_their_addresses_once_each() {
        use crate::download::filehost::HOST;
        let file = format!("https://{HOST}/w674u09fbhw0#Archive.part1.rar");
        let text = format!(
            "# https://{HOST}/f/AbCdEf123 is an example\r\n\
             1. {file}\r\n\
             \t{file}\n\
             (see https://youtu.be/x), and http://example.com/a.\n\
             two on a line: https://a.example/1 https://b.example/2"
        );
        assert_eq!(
            links_in(&text),
            [
                file.as_str(),
                "https://youtu.be/x",
                "http://example.com/a",
                "https://a.example/1",
                "https://b.example/2",
            ]
        );
        assert!(links_in("no links here").is_empty());
        let host = DownloadLink::parse(&file).unwrap();
        assert!(host.is_file_host && !host.is_youtube);
        let direct = DownloadLink::parse(&format!("https://dl.{HOST}/x")).unwrap();
        assert!(direct.is_file_host);
        let look_alike = DownloadLink::parse(&format!("https://{HOST}.evil.example/f/x")).unwrap();
        assert!(!look_alike.is_file_host);
    }

    #[test]
    fn a_look_alike_host_is_not_youtube() {
        assert!(!is_youtube_host("youtube.com.example.org"));
        assert!(!is_youtube_host("notyoutube.com"));
        assert!(is_youtube_host("m.youtube.com"));
        assert!(is_youtube_host("www.youtube-nocookie.com"));
    }
}

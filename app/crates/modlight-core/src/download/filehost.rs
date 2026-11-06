//! Direct downloads from the file host fuckingfast.co, as the bulk downloader `ff_dl.py`
//! does them: the file's page, then what its DOWNLOAD button does (`POST /f/<id>/go`
//! with HTMX's headers, answered with the direct link in `HX-Redirect`), then the file,
//! resumed from its `.part` where the server allows a range and started again where it
//! does not.
//!
//! The site's bot protection challenges a client whose TLS and HTTP/2 do not look
//! like a browser's (rustls included). The requests go through `wreq`, which
//! looks like one: a recent Chrome or Edge profile (see `engine::PROFILES` for what
//! passed and when), or the one chosen on the bulk page. Automatic moves every run on to
//! the next profile after a challenge.
//!
//! Windows only for now: BoringSSL, under `wreq`, needs cmake (and nasm) to build, which
//! the Mac build does not have; there the row says so.

// Off Windows only the tests use what the engine would.
#![cfg_attr(not(windows), allow(dead_code))]

use std::path::PathBuf;
use std::sync::{Arc, LazyLock};

use regex::Regex;
use tokio_util::sync::CancellationToken;
use url::Url;

use super::link::DownloadLink;
use super::run::{Outcome, Progress, RunEvent};
use crate::l10n::{Arg, format, s, t};

/// The file host's domain, spelled here only.
macro_rules! host {
    () => {
        "fuckingfast.co"
    };
}
pub const HOST: &str = host!();
const SITE: &str = concat!("https://", host!());
/// The name the site puts after a page's title (what `page_title` takes off).
const SITE_NAME: &str = "Fucking Fast";

/// What the protection's challenge page says, for an answer without `cf-mitigated`.
const CHALLENGE_MARKERS: [&str; 6] = [
    "Just a moment",
    "Verifying you are human",
    "cf-chl",
    "challenge-platform",
    "__cf_chl_",
    "Attention Required",
];

/// The browser profiles the bulk page offers besides Automatic, newest first, by their
/// names in `wreq-util` (`Chrome149`). Automatic rotates through `engine::PROFILES`.
pub const BROWSER_PROFILES: [&str; 17] = [
    "Chrome149", "Chrome148", "Chrome147", "Chrome146", "Chrome145", "Chrome144",
    "Chrome142", "Chrome140", "Chrome136", "Chrome131", "Edge148", "Edge147", "Edge146",
    "Edge145", "Edge140", "Edge134", "Edge131",
];

/// A profile's name as a person reads it: `Chrome149` is "Chrome 149".
pub fn profile_label(name: &str) -> String {
    match name.find(|c: char| c.is_ascii_digit()) {
        Some(at) => format!("{} {}", &name[..at], &name[at..]),
        None => name.to_string(),
    }
}

/// Whether a host is the file host's (suffix match with the dot, never `contains`).
pub fn is_host(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    host == HOST || host.ends_with(&format!(".{HOST}"))
}

/// An address that already is the direct link: `dl.<host>/...` or `<host>/dl/...`
/// (valid for about a day).
fn is_direct(url: &Url) -> bool {
    let host = url.host_str().unwrap_or("").to_ascii_lowercase();
    host == format!("dl.{HOST}")
        || ((host == HOST || host == format!("www.{HOST}")) && url.path().starts_with("/dl/"))
}

/// The file's id in `/f/<id>` or `/<id>`.
fn file_id(url: &Url) -> Option<String> {
    let path = url.path().trim_matches('/');
    let path = path.strip_prefix("f/").unwrap_or(path);
    let id = path.split('/').next()?;
    let valid = !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    valid.then(|| id.to_string())
}

/// The few entities a page title holds.
fn unescape(text: &str) -> String {
    text.replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&#x27;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// The page's title (`og:title`, else `<title>`) without the site's name after it: the
/// file's name until the server says better.
fn page_title(html: &str) -> Option<String> {
    static OG: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?i)<meta[^>]+property=["']og:title["'][^>]+content=["']([^"']+)"#)
            .unwrap()
    });
    static TITLE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?is)<title[^>]*>(.*?)</title>").unwrap());
    static SUFFIX: LazyLock<Regex> = LazyLock::new(|| {
        let name = regex::escape(SITE_NAME).replace(' ', r"\s*");
        Regex::new(&format!(r"(?i)\s*[-\u{{2013}}\u{{2014}}|]\s*{name}\s*$")).unwrap()
    });
    let found = OG.captures(html).or_else(|| TITLE.captures(html))?;
    let title = unescape(found.get(1)?.as_str().trim());
    let title = SUFFIX.replace(&title, "").trim().to_string();
    (!title.is_empty()).then_some(title)
}

/// The direct link in the answer to `/go`: HTMX's redirect header, the address the
/// answer ended at, or one in its body. Only an https address of the host itself is
/// taken, so a page cannot send the download anywhere else.
fn direct_link(hx_redirect: Option<&str>, final_url: &str, body: &str) -> Option<String> {
    static IN_BODY: LazyLock<Regex> = LazyLock::new(|| {
        let host = regex::escape(HOST);
        Regex::new(&format!(r#"https://(?:dl\.)?{host}/dl/[^\s"'<>]+"#)).unwrap()
    });
    let ended_there = Url::parse(final_url).is_ok_and(|u| is_direct(&u));
    [
        hx_redirect.map(str::trim).map(str::to_string),
        ended_there.then(|| final_url.to_string()),
        IN_BODY.find(body).map(|m| m.as_str().to_string()),
    ]
    .into_iter()
    .flatten()
    .find(|link| {
        Url::parse(link)
            .is_ok_and(|u| u.scheme() == "https" && u.host_str().is_some_and(is_host))
    })
}

/// The file's name: the server's (`filename*` first, then `filename`), the address's
/// last segment, the page's title; cleaned for the file system, at most 200 characters.
fn file_name(disposition: Option<&str>, url: &str, hint: Option<&str>) -> String {
    static EXTENDED: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"(?i)filename\*\s*=\s*UTF-8''([^;]+)"#).unwrap());
    let decode = |text: &str| {
        percent_encoding::percent_decode_str(text)
            .decode_utf8_lossy()
            .into_owned()
    };
    let from_server = disposition.and_then(|value| {
        EXTENDED
            .captures(value)
            .map(|c| decode(c[1].trim_matches(['"', ' '])))
            .or_else(|| modlight_api::web::file_name_from_disposition(value))
    });
    let from_url = Url::parse(url).ok().and_then(|u| {
        u.path_segments()?
            .filter(|segment| !segment.is_empty())
            .next_back()
            .map(decode)
    });
    let raw = from_server
        .or(from_url)
        .or_else(|| hint.map(str::to_string))
        .unwrap_or_default();
    let last = raw.rsplit(['/', '\\']).next().unwrap_or("");
    let clean: String = crate::names::file_helpers::sanitize_file_name(last)
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim_matches([' ', '.'])
        .chars()
        .take(200)
        .collect();
    if clean.is_empty() {
        "download.bin".into()
    } else {
        clean
    }
}

/// The whole file's size: the total of `Content-Range`, else `Content-Length`.
fn total_size(content_range: Option<&str>, content_length: Option<&str>) -> Option<u64> {
    content_range
        .and_then(|range| range.rsplit('/').next())
        .and_then(|total| total.trim().parse().ok())
        .or_else(|| content_length.and_then(|length| length.trim().parse().ok()))
}

/// The protection stopped the request: it says so in `cf-mitigated`, or a 403 or 503 is
/// its challenge page.
fn is_challenge(status: u16, mitigated: Option<&str>, body: &str) -> bool {
    if mitigated.is_some_and(|m| matches!(m.trim().to_ascii_lowercase().as_str(), "challenge" | "block")) {
        return true;
    }
    matches!(status, 403 | 503) && {
        let head = body.get(..4096.min(body.len())).unwrap_or(body);
        CHALLENGE_MARKERS.iter().any(|marker| head.contains(marker))
    }
}

/// How far along, from the bytes on disk and the speed of this run.
fn progress(downloaded: u64, total: Option<u64>, speed: f64) -> Progress {
    let percent = match total {
        Some(total) if total > 0 => (downloaded as f64 * 100.0 / total as f64).clamp(0.0, 100.0),
        _ => 0.0,
    };
    let eta = match total {
        Some(total) if speed > 1024.0 => ((total.saturating_sub(downloaded)) as f64 / speed) as i32,
        _ => -1,
    };
    Progress {
        percent,
        downloaded: downloaded as i64,
        total: total.unwrap_or(0) as i64,
        speed,
        eta,
        is_working: false,
    }
}

/// Everything one run is made of.
#[derive(Clone, Debug)]
pub struct HostSpec {
    pub link: DownloadLink,
    pub folder: PathBuf,
    /// One of [`BROWSER_PROFILES`] to use alone, or `None` for Automatic.
    pub profile: Option<String>,
}

/// Fetch the file of `spec` into its folder. `events` hears the name and the progress;
/// cancelling `cancel` stops it and keeps the `.part` for the next run.
pub async fn run(
    spec: &HostSpec,
    events: Arc<dyn Fn(RunEvent) + Send + Sync>,
    cancel: &CancellationToken,
) -> Outcome {
    #[cfg(windows)]
    {
        engine::run(spec, events, cancel).await
    }
    #[cfg(not(windows))]
    {
        let _ = (spec, events, cancel);
        Outcome {
            error: t(s::Download_HostUnsupported).to_string(),
            ..Outcome::default()
        }
    }
}

/// Why a run did not end with a file.
#[derive(Debug, PartialEq)]
enum Failure {
    Challenge,
    Gone,
    NotAFile,
    NoLink(u16),
    Status(u16),
    Short(u64, u64),
    Busy,
    Network(String),
    Disk(String),
    Canceled,
}

impl Failure {
    /// Worth another try after a pause.
    fn retry(&self) -> bool {
        matches!(
            self,
            Failure::NoLink(_) | Failure::Status(_) | Failure::Short(..) | Failure::Network(_)
        )
    }

    fn message(&self) -> String {
        match self {
            Failure::Challenge => t(s::Download_HostChallenge).to_string(),
            Failure::Gone => t(s::Download_HostGone).to_string(),
            Failure::NotAFile => t(s::Download_HostNotAFile).to_string(),
            Failure::NoLink(status) => format(t(s::Download_HostNoLink), &[Arg::from(*status as i64)]),
            Failure::Status(status) => format(t(s::Download_HostStatus), &[Arg::from(*status as i64)]),
            Failure::Short(have, want) => format(
                t(s::Download_HostShort),
                &[Arg::from(*have as i64), Arg::from(*want as i64)],
            ),
            Failure::Busy => t(s::Download_HostBusy).to_string(),
            Failure::Network(error) | Failure::Disk(error) => {
                format(t(s::Download_ErrorRaw), &[Arg::from(error.as_str())])
            }
            Failure::Canceled => String::new(),
        }
    }
}

#[cfg(windows)]
mod engine {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use futures_util::StreamExt;
    use tokio::io::AsyncWriteExt;
    use tokio_util::sync::CancellationToken;
    use url::Url;
    use wreq_util::{Emulation, Platform, Profile};

    use super::*;

    /// Profiles let through to `/go` and to the file, the newest first. Measured
    /// on a real file in November 2026: Chrome 140 and 144 to 149, Edge 140 to 148 passed
    /// (their file page was challenged, which `resolve` lives with); Chrome 142 and
    /// everything up to 131 were challenged on `/go`.
    pub(super) const PROFILES: [Profile; 6] = [
        Profile::Chrome149,
        Profile::Chrome148,
        Profile::Edge148,
        Profile::Chrome146,
        Profile::Chrome145,
        Profile::Chrome140,
    ];
    /// The profile in use, for every run: one challenged moves them all on.
    static PROFILE: AtomicUsize = AtomicUsize::new(0);
    /// Tries after a failure that may pass (a network error, a short read): `ff_dl.py`'s
    /// six attempts.
    const TRIES: u32 = 5;
    /// A challenge is tried again after this long (`ff_dl.py`: "chwilowy challenge").
    const CHALLENGE_PAUSE: Duration = Duration::from_secs(5);
    /// The pause between two resolutions, which never run at once (`--delay`).
    const BETWEEN_LINKS: Duration = Duration::from_secs(1);
    /// When the last resolution ended. Held while resolving: `ff_dl.py` resolves its
    /// links one after another, calmly, however many files download meanwhile.
    static RESOLVING: tokio::sync::Mutex<Option<Instant>> = tokio::sync::Mutex::const_new(None);
    /// Files being written, so two rows never write the same one (lower case: the file
    /// system ignores case).
    static CLAIMED: Mutex<Vec<String>> = Mutex::new(Vec::new());

    struct Claim(String);

    impl Claim {
        fn take(path: &Path) -> Option<Claim> {
            let key = path.to_string_lossy().to_lowercase();
            let mut claimed = CLAIMED.lock().unwrap_or_else(|e| e.into_inner());
            if claimed.contains(&key) {
                return None;
            }
            claimed.push(key.clone());
            Some(Claim(key))
        }
    }

    impl Drop for Claim {
        fn drop(&mut self) {
            CLAIMED
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .retain(|k| *k != self.0);
        }
    }

    fn network(error: wreq::Error) -> Failure {
        Failure::Network(error.to_string())
    }

    fn disk(error: std::io::Error) -> Failure {
        Failure::Disk(error.to_string())
    }

    fn header(response: &wreq::Response, name: &str) -> Option<String> {
        response.headers().get(name)?.to_str().ok().map(str::to_string)
    }

    /// A client with the profile in use, and which one it is.
    fn client() -> Result<(wreq::Client, usize), Failure> {
        let index = PROFILE.load(Ordering::SeqCst) % PROFILES.len();
        Ok((client_for(PROFILES[index])?, index))
    }

    pub(super) fn client_for(profile: Profile) -> Result<wreq::Client, Failure> {
        let emulation = Emulation::builder()
            .profile(profile)
            .platform(Platform::Windows)
            .build();
        wreq::Client::builder()
            .emulation(emulation)
            .cookie_store(true)
            .connect_timeout(Duration::from_secs(15))
            .read_timeout(Duration::from_secs(60))
            .build()
            .map_err(network)
    }

    /// The profile of this name in `wreq-util` (its `Debug` name: no parsing there).
    pub(super) fn profile_named(name: &str) -> Option<Profile> {
        Profile::VARIANTS
            .iter()
            .copied()
            .find(|profile| format!("{profile:?}") == name)
    }

    /// Profile `index` was challenged: the next one, for every run (once, however many
    /// runs saw it).
    fn challenged(index: usize) {
        let _ = PROFILE.compare_exchange(index, index + 1, Ordering::SeqCst, Ordering::SeqCst);
    }

    pub(super) async fn run(
        spec: &HostSpec,
        events: Arc<dyn Fn(RunEvent) + Send + Sync>,
        cancel: &CancellationToken,
    ) -> Outcome {
        if let Err(error) = std::fs::create_dir_all(&spec.folder) {
            return Outcome {
                error: format(
                    t(s::Download_ErrorFolder),
                    &[
                        Arg::from(spec.folder.display().to_string()),
                        Arg::from(error.to_string()),
                    ],
                ),
                ..Outcome::default()
            };
        }
        let result = tokio::select! {
            result = attempts(spec, &events) => result,
            _ = cancel.cancelled() => Err(Failure::Canceled),
        };
        match result {
            Ok(path) => Outcome {
                success: true,
                title: path.file_name().map(|n| n.to_string_lossy().into_owned()),
                file_path: Some(path),
                ..Outcome::default()
            },
            Err(Failure::Canceled) => Outcome {
                canceled: true,
                ..Outcome::default()
            },
            Err(failure) => {
                log::info!("Download: {} failed for {}: {failure:?}", HOST, spec.link.url);
                Outcome {
                    error: failure.message(),
                    ..Outcome::default()
                }
            }
        }
    }

    async fn attempts(
        spec: &HostSpec,
        events: &Arc<dyn Fn(RunEvent) + Send + Sync>,
    ) -> Result<PathBuf, Failure> {
        let link = Url::parse(&spec.link.url).map_err(|_| Failure::NotAFile)?;
        let chosen = spec.profile.as_deref().and_then(profile_named);
        // Automatic tries every profile; a chosen one is tried again twice, as
        // `ff_dl.py` does before it gives up.
        let most_challenges = if chosen.is_some() { 2 } else { PROFILES.len() };
        let mut resolved: Option<(String, Option<String>)> = None;
        let mut challenges = 0;
        let mut tries = 0;
        loop {
            let (client, rotating) = match chosen {
                Some(profile) => (client_for(profile)?, None),
                None => {
                    let (client, index) = client()?;
                    (client, Some(index))
                }
            };
            let step = match resolved.clone() {
                Some(found) => Ok(found),
                None => {
                    let mut last = RESOLVING.lock().await;
                    if let Some(ended) = *last {
                        tokio::time::sleep(BETWEEN_LINKS.saturating_sub(ended.elapsed())).await;
                    }
                    let found = resolve(&client, &link).await;
                    *last = Some(Instant::now());
                    found
                }
            };
            let step = match step {
                Ok(found) => {
                    resolved = Some(found.clone());
                    fetch(&client, &found.0, &spec.folder, found.1.as_deref(), events).await
                }
                Err(failure) => Err(failure),
            };
            let failure = match step {
                Ok(path) => return Ok(path),
                Err(failure) => failure,
            };
            if failure == Failure::Challenge && challenges < most_challenges {
                challenges += 1;
                match rotating {
                    Some(index) => {
                        challenged(index);
                        log::info!(
                            "Download: {HOST} challenged {:?}; the next browser profile",
                            PROFILES[index % PROFILES.len()]
                        );
                    }
                    None => log::info!("Download: {HOST} challenged {chosen:?}; again in a moment"),
                }
                tokio::time::sleep(CHALLENGE_PAUSE).await;
                continue;
            }
            if !failure.retry() || tries >= TRIES {
                return Err(failure);
            }
            tries += 1;
            if matches!(failure, Failure::Status(_)) {
                // The direct link may have expired: ask the page again.
                resolved = None;
            }
            tokio::time::sleep(Duration::from_secs(2 * tries as u64)).await;
        }
    }

    /// The direct link and the page's title (`resolve_direct`).
    async fn resolve(
        client: &wreq::Client,
        link: &Url,
    ) -> Result<(String, Option<String>), Failure> {
        if is_direct(link) {
            return Ok((link.to_string(), None));
        }
        let id = file_id(link).ok_or(Failure::NotAFile)?;
        let page_url = format!("{SITE}/f/{id}");
        let page = client.get(&page_url).send().await.map_err(network)?;
        let status = page.status().as_u16();
        let mitigated = header(&page, "cf-mitigated");
        let html = page.text().await.map_err(network)?;
        // The page only names the file; the profiles `/go` lets through see it
        // challenged, and the button's request goes through all the same.
        let hint = if is_challenge(status, mitigated.as_deref(), &html) {
            None
        } else if status == 405 {
            // What the site answers for an id it does not know.
            return Err(Failure::Gone);
        } else if status != 200 {
            return Err(Failure::Status(status));
        } else {
            page_title(&html)
        };
        let current = page_url;
        // What the DOWNLOAD button does.
        let go = client
            .post(format!("{SITE}/f/{id}/go"))
            .header("hx-request", "true")
            .header("hx-current-url", current.as_str())
            .header("referer", current.as_str())
            .header("origin", SITE)
            .header(
                "content-type",
                "application/x-www-form-urlencoded; charset=UTF-8",
            )
            .body("cf-turnstile-response=")
            .send()
            .await
            .map_err(network)?;
        let status = go.status().as_u16();
        let mitigated = header(&go, "cf-mitigated");
        let redirect = header(&go, "hx-redirect").or_else(|| header(&go, "x-hx-redirect"));
        let ended = go.uri().to_string();
        let body = go.text().await.map_err(network)?;
        if is_challenge(status, mitigated.as_deref(), &body) {
            return Err(Failure::Challenge);
        }
        if matches!(status, 404 | 405) {
            // An id the site does not know, asked through the button.
            return Err(Failure::Gone);
        }
        direct_link(redirect.as_deref(), &ended, &body)
            .map(|direct| (direct, hint))
            .ok_or(Failure::NoLink(status))
    }

    /// An answer that is not the file: a challenge (by its header; a file's body is not
    /// read for markers) or another status.
    fn check(response: &wreq::Response) -> Result<(), Failure> {
        let status = response.status().as_u16();
        if is_challenge(status, header(response, "cf-mitigated").as_deref(), "") {
            return Err(Failure::Challenge);
        }
        if !matches!(status, 200 | 206) {
            return Err(Failure::Status(status));
        }
        Ok(())
    }

    async fn get(
        client: &wreq::Client,
        direct: &str,
        range: Option<u64>,
    ) -> Result<wreq::Response, Failure> {
        let mut request = client.get(direct).header("referer", format!("{SITE}/"));
        if let Some(start) = range {
            request = request.header("range", format!("bytes={start}-"));
        }
        request.send().await.map_err(network)
    }

    /// The file into `folder` (`_download_once`): its name from the first answer, then
    /// on from the `.part` where the server takes a range, from zero where it does not.
    async fn fetch(
        client: &wreq::Client,
        direct: &str,
        folder: &Path,
        hint: Option<&str>,
        events: &Arc<dyn Fn(RunEvent) + Send + Sync>,
    ) -> Result<PathBuf, Failure> {
        // A plain request first, as a browser's: the protection challenges probes such as
        // `Range: bytes=0-0`.
        let first = get(client, direct, None).await?;
        check(&first)?;
        let name = file_name(
            header(&first, "content-disposition").as_deref(),
            direct,
            hint,
        );
        let total = total_size(
            header(&first, "content-range").as_deref(),
            header(&first, "content-length").as_deref(),
        );
        let target = folder.join(&name);
        let part = folder.join(format!("{name}.part"));
        let _claim = Claim::take(&target).ok_or(Failure::Busy)?;
        events(RunEvent::Title(name.clone()));
        if let Ok(meta) = std::fs::metadata(&target)
            && meta.is_file()
            && total.is_none_or(|total| meta.len() == total)
        {
            return Ok(target);
        }
        let mut start = std::fs::metadata(&part).map(|m| m.len()).unwrap_or(0);
        if let Some(total) = total {
            if start == total {
                std::fs::rename(&part, &target).map_err(disk)?;
                return Ok(target);
            }
            if start > total {
                start = 0;
            }
        }
        let response = if start == 0 {
            first
        } else {
            drop(first);
            let ranged = get(client, direct, Some(start)).await?;
            if ranged.status().as_u16() == 416 {
                // The .part is whole already.
                std::fs::rename(&part, &target).map_err(disk)?;
                return Ok(target);
            }
            if ranged.status().as_u16() == 206 && check(&ranged).is_ok() {
                ranged
            } else {
                // No resuming here (some ranges are refused): from the start.
                drop(ranged);
                start = 0;
                let fresh = get(client, direct, None).await?;
                check(&fresh)?;
                fresh
            }
        };
        events(RunEvent::Progress(progress(start, total, 0.0)));
        let mut file = if start > 0 {
            tokio::fs::OpenOptions::new()
                .append(true)
                .open(&part)
                .await
        } else {
            tokio::fs::File::create(&part).await
        }
        .map_err(disk)?;
        let mut stream = response.bytes_stream();
        let started = Instant::now();
        let mut reported = Instant::now();
        let mut done = 0u64;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(network)?;
            file.write_all(&chunk).await.map_err(disk)?;
            done += chunk.len() as u64;
            if reported.elapsed() >= Duration::from_millis(500) {
                reported = Instant::now();
                let speed = done as f64 / started.elapsed().as_secs_f64().max(0.001);
                events(RunEvent::Progress(progress(start + done, total, speed)));
            }
        }
        file.flush().await.map_err(disk)?;
        drop(file);
        let have = start + done;
        if let Some(total) = total
            && have != total
        {
            return Err(Failure::Short(have, total));
        }
        std::fs::rename(&part, &target).map_err(disk)?;
        Ok(target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(text: &str) -> Url {
        Url::parse(text).unwrap()
    }

    #[test]
    fn file_pages_and_direct_links_are_told_apart() {
        let page = url(&format!("https://{HOST}/w674u09fbhw0#Archive.part1.rar"));
        assert_eq!(file_id(&page).as_deref(), Some("w674u09fbhw0"));
        assert!(!is_direct(&page));
        let classic = url(&format!("https://{HOST}/f/AbC-d_9/"));
        assert_eq!(file_id(&classic).as_deref(), Some("AbC-d_9"));
        assert_eq!(file_id(&url(&format!("https://{HOST}/f/a.b"))), None);
        assert_eq!(file_id(&url(&format!("https://{HOST}/"))), None);
        assert!(is_direct(&url(&format!("https://dl.{HOST}/abc/file.rar"))));
        assert!(is_direct(&url(&format!("https://{HOST}/dl/abc"))));
        assert!(is_host(&format!("DL.{}", HOST.to_uppercase())));
        assert!(!is_host(&format!("{HOST}.evil.example")));
        assert!(!is_host(&format!("not{HOST}")));
    }

    #[test]
    fn the_title_loses_the_sites_name() {
        let og = format!(
            r#"<meta property="og:title" content="Archive &amp; Co.part1.rar - {SITE_NAME}">"#
        );
        assert_eq!(page_title(&og).as_deref(), Some("Archive & Co.part1.rar"));
        let plain = format!("<html><title>\n  a.rar | {SITE_NAME} </title>");
        assert_eq!(page_title(&plain).as_deref(), Some("a.rar"));
        assert_eq!(page_title(&format!("<title> - {SITE_NAME}</title>")), None);
        assert_eq!(page_title("nothing"), None);
    }

    #[test]
    fn only_the_hosts_own_address_is_taken_as_the_direct_link() {
        let direct = format!("https://dl.{HOST}/x/a.rar");
        assert_eq!(direct_link(Some(&direct), "", "").as_deref(), Some(direct.as_str()));
        assert_eq!(
            direct_link(None, &direct, "").as_deref(),
            Some(direct.as_str()),
            "a plain redirect ended there"
        );
        let body = format!(r#"<a href="https://{HOST}/dl/abc123">x</a>"#);
        assert_eq!(
            direct_link(None, &format!("https://{HOST}/f/x/go"), &body),
            Some(format!("https://{HOST}/dl/abc123"))
        );
        assert_eq!(direct_link(Some("https://evil.example/x"), "", ""), None);
        assert_eq!(direct_link(Some(&format!("http://dl.{HOST}/x")), "", ""), None);
        assert_eq!(direct_link(None, "", "no link"), None);
    }

    #[test]
    fn the_name_comes_from_the_server_then_the_address_then_the_title() {
        let direct = format!("https://dl.{HOST}/abc/Some%20File.part2.rar");
        assert_eq!(
            file_name(Some("attachment; filename*=UTF-8''Za%C5%BC%C3%B3%C5%82%C4%87.rar"), &direct, None),
            "Zażółć.rar"
        );
        assert_eq!(
            file_name(Some(r#"attachment; filename="quoted.rar""#), &direct, None),
            "quoted.rar"
        );
        assert_eq!(file_name(None, &direct, None), "Some File.part2.rar");
        assert_eq!(file_name(None, &format!("https://{HOST}/"), Some("hint.rar")), "hint.rar");
        assert_eq!(
            file_name(Some(r#"filename="..\..\Windows\evil:name?.exe""#), &direct, None),
            "evilname.exe"
        );
        assert_eq!(file_name(None, &format!("https://{HOST}/"), None), "download.bin");
        assert_eq!(file_name(Some(&format!(r#"filename="{}""#, "a".repeat(300))), &direct, None).len(), 200);
    }

    #[test]
    fn sizes_and_challenges_are_read_from_the_answer() {
        assert_eq!(total_size(Some("bytes 100-199/5000"), Some("100")), Some(5000));
        assert_eq!(total_size(Some("bytes 0-9/*"), Some("10")), Some(10));
        assert_eq!(total_size(None, Some("1234")), Some(1234));
        assert_eq!(total_size(None, None), None);
        assert!(is_challenge(200, Some("challenge"), ""));
        assert!(is_challenge(403, None, "<title>Just a moment...</title>"));
        assert!(!is_challenge(403, None, "forbidden"));
        assert!(!is_challenge(200, None, "Just a moment"));
        let p = progress(50, Some(200), 10_000.0);
        assert_eq!((p.percent, p.downloaded, p.total, p.eta), (25.0, 50, 200, 0));
        assert_eq!(progress(5, None, 0.0).eta, -1);
    }

    #[test]
    fn every_offered_profile_exists_and_reads_well() {
        assert_eq!(profile_label("Chrome149"), "Chrome 149");
        assert_eq!(profile_label("Edge131"), "Edge 131");
        #[cfg(windows)]
        for name in BROWSER_PROFILES {
            assert!(engine::profile_named(name).is_some(), "{name}");
        }
        #[cfg(windows)]
        for profile in engine::PROFILES {
            assert!(BROWSER_PROFILES.contains(&format!("{profile:?}").as_str()), "{profile:?}");
        }
    }

    /// Through the protection to the site and back with its answer for an id it does not
    /// know, without fetching any file. Run by hand:
    /// `cargo test -p modlight-core --lib -- --ignored an_unknown_file`.
    #[cfg(windows)]
    #[test]
    #[ignore = "reaches the file host over the network"]
    fn an_unknown_file_is_reported_gone() {
        let spec = HostSpec {
            link: DownloadLink::parse(&format!("https://{HOST}/f/ZzModlightNoSuchFile0")).unwrap(),
            folder: tempfile::tempdir().unwrap().path().to_path_buf(),
            profile: None,
        };
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let outcome = runtime.block_on(run(
            &spec,
            Arc::new(|_| {}),
            &CancellationToken::new(),
        ));
        assert_eq!(outcome.error, t(s::Download_HostGone), "{outcome:?}");
    }

    /// Diagnosis: each step for a real link (`FILEHOST_PROBE_URL`) with each profile;
    /// only the file's headers are read, never its body.
    #[cfg(windows)]
    #[test]
    #[ignore = "diagnosis against a real link"]
    fn probe_each_step() {
        let Ok(link) = std::env::var("FILEHOST_PROBE_URL") else {
            return;
        };
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let id = file_id(&url(&link)).unwrap();
            for profile in engine::PROFILES {
                let client = engine::client_for(profile).unwrap();
                let page = client.get(format!("{SITE}/f/{id}")).send().await.unwrap();
                let page_status = page.status().as_u16();
                let page_cf = page.headers().get("cf-mitigated").cloned();
                let current = page.uri().to_string();
                drop(page.text().await);
                let go = client
                    .post(format!("{SITE}/f/{id}/go"))
                    .header("hx-request", "true")
                    .header("hx-current-url", current.as_str())
                    .header("referer", current.as_str())
                    .header("origin", SITE)
                    .header("content-type", "application/x-www-form-urlencoded; charset=UTF-8")
                    .body("cf-turnstile-response=")
                    .send()
                    .await
                    .unwrap();
                let go_status = go.status().as_u16();
                let go_cf = go.headers().get("cf-mitigated").cloned();
                let redirect = go.headers().get("hx-redirect").and_then(|v| v.to_str().ok()).map(str::to_string);
                drop(go);
                let file = match &redirect {
                    Some(direct) => {
                        let r = client.get(direct).header("referer", format!("{SITE}/")).send().await.unwrap();
                        format!("{} cf={:?} len={:?}", r.status().as_u16(), r.headers().get("cf-mitigated"), r.headers().get("content-length"))
                    }
                    None => "-".into(),
                };
                println!(
                    "{profile:?}: page {page_status} cf={page_cf:?} | go {go_status} cf={go_cf:?} link={} | file {file}",
                    redirect.is_some()
                );
            }
        });
    }

    #[test]
    fn failures_say_what_happened() {
        assert!(Failure::Network("reset".into()).retry());
        assert!(!Failure::Gone.retry() && !Failure::Busy.retry() && !Failure::Challenge.retry());
        assert!(Failure::Short(10, 20).message().contains("10"));
        assert!(Failure::Network("connection reset".into()).message().contains("connection reset"));
    }
}

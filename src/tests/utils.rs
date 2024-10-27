use std::{
    fs::File,
    io,
    path::{Path, PathBuf},
    sync::OnceLock,
    thread,
};

use crate::{Crate, ExternalEnv, Packages};

use tempfile::TempDir;
use tiny_http::{Response, Server};
use tracing_subscriber::{filter, prelude::*};

pub fn init_log() {
    let filter = filter::Targets::new()
        .with_default(filter::LevelFilter::WARN)
        .with_target(env!("CARGO_PKG_NAME"), filter::LevelFilter::TRACE);
    // Ignore errors because other tests in the same binary may have already initialized the logger
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .compact()
                .with_test_writer(),
        )
        .try_init();
}

struct MiniCrates {
    base: PathBuf,
    url: String,
}

impl MiniCrates {
    // A tiny HTTP server that mimic the parts of crates.io's APIs that we need for testing
    fn spawn() -> &'static Self {
        static MINI_CRATES: OnceLock<MiniCrates> = OnceLock::new();
        MINI_CRATES.get_or_init(|| {
            let base = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("assets")
                .join("mini_crates_io");
            let server = Server::http("127.0.0.1:0").unwrap();
            let ip = server.server_addr().to_ip().unwrap();
            let url = format!("http://{ip}");
            Self::spawn_router(base.clone(), server);
            Self { base, url }
        })
    }

    fn spawn_router(path_base: PathBuf, server: Server) {
        thread::spawn(move || {
            for req in server.incoming_requests() {
                // No breaking out of this directory *spray spray*
                let req_path = req.url().trim_start_matches("../").trim_matches('/');
                let file_path = path_base.join(req_path);
                let resp = match File::open(&file_path) {
                    Ok(file) => Response::from_file(file).boxed(),
                    Err(e) => {
                        let status_code = if e.kind() == io::ErrorKind::NotFound {
                            404
                        } else {
                            500
                        };
                        Response::empty(status_code).boxed()
                    }
                };

                req.respond(resp).unwrap();
            }
        });
    }

    fn url(&self) -> &str {
        &self.url
    }

    fn index_url(&self) -> String {
        let base = self.url();
        format!("{base}/index")
    }

    fn static_url(&self) -> String {
        let base = self.url();
        format!("{base}/static")
    }
}

pub struct FullFakeEnv {
    crates: &'static MiniCrates,
    cache_dir: TempDir,
}

impl FullFakeEnv {
    pub fn new() -> Self {
        let crates = MiniCrates::spawn();
        let mut builder = tempfile::Builder::new();
        builder.prefix("crates2pkgbuild-test-");
        let cache_dir = builder.tempdir().unwrap();
        Self { crates, cache_dir }
    }
}

impl ExternalEnv for FullFakeEnv {
    fn cache_dir(&self) -> Option<PathBuf> {
        Some(self.cache_dir.path().to_owned())
    }

    fn index_url(&self) -> String {
        self.crates.index_url()
    }

    fn static_url(&self) -> String {
        self.crates.static_url()
    }
}

/// Useful for testing that a fresh cache only uses the cache
///
/// The usual flow would be:
///
/// 1. Creating a [`FullFakeEnv`]
/// 2. Populate the cache by running some requests
/// 3. Convert it to a [`CacheOnlyEnv`] that only uses the cache
pub struct CacheOnlyEnv(TempDir);

impl From<FullFakeEnv> for CacheOnlyEnv {
    fn from(full: FullFakeEnv) -> Self {
        let FullFakeEnv { cache_dir, .. } = full;
        Self(cache_dir)
    }
}

impl ExternalEnv for CacheOnlyEnv {
    fn cache_dir(&self) -> Option<PathBuf> {
        Some(self.0.path().to_owned())
    }

    fn index_url(&self) -> String {
        unimplemented!()
    }

    fn static_url(&self) -> String {
        unimplemented!()
    }
}

pub fn sample_packages() -> Packages {
    static SAMPLE_PACKAGES_TOML: &str = include_str!("../../packages.demo.toml");
    toml::from_str(SAMPLE_PACKAGES_TOML).unwrap()
}

pub fn sample_package(c: SampleCrate) -> Crate {
    let packages = sample_packages();
    packages.resolve_crate(c.as_str()).unwrap().unwrap()
}

#[derive(Clone, Copy)]
pub enum SampleCrate {
    CargoPgo,
    Inlyne,
    RaMultiplex,
    RegexCli,
    ToHtml,
}

impl SampleCrate {
    fn as_str(self) -> &'static str {
        match self {
            Self::CargoPgo => "cargo-pgo",
            Self::Inlyne => "inlyne",
            Self::RaMultiplex => "ra-multiplex",
            Self::RegexCli => "regex-cli",
            Self::ToHtml => "to-html",
        }
    }
}

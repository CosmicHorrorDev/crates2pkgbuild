use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Debug, Write as _},
    fs,
    io::{self, Read, Write as _},
    path::PathBuf,
    time,
};

use anyhow::Context;
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use spdx::expression::{Expression, ExpressionReq};

#[cfg(test)]
mod tests;

fn main() {
    todo!()
}

fn fetch_with_env<E: ExternalEnv>(crate_: Crate, env: &E) -> anyhow::Result<PkgBuild> {
    let start = time::Instant::now();
    let maybe_cache = Cache::try_from_env(env);

    let maybe_entry = maybe_cache.as_ref().and_then(|cache| {
        cache
            .get(&crate_)
            .inspect_err(|err| {
                tracing::warn!(
                    %err,
                    name=crate_.name,
                    "Error fetching entry from cache. Fetching fresh",
                )
            })
            .ok()
            .flatten()
    });

    let (checksum, tarball) =
        if let Some(entry) = maybe_entry {
            let elapsed = start.elapsed();
            tracing::debug!(?elapsed, name = crate_.name, "Pulled entry from cache");
            entry
        } else {
            let jsonl = http_get(&env.crate_index_url(&crate_))?;
            let jsonl = String::from_utf8(jsonl)?;
            let desired_index_entry = jsonl
                .lines()
                .find_map(|line| {
                    let entry: CrateIndexEntry = serde_json::from_str(line).ok()?;
                    if entry.vers == crate_.val.version {
                        Some(entry)
                    } else {
                        None
                    }
                })
                .with_context(|| {
                    format!(
                        "No index entry found for {} {}",
                        crate_.name, crate_.val.version
                    )
                })?;
            let tarball = http_get(&env.crate_tarball_url(&crate_))?;
            let actual_checksum = Sha256Sum::hash(&tarball);
            let upstream_checksum = Sha256Sum::try_from_hex(&desired_index_entry.cksum)?;
            anyhow::ensure!(
                actual_checksum == upstream_checksum,
                "Downloaded tarball has invalid checksum"
            );

            if let Some(cache) = &maybe_cache {
                let _ = cache.insert(&crate_, upstream_checksum, &tarball).inspect_err(
                |err| tracing::warn!(%err, crate_name=crate_.name, "Failed saving cache entry"),
            );
            }

            let elapsed = start.elapsed();
            tracing::debug!(?elapsed, name = crate_.name, "Pulled entry from source");
            (upstream_checksum, tarball)
        };

    PkgBuild::new(crate_, checksum, &tarball)
}

#[derive(Deserialize)]
struct CrateIndexEntry {
    name: String,
    vers: String,
    cksum: String,
    yanked: bool,
}

// TODO: formatting causes the latter comment below to disappear
// struct Sha256Sum([u8; 256 /* bits */ / 8 /* this comment disappears */]);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Sha256Sum([u8; Self::BYTES_LEN]);

impl Sha256Sum {
    const BYTES_LEN: usize = 256 / 8;

    fn try_from_hex(hex: &str) -> anyhow::Result<Self> {
        let bytes = hex
            .as_bytes()
            .chunks_exact(2)
            .map(|hex_nibble_pair| {
                let hex_nibble_pair = std::str::from_utf8(hex_nibble_pair)?;
                let byte = u8::from_str_radix(hex_nibble_pair, 16)?;
                Ok::<_, anyhow::Error>(byte)
            })
            .collect::<anyhow::Result<Vec<_>, _>>()?;
        let inner = bytes.as_slice().try_into()?;
        Ok(Self(inner))
    }

    fn hash(bytes: &'_ [u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let hash = hasher.finalize();
        Self(hash.into())
    }
}

impl fmt::Display for Sha256Sum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }

        Ok(())
    }
}

/// The cache used to store downloaded crate tarballs
///
/// We cache the crate tarball downloads from static.crates.io/crates to avoid interacting with the
/// API more than necessary. The cache exists in the `crates2pkgbuild` directory under the user's
/// cache dir with one sub-directory per package to store the downloaded tarball. The sub-directory
/// isn't versioned but files within are, so garbage collection consists of removing the directory
/// for a package before inserting a new entry to clean out any older entries
///
/// Each entry consists of the crate tarball followed by the SHA256 checksum. The checksum is
/// checked when fetching an entry and this same checksum also gets checked when converting to a
/// PKGBUILD _and_ by pacman when installing
///
/// A malicious actor could insert an arbitrary entry that otherwise becomes a valid PKGBUILD, but
/// `makepkg` will still fail since it will still download the actual crate when attempting
/// installion
struct Cache(PathBuf);

impl Cache {
    fn try_from_env<E: ExternalEnv>(env: &E) -> Option<Self> {
        env.cache_dir().map(Self)
    }

    fn crate_path(&self, meta: CrateMeta<'_>) -> PathBuf {
        self.0.join(meta.name)
    }

    fn entry_path(&self, meta: CrateMeta<'_>) -> PathBuf {
        let name = meta.name;
        let version = meta.version;
        let file_name = format!("{name}-{version}.crate_then_sha256");
        self.crate_path(meta).join(file_name)
    }

    fn get<'a, M>(&self, meta: M) -> anyhow::Result<Option<(Sha256Sum, Vec<u8>)>>
    where
        M: Into<CrateMeta<'a>>,
    {
        let entry_path = self.entry_path(meta.into());
        match fs::read(&entry_path) {
            Ok(mut file) => {
                let (contents, stored_checksum) = file
                    .split_last_chunk::<{ Sha256Sum::BYTES_LEN }>()
                    .context("Invalid file: too small")?;
                let stored_checksum = Sha256Sum(*stored_checksum);
                let actual_checksum = Sha256Sum::hash(contents);
                anyhow::ensure!(stored_checksum == actual_checksum, "Invalid checksum");
                let tarball_len = contents.len();
                file.truncate(tarball_len);
                Ok(Some((actual_checksum, file)))
            }
            Err(err) => {
                if err.kind() == io::ErrorKind::NotFound {
                    Ok(None)
                } else {
                    Err(err.into())
                }
            }
        }
    }

    fn insert<'a, M>(&self, meta: M, checksum: Sha256Sum, tarball: &[u8]) -> anyhow::Result<()>
    where
        M: Into<CrateMeta<'a>>,
    {
        let meta = meta.into();
        let crate_path = self.crate_path(meta);
        let entry_path = self.entry_path(meta);
        let actual_checksum = Sha256Sum::hash(tarball);
        anyhow::ensure!(checksum == actual_checksum, "Invalid checksum");

        // Garbage collect
        let _ = fs::remove_dir_all(&crate_path);
        fs::create_dir_all(&crate_path)?;

        // Write out the crate followed by the checksum
        let mut cache_entry = fs::File::create(&entry_path)?;
        cache_entry.write_all(tarball)?;
        cache_entry.write_all(&checksum.0)?;

        Ok(())
    }
}

fn http_get(url: &str) -> anyhow::Result<Vec<u8>> {
    // Custom user agent to help identify our traffic
    const USER_AGENT: &str = concat!(
        env!("CARGO_PKG_NAME"),
        ' ',
        env!("CARGO_PKG_VERSION"),
        ' ',
        env!("CARGO_PKG_REPOSITORY")
    );

    // crates.io doesn't like hosting big content, so this is more of a sanity check than anything
    const LIMIT: usize = 100 * 1_024 * 1_024;

    let resp = ureq::get(url)
        .set(http::header::USER_AGENT.as_str(), USER_AGENT)
        .call()?;
    let len = resp
        .header(http::header::CONTENT_LENGTH.as_str())
        .and_then(|len| len.parse().ok());
    let mut body = Vec::with_capacity(len.unwrap_or(0).clamp(0, LIMIT));
    // TODO: detect and error our when we exceed `LIMIT`
    resp.into_reader()
        .take(u64::try_from(LIMIT).unwrap())
        .read_to_end(&mut body)?;
    Ok(body)
}

trait ExternalEnv {
    fn cache_dir(&self) -> Option<PathBuf>;
    fn index_url(&self) -> String;
    fn static_url(&self) -> String;

    fn crate_index_url<'a, M: Into<CrateMeta<'a>>>(&self, meta: M) -> String {
        let CrateMeta { name, .. } = meta.into();
        let first_two = &name[..2];
        let second_two = &name[2..][..2];
        let index_base = self.index_url();
        format!("{index_base}/{first_two}/{second_two}/{name}")
    }

    fn crate_tarball_url(&self, crate_: &Crate) -> String {
        let name = &crate_.name;
        let version = &crate_.val.version;
        let static_base = self.static_url();
        format!("{static_base}/{name}/{name}-{version}.crate")
    }
}

#[derive(Clone, Copy)]
struct CrateMeta<'a> {
    name: &'a str,
    version: &'a str,
}

impl<'a> From<&'a Crate> for CrateMeta<'a> {
    fn from(crate_: &'a Crate) -> Self {
        let name = &crate_.name;
        let version = &crate_.val.version;
        Self { name, version }
    }
}

impl<'a> From<&'a PkgBuild> for CrateMeta<'a> {
    fn from(pkgbuild: &'a PkgBuild) -> Self {
        let name = &pkgbuild.pkgname;
        let version = &pkgbuild.pkgver;
        Self { name, version }
    }
}

struct RealEnv;

impl ExternalEnv for RealEnv {
    fn cache_dir(&self) -> Option<PathBuf> {
        dirs::cache_dir().map(|dir| dir.join("crates2pkgbuild"))
    }

    fn index_url(&self) -> String {
        "https://index.crates.io".into()
    }

    fn static_url(&self) -> String {
        "https://static.crates.io/crates".into()
    }
}

#[derive(Debug, Deserialize)]
struct CargoTomlMeta {
    package: CargoTomlPackage,
    #[serde(default)]
    bin: Option<Vec<CargoTomlBin>>,
}

#[derive(Debug, Deserialize)]
struct CargoTomlPackage {
    version: String,
    description: Option<String>,
    readme: Option<String>,
    license: Option<String>,
    repository: Option<String>,
    homepage: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CargoTomlBin {
    name: String,
}

#[derive(Debug, PartialEq)]
struct PkgBuild {
    maintainers: Vec<String>,
    contributors: Vec<String>,
    pkgname: String,
    pkgver: String,
    pkgrel: u32,
    pkgdesc: String,
    arch: BTreeSet<Arch>,
    url: String,
    licenses: BTreeSet<LicenseKind>,
    depends: BTreeSet<String>,
    makedepends: BTreeSet<String>,
    sha256_sum: Sha256Sum,
    env: BTreeMap<String, EnvValue>,
    test_in_check: bool,
    install: Vec<(Perms, String, String)>,
    find_files: Vec<(String, Perms, String)>,
}

impl PkgBuild {
    fn new(crate_: Crate, sha256_sum: Sha256Sum, tarball: &[u8]) -> anyhow::Result<Self> {
        let start = time::Instant::now();

        // TODO: verify that the sha256_sum matches the `tarball`'s checksum
        let Crate {
            name,
            val:
                CrateValue {
                    maintainers,
                    contributors,
                    version,
                    release_version,
                    arch,
                    deps,
                    mut make_deps,
                    env,
                    test_in_check,
                    missing_license_files,
                    find_build_completions,
                    static_completions_within,
                },
        } = crate_;

        let gz_decoder = GzDecoder::new(io::Cursor::new(tarball));
        let mut archive = tar::Archive::new(gz_decoder);
        let cargo_toml_contents = archive
            .entries()?
            .filter_map(|maybe_e| maybe_e.ok())
            .find_map(|mut entry| {
                let path_bytes = entry.path_bytes();
                let mut parts = path_bytes.split(|&byte| byte == b'/');
                let (Some(_), Some(name), None) = (parts.next(), parts.next(), parts.next()) else {
                    return None;
                };

                if name == b"Cargo.toml" {
                    let mut buf = Vec::new();
                    entry.read_to_end(&mut buf).ok()?;
                    Some(buf)
                } else {
                    None
                }
            })
            .context("Failed reading `Cargo.toml` contents from tarball")?;
        let cargo_toml_contents = String::from_utf8(cargo_toml_contents)?;
        let meta: CargoTomlMeta = toml::from_str(&cargo_toml_contents)?;
        let CargoTomlMeta {
            package:
                CargoTomlPackage {
                    version: upstream_version,
                    description,
                    readme,
                    license,
                    repository,
                    homepage,
                },
            bin,
        } = meta;
        let description = description.unwrap();
        let pkgdesc = description
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed)
                }
            })
            .collect::<Vec<_>>()
            .join(" ");
        let url = homepage
            .or(repository)
            .expect("Missing both repository and homepage links");
        let license_expr = Expression::parse(&license.unwrap())?;
        let licenses = license_expr
            .requirements()
            .map(LicenseKind::try_from)
            .collect::<anyhow::Result<_>>()?;

        if !missing_license_files {
            // TODO: if we're not expected to miss license files then look for the expected files in
            // their usual locations
            // todo!("Try to find the license files in the tarball");
        }

        let mut install = Vec::new();
        let bin = bin.unwrap_or_else(|| vec![CargoTomlBin { name: name.clone() }]);
        for CargoTomlBin { name } in bin {
            install.push((
                Perms(0o755),
                format!("target/release/{name}"),
                format!("$pkgdir/usr/bin/{name}"),
            ));
        }
        if let Some(readme) = readme {
            install.push((
                Perms(0o644),
                readme,
                "$pkgdir/usr/share/doc/$pkgname/README.md".into(),
            ));
        }

        if let Some(comp_within) = static_completions_within {
            // TODO: I don't think the names will be stable enough for this to work. It should
            // probably be included as part of the config
            // TODO: try to find completions at:
            // <name>-<version>/<comp_within>/<shell_comp_files>
            let mut comp_to_install: BTreeMap<_, _> = ShellIter::new()
                .map(|shell| {
                    let file_name = shell.file_name(&name);
                    let install_from = format!("{name}-{version}/{comp_within}/{file_name}");
                    let install_to = shell.file_out_path(&name);
                    (install_from, install_to)
                })
                .collect();
            let gz_decoder = GzDecoder::new(io::Cursor::new(tarball));
            let mut archive = tar::Archive::new(gz_decoder);
            for (install_from, install_to) in archive.entries()?.filter_map(|maybe| {
                let entry = maybe.ok()?;
                let path_bytes = entry.path_bytes();
                let path = std::str::from_utf8(&path_bytes).ok()?;
                comp_to_install.remove_entry(path)
            }) {
                let (_, rel_from) = install_from.split_once('/').unwrap();
                install.push((Perms(0o644), rel_from.into(), install_to));
            }
        }

        // TODO: I don't think the names will be stable enough for this to work. It should probably
        // be included as part of the config
        let mut find_files = Vec::new();
        for shell in &find_build_completions {
            let shell_name = shell.file_name(&name);
            let shell_out_path = shell.file_out_path(&name);
            find_files.push((shell_name, Perms(0o644), shell_out_path));
        }
        if !find_build_completions.is_empty() {
            make_deps.insert("findutils".into());
        }

        tracing::trace!(elapsed = ?start.elapsed(), "Extracted PKGBUILD metadata");

        Ok(Self {
            maintainers,
            contributors,
            pkgname: name,
            pkgver: version,
            pkgrel: release_version,
            pkgdesc,
            arch,
            url,
            licenses,
            depends: deps,
            makedepends: make_deps,
            sha256_sum: sha256_sum.into(),
            env,
            test_in_check,
            install,
            find_files,
        })
    }
}

/// Render out the `PkgBuild` to an actual PKGBUILD file
impl fmt::Display for PkgBuild {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let maintainers = CommentPerLine("Maintainer", &self.maintainers);
        let contributors = CommentPerLine("Contributor", &self.contributors);
        let pkgname = BashStr(&self.pkgname);
        let pkgver = BashStr(&self.pkgver);
        let pkgrel = self.pkgrel;
        let pkgdesc = BashStr(&self.pkgdesc);
        let arches = BashSet(&self.arch);
        let url = BashStr(&self.url);
        let licenses = BashSet(&self.licenses);
        let depends = BashSet(&self.depends);
        let makedepends = BashSet(&self.makedepends);
        let sha256sum = &self.sha256_sum;

        let crates_index_url = &RealEnv.crate_index_url(self);
        let prepare_env = PkgbuildEnv::new(&self.env, Step::Prepare);
        let build_env = PkgbuildEnv::new(&self.env, Step::Build);
        let check_env = PkgbuildEnv::new(&self.env, Step::Check);
        let install_files = InstallLines(&self.install);
        let install_find_files = InstallFindLines(&self.find_files);
        let conditional_check = ConditionalCheck(self.test_in_check.then_some(check_env));

        write!(
            f,
            "\
{maintainers}{contributors}
pkgname={pkgname}
pkgver={pkgver}
pkgrel={pkgrel}
arch={arches}
license={licenses}
pkgdesc={pkgdesc}
url={url}
depends={depends}
makedepends={makedepends}
source=(\"$pkgname-$pkgver.tar.gz::\
https://static.crates.io/crates/$pkgname/$pkgname-$pkgver.crate\")
# Upstream checksum. Can be verified with
# $ curl {crates_index_url} | grep -F '\"{pkgver}\"' | jq .cksum
sha256sums=({sha256sum})

prepare() {{
  cd \"$srcdir/$pkgname-$pkgver\"

{prepare_env}  cargo fetch --locked --target \"$CARCH-unknown-linux-gnu\"
}}

build() {{
  cd \"$srcdir/$pkgname-$pkgver\"

{build_env}  cargo build --frozen --release
}}
{conditional_check}
package() {{
  cd \"$srcdir/$pkgname-$pkgver\"

{install_files}{install_find_files}}}

# vi: filetype=sh shiftwidth=2 expandtab
\
            ",
        )
    }
}

struct CommentPerLine<'a>(&'static str, &'a [String]);

impl<'a> fmt::Display for CommentPerLine<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let prefix = self.0;
        for line in self.1 {
            write!(f, "# {prefix}: {line}\n")?;
        }

        Ok(())
    }
}

struct BashStr<'a>(&'a str);

impl<'a> fmt::Display for BashStr<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.0;
        if s.is_empty() {
            f.write_str("''")
        } else {
            if !needs_quotes(s) {
                f.write_str(s)
            } else {
                if s.contains(['\'', '$']) {
                    if s.contains(['"', '\\']) {
                        todo!();
                    } else {
                        write!(f, "\"{s}\"")
                    }
                } else {
                    write!(f, "'{s}'")
                }
            }
        }
    }
}

fn needs_quotes(s: &str) -> bool {
    for b in s.bytes() {
        if !matches!(
            b,
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'/',
        ) {
            return true;
        }
    }

    false
}

struct BashSet<'a, T>(&'a BTreeSet<T>);

// TODO: store additional context to make sure that we can wrap lines when formatting
impl<'a, T> fmt::Display for BashSet<'a, T>
where
    T: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_char('(')?;
        let mut first = true;
        for entry in self.0.into_iter() {
            if !first {
                f.write_char(' ')?;
            }
            first = false;

            write!(f, "{entry}")?;
        }

        f.write_char(')')
    }
}

struct PkgbuildEnv<'a>(BTreeMap<&'a str, &'a str>);

impl<'a> PkgbuildEnv<'a> {
    fn new(full_env: &'a BTreeMap<String, EnvValue>, step: Step) -> Self {
        let inner = full_env
            .iter()
            .filter_map(|(name, val)| {
                if val.steps.contains(&step) {
                    Some((name.as_str(), val.value.as_str()))
                } else {
                    None
                }
            })
            .collect();
        Self(inner)
    }
}

impl<'a> fmt::Display for PkgbuildEnv<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (key, value) in self.0.iter() {
            write!(f, "  export {}={}\n", key, BashStr(value))?;
        }

        Ok(())
    }
}

struct InstallLines<'a>(&'a [(Perms, String, String)]);

impl<'a> fmt::Display for InstallLines<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (perms, from, to) in self.0 {
            write!(
                f,
                "  install -Dm{} {} {}\n",
                perms,
                BashStr(from),
                BashStr(to)
            )?;
        }

        Ok(())
    }
}

struct InstallFindLines<'a>(&'a [(String, Perms, String)]);

impl<'a> fmt::Display for InstallFindLines<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (name, perms, to) in self.0 {
            write!(
                f,
                "  find . -name {name} -type f -exec install -D{perms} {{}} {to} \\;\n"
            )?;
        }

        Ok(())
    }
}

struct ConditionalCheck<'a>(Option<PkgbuildEnv<'a>>);

impl<'a> fmt::Display for ConditionalCheck<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            None => Ok(()),
            Some(env) => write!(
                f,
                "
check() {{
  cd \"$srcdir/$pkgname-$pkgver\"

{env}  cargo test --release --locked
}}
\
                "
            ),
        }
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum LicenseKind {
    Apache,
    Mit,
}

impl fmt::Display for LicenseKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Apache => "APACHE",
            Self::Mit => "MIT",
        })
    }
}

impl TryFrom<&ExpressionReq> for LicenseKind {
    type Error = anyhow::Error;

    fn try_from(req: &ExpressionReq) -> Result<Self, Self::Error> {
        match req.req.license.id().unwrap().name {
            "Apache-2.0" => Ok(LicenseKind::Apache),
            "MIT" => Ok(LicenseKind::Mit),
            other => Err(anyhow::anyhow!("Unknown license kind: {other}")),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Perms(u32);

impl fmt::Display for Perms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let owner = (self.0 & 0o700) >> 6;
        let group = (self.0 & 0o070) >> 3;
        let all = self.0 & 0o007;
        write!(f, "{owner}{group}{all}")
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct Packages {
    maintainers: Vec<String>,
    arch: BTreeSet<Arch>,
    deps: BTreeSet<String>,
    make_deps: BTreeSet<String>,
    env: BTreeMap<String, EnvValue>,
    #[serde(rename = "crate")]
    crate_: BTreeMap<String, CrateValue>,
}

impl Packages {
    fn resolve_crate(&self, name: &str) -> Option<anyhow::Result<Crate>> {
        let crate_ = self.crate_.get(name)?.to_owned();
        let mut maintainers = self.maintainers.clone();
        maintainers.extend_from_slice(&crate_.maintainers);
        let contributors = crate_.contributors;
        let version = crate_.version;
        let release_version = crate_.release_version;
        let arch = self.arch.union(&crate_.arch).cloned().collect();
        let deps = self.deps.union(&crate_.deps).cloned().collect();
        let make_deps = self.make_deps.union(&crate_.make_deps).cloned().collect();
        let env = self
            .env
            .clone()
            .into_iter()
            .chain(crate_.env.into_iter())
            .collect();
        let test_in_check = crate_.test_in_check;
        let missing_license_files = crate_.missing_license_files;
        let find_build_completions = crate_.find_build_completions;
        let static_completions_within = crate_.static_completions_within;
        let val = CrateValue {
            maintainers,
            contributors,
            version,
            release_version,
            arch,
            deps,
            make_deps,
            env,
            test_in_check,
            missing_license_files,
            find_build_completions,
            static_completions_within,
        };

        Some(Ok(Crate {
            name: name.into(),
            val,
        }))
    }
}

#[derive(Clone, Serialize)]
struct Crate {
    name: String,
    val: CrateValue,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct CrateValue {
    #[serde(default)]
    maintainers: Vec<String>,
    #[serde(default)]
    contributors: Vec<String>,
    version: String,
    #[serde(default = "default_pkgrel")]
    release_version: u32,
    #[serde(default)]
    arch: BTreeSet<Arch>,
    #[serde(default)]
    deps: BTreeSet<String>,
    #[serde(default)]
    make_deps: BTreeSet<String>,
    #[serde(default)]
    env: BTreeMap<String, EnvValue>,
    #[serde(default)]
    test_in_check: bool,
    #[serde(default)]
    missing_license_files: bool,
    #[serde(default)]
    find_build_completions: BTreeSet<Shell>,
    #[serde(default)]
    static_completions_within: Option<String>,
}

fn default_pkgrel() -> u32 {
    1
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct EnvValue {
    value: String,
    steps: BTreeSet<Step>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
enum Step {
    Build,
    Check,
    Prepare,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct CratesSettings {
    maintainers: Vec<String>,
    arch: Vec<Arch>,
    make_deps: Vec<String>,
    env: BTreeMap<String, EnvValue>,
    find_build_completions: BTreeSet<Shell>,
    static_completions_within: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
enum Arch {
    #[serde(rename = "i686")]
    I686,
    #[serde(rename = "x86_64")]
    X86_64,
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::I686 => "i686",
            Self::X86_64 => "x86_64",
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
enum Shell {
    // TODO: this doesn't get matched right for inlyne anymore
    Bash,
    Elvish,
    Fish,
    Zsh,
}

impl Shell {
    // TODO: we can't trust these names to be stable, we need some way to rename
    fn file_name(self, bin_name: &str) -> String {
        match self {
            Self::Bash => bin_name.to_owned(),
            Self::Elvish => format!("{bin_name}.elv"),
            Self::Fish => format!("{bin_name}.fish"),
            Self::Zsh => format!("_{bin_name}"),
        }
    }

    fn intermediate_name(self, bin_name: &str) -> String {
        let ext = match self {
            Self::Bash => "bash",
            Self::Elvish => "elv",
            Self::Fish => "fish",
            Self::Zsh => "zsh",
        };

        format!("{bin_name}.{ext}")
    }

    fn file_out_path(self, bin_name: &str) -> String {
        let dir = match self {
            Self::Bash => "bash-completion/completions",
            Self::Elvish => "elvish/lib",
            Self::Fish => "fish/vendor_completions.d",
            Self::Zsh => "zsh/site-functions",
        };
        let comp_name = self.file_name(bin_name);

        format!("$pkgdir/usr/share/{dir}/{comp_name}")
    }
}

#[derive(Clone, Debug)]
struct ShellIter(Option<Shell>);

impl ShellIter {
    fn new() -> Self {
        Self(Some(Shell::Bash))
    }
}

impl Iterator for ShellIter {
    type Item = Shell;

    fn next(&mut self) -> Option<Self::Item> {
        let ret = self.0.take()?;
        self.0 = match ret {
            Shell::Bash => Some(Shell::Elvish),
            Shell::Elvish => Some(Shell::Fish),
            Shell::Fish => Some(Shell::Zsh),
            Shell::Zsh => None,
        };
        Some(ret)
    }
}

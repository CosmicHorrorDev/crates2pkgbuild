use super::utils::{init_log, sample_package, CacheOnlyEnv, FullFakeEnv, SampleCrate};

// Pull a package from source and then again from the cache
#[test]
fn fresh_cache_gets_used() {
    init_log();

    let env = FullFakeEnv::new();
    let crate_ = sample_package(SampleCrate::RegexCli);
    let pkgbuild = crate::fetch_with_env(crate_.clone(), &env).unwrap();

    // No server now, just the cache
    let env: CacheOnlyEnv = env.into();
    let pkgbuild2 = crate::fetch_with_env(crate_, &env).unwrap();
    assert_eq!(pkgbuild, pkgbuild2);
}

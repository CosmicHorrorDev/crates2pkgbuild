use super::utils::{init_log, sample_package, FullFakeEnv, SampleCrate};

macro_rules! gen_snapshot_tests {
    ( $( ( $test_name:ident, $sample:expr ) ),* $(,)? ) => {
        $(
            #[test]
            fn $test_name() {
                init_log();

                let env = FullFakeEnv::new();
                let crate_ = sample_package($sample);
                let pkgbuild = crate::fetch_with_env(crate_.clone(), &env).unwrap();
                insta::with_settings!({ info => &crate_ }, {
                    insta::assert_snapshot!(pkgbuild);
                });
            }
        )*
    }
}

gen_snapshot_tests!(
    (cargo_pgo, SampleCrate::CargoPgo),
    (inlyne, SampleCrate::Inlyne),
    (ra_multiplex, SampleCrate::RaMultiplex),
    (regex_cli, SampleCrate::RegexCli),
    (to_html, SampleCrate::ToHtml),
);

pub fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!(
            "required integration-test variable {name} is unset; see the matching tests/samba*/README.md"
        )
    })
}

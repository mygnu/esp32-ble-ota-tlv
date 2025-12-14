fn main() {
    // Ensure ESP-IDF embeds the Cargo package version as firmware metadata.
    unsafe {
        std::env::set_var("PROJECT_VER", env!("CARGO_PKG_VERSION"));
        std::env::set_var("CONFIG_APP_PROJECT_VER", env!("CARGO_PKG_VERSION"));
    }

    embuild::espidf::sysenv::output();
}

//! Native startup UI. Guest execution remains in a fresh runtime process.
#![deny(unsafe_op_in_unsafe_fn)]

mod log_reader;
mod model;
mod process;
mod store;
#[cfg(windows)]
mod windows;

#[cfg(test)]
mod test_support {
    use std::path::PathBuf;
    pub struct Fixture(pub PathBuf);
    impl Fixture {
        pub fn new() -> Self {
            let (path, file) =
                crate::store::unique_file(&std::env::temp_dir(), "compat16-ui-test", "tmp")
                    .unwrap();
            drop(file);
            std::fs::remove_file(&path).unwrap();
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        pub fn file(&self, name: &str) -> PathBuf {
            let path = self.0.join(name);
            std::fs::write(&path, []).unwrap();
            path
        }
        pub fn directory(&self, name: &str) -> PathBuf {
            let path = self.0.join(name);
            std::fs::create_dir(&path).unwrap();
            path
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            if let (Ok(path), Ok(root)) =
                (self.0.canonicalize(), std::env::temp_dir().canonicalize())
            {
                if path.starts_with(&root) && path != root {
                    let _ = std::fs::remove_dir_all(path);
                }
            }
        }
    }
}

/// A system-mapped legacy image may retain the original application's argv0.
/// Only an invocation of this executable itself, with no tail, opens the UI.
pub fn is_home_invocation() -> bool {
    #[cfg(windows)]
    {
        windows::is_home_invocation()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

pub fn run() -> Result<(), String> {
    #[cfg(windows)]
    {
        windows::run()
    }
    #[cfg(not(windows))]
    {
        Err("The launcher requires Windows.".into())
    }
}

pub fn show_error(message: &str) {
    #[cfg(windows)]
    windows::show_error(message);
    #[cfg(not(windows))]
    eprintln!("{message}");
}

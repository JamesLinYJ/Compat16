#[path = "../../build-support/windows_resources.rs"]
mod windows_resources;

fn main() {
    windows_resources::link_resources(&["compat16", "compat16w"]);
}

// External-crate compile-fail sketch: SessionMediaAuthority::new is crate-private.
extern crate cockpit_core;

fn mint() {
    let _ = cockpit_core::tool_media_authority::SessionMediaAuthority::new;
}

fn main() {}

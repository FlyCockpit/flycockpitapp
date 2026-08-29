// External-crate compile-fail sketch: fields are sealed against struct literals.
extern crate cockpit_core;

fn fabricate() -> cockpit_core::tool_media_authority::SessionMediaAuthority {
    cockpit_core::tool_media_authority::SessionMediaAuthority {}
}

fn main() {}

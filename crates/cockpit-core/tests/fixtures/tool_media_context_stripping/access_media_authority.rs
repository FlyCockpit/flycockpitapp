// External-crate compile-fail sketch: media_authority is not a public field.
extern crate cockpit_core;

fn steal_subject(ctx: &cockpit_core::engine::tool::ToolCtx) {
    let _ = &ctx.media_authority;
}

fn main() {}

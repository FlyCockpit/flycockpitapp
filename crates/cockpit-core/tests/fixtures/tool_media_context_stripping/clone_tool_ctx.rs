// External-crate compile-fail sketch: ToolCtx is not Clone.
extern crate cockpit_core;

fn retain(ctx: &cockpit_core::engine::tool::ToolCtx) {
    let _: cockpit_core::engine::tool::ToolCtx = ctx.clone();
}

fn main() {}

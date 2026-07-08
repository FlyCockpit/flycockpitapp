//! MCP transport clients: `streamable` HTTP, `stdio`, legacy `sse`.

pub mod http;
pub mod sse;
pub mod stdio;
pub(crate) mod timeout;

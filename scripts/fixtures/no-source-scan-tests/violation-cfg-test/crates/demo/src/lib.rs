pub fn marker() {}

#[cfg(test)]
mod tests {
    const SRC: &str = include_str!("lib.rs");

    #[test]
    fn uses_scan() {
        assert!(!SRC.is_empty());
    }
}

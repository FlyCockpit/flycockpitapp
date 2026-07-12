use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSyntaxConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_data_syntax_max_bytes")]
    pub max_bytes: usize,
}

default_const!(default_data_syntax_max_bytes, usize, 10 * 1024 * 1024);

impl Default for DataSyntaxConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_bytes: default_data_syntax_max_bytes(),
        }
    }
}

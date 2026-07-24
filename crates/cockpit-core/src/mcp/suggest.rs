const MAX_DISTANCE: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ToolSuggestion {
    pub name: String,
    pub description: String,
}

pub(crate) fn closest_tool<I>(needle: &str, candidates: I) -> Option<ToolSuggestion>
where
    I: IntoIterator<Item = (String, String)>,
{
    let (name, description) = closest_name_with_payload(needle, candidates)?;
    Some(ToolSuggestion { name, description })
}

pub(crate) fn closest_server<'a, I>(needle: &str, candidates: I) -> Option<String>
where
    I: IntoIterator<Item = &'a str>,
{
    closest_name_with_payload(
        needle,
        candidates
            .into_iter()
            .map(|name| (name.to_string(), String::new())),
    )
    .map(|(name, _)| name)
}

fn closest_name_with_payload<I>(needle: &str, candidates: I) -> Option<(String, String)>
where
    I: IntoIterator<Item = (String, String)>,
{
    let needle = normalize(needle);
    if needle.is_empty() {
        return None;
    }
    let mut best: Option<(usize, bool, String, String)> = None;
    for (name, description) in candidates {
        let normalized = normalize(&name);
        if normalized.is_empty() {
            continue;
        }
        let Some(distance) = bounded_levenshtein(&needle, &normalized, MAX_DISTANCE) else {
            continue;
        };
        let prefix_like = normalized.starts_with(&needle)
            || needle.starts_with(&normalized)
            || normalized.contains(&needle)
            || needle.contains(&normalized);
        let candidate = (distance, !prefix_like, name, description);
        if best.as_ref().is_none_or(|current| candidate < *current) {
            best = Some(candidate);
        }
    }
    best.map(|(_, _, name, description)| (name, description))
}

fn normalize(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn bounded_levenshtein(a: &str, b: &str, max: usize) -> Option<usize> {
    let a = a.chars().collect::<Vec<_>>();
    let b = b.chars().collect::<Vec<_>>();
    if a.len().abs_diff(b.len()) > max {
        return None;
    }
    let mut previous = (0..=b.len()).collect::<Vec<_>>();
    let mut current = vec![0; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        current[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            let delete = previous[j + 1] + 1;
            let insert = current[j] + 1;
            let substitute = previous[j] + cost;
            current[j + 1] = delete.min(insert).min(substitute);
        }
        std::mem::swap(&mut previous, &mut current);
    }
    let distance = previous[b.len()];
    (distance <= max).then_some(distance)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closest_tool_returns_name_and_description_inside_threshold() {
        let suggestion = closest_tool(
            "rename_sesion",
            [
                ("context_usage".to_string(), "Context one-liner".to_string()),
                ("rename_session".to_string(), "Rename one-liner".to_string()),
            ],
        )
        .unwrap();

        assert_eq!(suggestion.name, "rename_session");
        assert_eq!(suggestion.description, "Rename one-liner");
    }

    #[test]
    fn closest_server_ignores_far_candidates() {
        assert_eq!(
            closest_server("githb", ["cockpit", "github"].into_iter()).as_deref(),
            Some("github")
        );
        assert!(closest_server("zzzzzz", ["cockpit", "github"].into_iter()).is_none());
    }
}

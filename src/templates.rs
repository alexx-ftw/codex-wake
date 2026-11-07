//! Rendering for user-configurable action messages.
//!
//! Templates and rendered messages are limited to 64 KiB each. Webhook input
//! is separately limited to 1 MiB by the input handler.

use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;

const MAX_TEMPLATE_BYTES: usize = 64 * 1024;
const MAX_RENDERED_BYTES: usize = 64 * 1024;

/// Validate template syntax without looking up any placeholders.
pub fn validate(template: &str) -> Result<()> {
    ensure!(
        template.len() <= MAX_TEMPLATE_BYTES,
        "Template exceeds 64 KiB"
    );

    let mut rest = template;
    while let Some(open) = rest.find("{{") {
        let variable = &rest[open + 2..];
        let end = variable.find("}}").context("Unclosed template variable")?;
        validate_path(&variable[..end])?;
        rest = &variable[end + 2..];
    }
    Ok(())
}

pub(crate) fn validate_path(path: &str) -> Result<()> {
    ensure!(!path.is_empty(), "Template variable path is empty");
    for segment in path.split('.') {
        ensure!(
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
            "Invalid template variable path"
        );
    }
    Ok(())
}

/// Render `{{dotted.json.path}}` placeholders as literal scalar values.
pub fn render(template: &str, context: &Value) -> Result<String> {
    validate(template)?;

    let mut rendered = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find("{{") {
        rendered.push_str(&rest[..open]);
        let variable = &rest[open + 2..];
        let end = variable
            .find("}}")
            .expect("validate checked template syntax");
        let path = &variable[..end];
        let value = lookup(context, path)?;
        let text = match value {
            Value::String(value) => value.clone(),
            Value::Number(value) => value.to_string(),
            Value::Bool(value) => value.to_string(),
            Value::Null => bail!("Template variable `{path}` is null"),
            Value::Object(_) | Value::Array(_) => {
                bail!("Template variable `{path}` is not a scalar")
            }
        };
        ensure!(
            rendered.len().saturating_add(text.len()) <= MAX_RENDERED_BYTES,
            "Rendered template exceeds 64 KiB"
        );
        rendered.push_str(&text);
        rest = &variable[end + 2..];
    }
    ensure!(
        rendered.len().saturating_add(rest.len()) <= MAX_RENDERED_BYTES,
        "Rendered template exceeds 64 KiB"
    );
    rendered.push_str(rest);
    Ok(rendered)
}

pub(crate) fn lookup<'a>(context: &'a Value, path: &str) -> Result<&'a Value> {
    let mut value = context;
    for segment in path.split('.') {
        value = match value {
            Value::Object(object) => object.get(segment),
            Value::Array(array) => segment
                .parse::<usize>()
                .ok()
                .and_then(|index| array.get(index)),
            _ => None,
        }
        .ok_or_else(|| anyhow::anyhow!("Template variable `{path}` is missing"))?;
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::{MAX_RENDERED_BYTES, MAX_TEMPLATE_BYTES, render, validate};
    use serde_json::json;

    #[test]
    fn renders_unicode_and_multiple_variables() {
        let context = json!({
            "source": {"comment": {"user": {"login": "Zoë"}, "body": "¡Hola!"}},
            "event": {"repo": "owner/repo"},
            "target": {"thread": "abc"},
            "goal": {"objective": "revisar 🚀"}
        });
        assert_eq!(
            render(
                "{{source.comment.user.login}}: {{source.comment.body}} @ {{event.repo}} {{target.thread}} {{goal.objective}}",
                &context
            )
            .unwrap(),
            "Zoë: ¡Hola! @ owner/repo abc revisar 🚀"
        );
    }

    #[test]
    fn inserted_braces_are_not_reread_as_placeholders() {
        let context = json!({"source": {"comment": {"body": "{{missing}}"}}});
        assert_eq!(
            render("{{source.comment.body}}", &context).unwrap(),
            "{{missing}}"
        );
    }

    #[test]
    fn renders_numbers_and_booleans_as_scalars() {
        let context = json!({"count": 42, "enabled": true});
        assert_eq!(
            render("{{count}}/{{enabled}}", &context).unwrap(),
            "42/true"
        );
    }

    #[test]
    fn distinguishes_missing_and_null_values() {
        let context = json!({"present": null});
        assert!(
            render("{{missing}}", &context)
                .unwrap_err()
                .to_string()
                .contains("missing")
        );
        assert!(
            render("{{present}}", &context)
                .unwrap_err()
                .to_string()
                .contains("null")
        );
    }

    #[test]
    fn rejects_non_scalar_values_and_code_like_paths() {
        let context = json!({"object": {"child": "value"}, "array": ["value"]});
        assert!(render("{{object}}", &context).is_err());
        assert!(render("{{array}}", &context).is_err());
        assert!(validate("{{source.body); run()}} ").is_err());
        assert!(validate("{{source..body}}").is_err());
    }

    #[test]
    fn validates_syntax_without_resolving_values() {
        assert!(validate("literal {{unknown.path}} text").is_ok());
        assert!(validate("{{unclosed").is_err());
        assert!(validate("literal }}").is_ok());
        assert!(validate("{{empty.}} ").is_err());
        assert!(validate(&"x".repeat(MAX_TEMPLATE_BYTES + 1)).is_err());
    }

    #[test]
    fn accepts_template_and_rendered_size_boundaries() {
        assert!(validate(&"x".repeat(MAX_TEMPLATE_BYTES)).is_ok());
        let context = json!({"large": "x".repeat(MAX_RENDERED_BYTES)});
        assert_eq!(
            render("{{large}}", &context).unwrap().len(),
            MAX_RENDERED_BYTES
        );
        assert!(render("!{{large}}", &context).is_err());
    }

    #[test]
    fn preserves_json_braces_and_supports_array_indices() {
        let context = json!({"source":{"labels":[{"name":"ready"}]}});
        assert_eq!(
            render(
                "{\"label\": \"{{source.labels.0.name}}\", \"nested\": {\"ok\":true}}",
                &context
            )
            .unwrap(),
            "{\"label\": \"ready\", \"nested\": {\"ok\":true}}"
        );
        assert!(render("{{source.labels.9.name}}", &context).is_err());
    }
}

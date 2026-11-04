use anyhow::{Result, anyhow, bail};
use serde_json::{Map, Value, json};
use std::{fs, path::Path, process::Command, time::Duration};

const RPC_TIMEOUT: Duration = Duration::from_secs(15);
const MARKETPLACE_TIMEOUT: Duration = Duration::from_secs(20);
const WRITE_ATTEMPTS: usize = 3;

fn user_layer(response: &Value) -> Option<&Value> {
    response
        .get("layers")?
        .as_array()?
        .iter()
        .find(|layer| layer.get("name").and_then(|name| name.get("type")) == Some(&json!("user")))
}

fn marketplace_name(plugin_id: &str) -> Option<&str> {
    plugin_id
        .rsplit_once('@')
        .map(|(_, name)| name)
        .filter(|name| !name.is_empty())
}

fn plugin_name(plugin_id: &str) -> &str {
    plugin_id
        .split_once('@')
        .map_or(plugin_id, |(name, _)| name)
}

fn exclusive_manifest(manifest: &Value, marketplace: &str, plugin: &str) -> bool {
    manifest.get("name").and_then(Value::as_str) == Some(marketplace)
        && manifest
            .get("plugins")
            .and_then(Value::as_array)
            .is_some_and(|plugins| {
                plugins.len() == 1 && plugins[0].get("name").and_then(Value::as_str) == Some(plugin)
            })
}

fn owned_state(config: &Value, prefix: &str) -> Option<Map<String, Value>> {
    let state = config.get("hooks")?.get("state")?.as_object()?;
    let owned: Map<_, _> = state
        .iter()
        .filter(|(key, _)| key.starts_with(prefix))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    (!owned.is_empty()).then_some(owned)
}

fn conflict(error: &anyhow::Error) -> bool {
    error.to_string().to_ascii_lowercase().contains("conflict")
}

fn clear_with(
    plugin_id: &str,
    cache: &Path,
    call: &mut impl FnMut(&str, Value) -> Result<Value>,
    remove_marketplace: &mut impl FnMut(&str) -> Result<()>,
    inspect_marketplace: &mut impl FnMut(&str, &str) -> Result<()>,
) -> Result<()> {
    let prefix = format!("{plugin_id}:");
    let marketplace = marketplace_name(plugin_id);
    let plugin = plugin_name(plugin_id);
    let package = cache.join("package").to_str().map(str::to_owned);

    for attempt in 0..WRITE_ATTEMPTS {
        let response = call("config/read", json!({"includeLayers":true}))
            .map_err(|_| anyhow!("Codex config read failed"))?;
        let Some(layer) = user_layer(&response) else {
            if let Some(name) = marketplace {
                inspect_marketplace(name, plugin)?;
            }
            return Ok(());
        };
        let config = layer.get("config").unwrap_or(&Value::Null);

        if let Some(state) = owned_state(config, &prefix) {
            let mut filtered = config
                .get("hooks")
                .and_then(|hooks| hooks.get("state"))
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            for key in state.keys() {
                filtered.remove(key);
            }
            let version = layer
                .get("version")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("Codex user config layer has no version"))?;
            let params = json!({
                "keyPath":"hooks.state",
                "value":filtered,
                "mergeStrategy":"replace",
                "expectedVersion":version
            });
            if let Err(error) = call("config/value/write", params) {
                if conflict(&error) && attempt + 1 < WRITE_ATTEMPTS {
                    continue;
                }
                bail!(
                    "Codex config write failed{}",
                    if conflict(&error) {
                        " after retries"
                    } else {
                        ""
                    }
                );
            }
        }

        let cache_match = if let (Some(name), Some(package)) = (marketplace, package.as_deref()) {
            let entry = config.get("marketplaces").and_then(|items| items.get(name));
            entry
                .and_then(|item| item.get("source_type"))
                .and_then(Value::as_str)
                == Some("local")
                && entry
                    .and_then(|item| item.get("source"))
                    .and_then(Value::as_str)
                    == Some(package)
        } else {
            false
        };
        if cache_match {
            remove_marketplace(marketplace.expect("cache match has marketplace name"))?;
        } else if let Some(name) = marketplace {
            inspect_marketplace(name, plugin)?;
        }
        return Ok(());
    }
    unreachable!("bounded write loop always returns")
}

fn remove_marketplace(codex: &Path, name: &str) -> Result<()> {
    let output = crate::manager::run(
        Command::new(codex).args(["plugin", "marketplace", "remove", name]),
        MARKETPLACE_TIMEOUT,
    )
    .map_err(|_| anyhow!("Codex marketplace removal failed"))?;
    if !output.status.success() {
        bail!("Codex marketplace removal failed");
    }
    Ok(())
}

fn inspect_marketplace(codex: &Path, name: &str, plugin: &str) -> Result<()> {
    let output = crate::manager::run(
        Command::new(codex).args(["plugin", "marketplace", "list", "--json"]),
        MARKETPLACE_TIMEOUT,
    )
    .map_err(|_| anyhow!("Codex marketplace list failed"))?;
    if !output.status.success() {
        bail!("Codex marketplace list failed");
    }
    let listing: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| anyhow!("Codex marketplace list returned invalid JSON"))?;
    let roots = listing.get("marketplaces").and_then(Value::as_array);
    let mut matching = roots
        .into_iter()
        .flatten()
        .filter(|entry| entry.get("name").and_then(Value::as_str) == Some(name));
    let Some(root) = matching
        .next()
        .and_then(|entry| entry.get("root").and_then(Value::as_str))
    else {
        return Ok(());
    };
    if matching.next().is_some() {
        return Ok(());
    }
    let Ok(bytes) = fs::read(Path::new(root).join(".agents/plugins/marketplace.json")) else {
        return Ok(());
    };
    let Ok(manifest) = serde_json::from_slice::<Value>(&bytes) else {
        return Ok(());
    };
    if exclusive_manifest(&manifest, name, plugin) {
        remove_marketplace(codex, name)?;
    }
    Ok(())
}

/// Remove this plugin's hook bookkeeping and its exact local marketplace entry.
pub fn clear_records(codex: &Path, socket: &Path, plugin_id: &str, cache: &Path) -> Result<()> {
    let mut call =
        |method: &str, params: Value| crate::goals::socket_rpc(socket, method, params, RPC_TIMEOUT);
    let mut remove = |name: &str| remove_marketplace(codex, name);
    let mut inspect = |name: &str, plugin: &str| inspect_marketplace(codex, name, plugin);
    clear_with(plugin_id, cache, &mut call, &mut remove, &mut inspect)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLUGIN: &str = "codex-wake@codex-wake-local";

    fn layer(config: Value, version: &str) -> Value {
        json!({"name":{"type":"user","file":"/tmp/config.toml"},"version":version,"config":config})
    }

    #[test]
    fn removes_only_exact_plugin_prefix_keys_from_user_layer() {
        let response = json!({"layers":[
            layer(json!({"hooks":{"state":{"codex-wake@codex-wake-local:ready":1,"codex-wake@codex-wake-local-extra:ready":2,"other:ready":3}}}),"user-v1"),
            {"name":{"type":"system","file":"/tmp/managed.toml"},"version":"system-v1","config":{"hooks":{"state":{"codex-wake@codex-wake-local:managed":4}}}}
        ]});
        let mut calls = Vec::new();
        let mut call = |method: &str, params: Value| {
            calls.push((method.to_owned(), params));
            Ok(if method == "config/read" {
                response.clone()
            } else {
                json!({"status":"ok"})
            })
        };
        let mut removed = Vec::new();
        clear_with(
            PLUGIN,
            Path::new("/tmp/cache"),
            &mut call,
            &mut |name| {
                removed.push(name.to_owned());
                Ok(())
            },
            &mut |_, _| Ok(()),
        )
        .unwrap();

        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, "config/read");
        assert_eq!(calls[0].1, json!({"includeLayers":true}));
        assert_eq!(calls[1].0, "config/value/write");
        assert_eq!(calls[1].1["keyPath"], "hooks.state");
        assert_eq!(calls[1].1["mergeStrategy"], "replace");
        assert_eq!(calls[1].1["expectedVersion"], "user-v1");
        assert_eq!(
            calls[1].1["value"],
            json!({"codex-wake@codex-wake-local-extra:ready":2,"other:ready":3})
        );
        assert!(removed.is_empty());
    }

    #[test]
    fn rereads_only_after_conflict_and_retries_with_fresh_version() {
        let configs = [
            json!({"layers":[layer(json!({"hooks":{"state":{"codex-wake@codex-wake-local:a":1,"keep":2}}}),"v1")]}),
            json!({"layers":[layer(json!({"hooks":{"state":{"codex-wake@codex-wake-local:b":3,"keep":4}}}),"v2")]}),
        ];
        let mut reads = 0;
        let mut writes = Vec::new();
        let mut call = |method: &str, params: Value| {
            if method == "config/read" {
                let result = configs[reads].clone();
                reads += 1;
                Ok(result)
            } else {
                writes.push(params);
                if writes.len() == 1 {
                    bail!("version conflict")
                } else {
                    Ok(json!({"status":"ok"}))
                }
            }
        };
        clear_with(
            PLUGIN,
            Path::new("/tmp/cache"),
            &mut call,
            &mut |_| Ok(()),
            &mut |_, _| Ok(()),
        )
        .unwrap();

        assert_eq!(reads, 2);
        assert_eq!(writes.len(), 2);
        assert_eq!(writes[0]["expectedVersion"], "v1");
        assert_eq!(writes[1]["expectedVersion"], "v2");
        assert_eq!(writes[1]["value"], json!({"keep":4}));
    }

    #[test]
    fn removes_marketplace_only_for_exact_local_cache_source() {
        let mut config = json!({"marketplaces":{
            "codex-wake-local":{"source_type":"local","source":"/tmp/cache/package"},
            "other":{"source_type":"local","source":"/tmp/other/package"}
        }});
        let response = json!({"layers":[layer(config.clone(),"v1")]});
        let mut call = |_: &str, _: Value| Ok(response.clone());
        let mut removed = Vec::new();
        clear_with(
            PLUGIN,
            Path::new("/tmp/cache"),
            &mut call,
            &mut |name| {
                removed.push(name.to_owned());
                Ok(())
            },
            &mut |_, _| Ok(()),
        )
        .unwrap();
        assert_eq!(removed, ["codex-wake-local"]);

        config["marketplaces"]["codex-wake-local"]["source"] = json!("/tmp/elsewhere/package");
        let response = json!({"layers":[layer(config,"v1")]});
        let mut call = |_: &str, _: Value| Ok(response.clone());
        let mut removed = Vec::new();
        clear_with(
            PLUGIN,
            Path::new("/tmp/cache"),
            &mut call,
            &mut |name| {
                removed.push(name.to_owned());
                Ok(())
            },
            &mut |_, _| Ok(()),
        )
        .unwrap();
        assert!(removed.is_empty());
    }

    #[test]
    fn non_conflict_write_error_does_not_retry() {
        let response = json!({"layers":[layer(json!({"hooks":{"state":{"codex-wake@codex-wake-local:a":1}}}),"v1")]});
        let mut reads = 0;
        let mut call = |method: &str, _: Value| {
            if method == "config/read" {
                reads += 1;
                Ok(response.clone())
            } else {
                bail!("permission denied")
            }
        };
        assert!(
            clear_with(
                PLUGIN,
                Path::new("/tmp/cache"),
                &mut call,
                &mut |_| Ok(()),
                &mut |_, _| Ok(()),
            )
            .is_err()
        );
        assert_eq!(reads, 1);
    }

    #[test]
    fn stops_after_three_conflicts() {
        let response = json!({"layers":[layer(json!({"hooks":{"state":{"codex-wake@codex-wake-local:a":1}}}),"v1")]});
        let mut reads = 0;
        let mut writes = 0;
        let mut call = |method: &str, _: Value| {
            if method == "config/read" {
                reads += 1;
                Ok(response.clone())
            } else {
                writes += 1;
                bail!("version conflict")
            }
        };

        assert!(
            clear_with(
                PLUGIN,
                Path::new("/tmp/cache"),
                &mut call,
                &mut |_| Ok(()),
                &mut |_, _| Ok(()),
            )
            .is_err()
        );
        assert_eq!((reads, writes), (3, 3));
    }

    #[test]
    fn exclusive_manifest_requires_one_exact_plugin() {
        let sole_owned = json!({"name":"codex-wake-local","plugins":[{"name":"codex-wake"}]});
        let shared =
            json!({"name":"codex-wake-local","plugins":[{"name":"codex-wake"},{"name":"other"}]});
        let other = json!({"name":"codex-wake-local","plugins":[{"name":"other"}]});
        assert!(exclusive_manifest(
            &sole_owned,
            "codex-wake-local",
            "codex-wake"
        ));
        assert!(!exclusive_manifest(
            &shared,
            "codex-wake-local",
            "codex-wake"
        ));
        assert!(!exclusive_manifest(
            &other,
            "codex-wake-local",
            "codex-wake"
        ));
        assert!(!exclusive_manifest(
            &sole_owned,
            "another-marketplace",
            "codex-wake"
        ));
    }
}

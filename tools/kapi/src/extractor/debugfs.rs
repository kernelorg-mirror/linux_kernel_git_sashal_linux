use crate::formatter::OutputFormatter;
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use super::{ApiExtractor, ApiSpec, CapabilitySpec, display_api_spec};

#[derive(Deserialize)]
struct KernelApiJson {
    name: String,
    api_type: Option<String>,
    version: Option<u32>,
    description: Option<String>,
    long_description: Option<String>,
    context_flags: Option<u32>,
    since_version: Option<String>,
    examples: Option<String>,
    notes: Option<String>,
    capabilities: Option<Vec<KernelCapabilityJson>>,
}

#[derive(Deserialize)]
struct KernelCapabilityJson {
    capability: i32,
    name: String,
    action: String,
    allows: String,
    without_cap: String,
    check_condition: Option<String>,
    priority: Option<u8>,
    alternatives: Option<Vec<i32>>,
}

/// Extractor for kernel API specifications from debugfs
pub struct DebugfsExtractor {
    debugfs_path: PathBuf,
}

impl DebugfsExtractor {
    /// Create a new debugfs extractor with the specified debugfs path
    pub fn new(debugfs_path: Option<String>) -> Result<Self> {
        let path = match debugfs_path {
            Some(p) => PathBuf::from(p),
            None => PathBuf::from("/sys/kernel/debug"),
        };

        // Check if the debugfs path exists
        if !path.exists() {
            bail!("Debugfs path does not exist: {}", path.display());
        }

        // Check if kapi directory exists
        let kapi_path = path.join("kapi");
        if !kapi_path.exists() {
            bail!(
                "Kernel API debugfs interface not found at: {}",
                kapi_path.display()
            );
        }

        Ok(Self { debugfs_path: path })
    }

    /// Parse the list file to get all available API names
    fn parse_list_file(&self) -> Result<Vec<String>> {
        let list_path = self.debugfs_path.join("kapi/list");
        let content = fs::read_to_string(&list_path)
            .with_context(|| format!("Failed to read {}", list_path.display()))?;

        let mut apis = Vec::new();
        let mut in_list = false;

        for line in content.lines() {
            if line.contains("===") {
                in_list = true;
                continue;
            }

            if in_list && line.starts_with("Total:") {
                break;
            }

            if in_list && !line.trim().is_empty() {
                // Extract API name from lines like "sys_read - Read from a file descriptor"
                if let Some(name) = line.split(" - ").next() {
                    apis.push(name.trim().to_string());
                }
            }
        }

        Ok(apis)
    }

    /// Try to parse JSON content, convert context flags from u32 to string representations
    fn parse_context_flags(flags: u32) -> Vec<String> {
        let mut result = Vec::new();

        // These values should match KAPI_CTX_* flags from kernel
        if flags & (1 << 0) != 0 {
            result.push("PROCESS".to_string());
        }
        if flags & (1 << 1) != 0 {
            result.push("SOFTIRQ".to_string());
        }
        if flags & (1 << 2) != 0 {
            result.push("HARDIRQ".to_string());
        }
        if flags & (1 << 3) != 0 {
            result.push("NMI".to_string());
        }
        if flags & (1 << 4) != 0 {
            result.push("ATOMIC".to_string());
        }
        if flags & (1 << 5) != 0 {
            result.push("SLEEPABLE".to_string());
        }
        if flags & (1 << 6) != 0 {
            result.push("PREEMPT_DISABLED".to_string());
        }
        if flags & (1 << 7) != 0 {
            result.push("IRQ_DISABLED".to_string());
        }

        result
    }

    /// Convert capability action from kernel representation
    fn parse_capability_action(action: &str) -> String {
        match action {
            "bypass_check" => "Bypasses check".to_string(),
            "increase_limit" => "Increases limit".to_string(),
            "override_restriction" => "Overrides restriction".to_string(),
            "grant_permission" => "Grants permission".to_string(),
            "modify_behavior" => "Modifies behavior".to_string(),
            "access_resource" => "Allows resource access".to_string(),
            "perform_operation" => "Allows operation".to_string(),
            _ => action.to_string(),
        }
    }

    /// Try to parse as JSON first
    fn try_parse_json(&self, content: &str) -> Option<ApiSpec> {
        let json_data: KernelApiJson = serde_json::from_str(content).ok()?;

        let mut spec = ApiSpec {
            name: json_data.name,
            api_type: json_data.api_type.unwrap_or_else(|| "unknown".to_string()),
            description: json_data.description,
            long_description: json_data.long_description,
            version: json_data.version.map(|v| v.to_string()),
            context_flags: json_data
                .context_flags
                .map_or_else(Vec::new, Self::parse_context_flags),
            param_count: None,
            error_count: None,
            examples: json_data.examples,
            notes: json_data.notes,
            since_version: json_data.since_version,
            subsystem: None,   // Not in current JSON format
            sysfs_path: None,  // Not in current JSON format
            permissions: None, // Not in current JSON format
            socket_state: None,
            protocol_behaviors: vec![],
            addr_families: vec![],
            buffer_spec: None,
            async_spec: None,
            net_data_transfer: None,
            capabilities: vec![],
            parameters: vec![],
            return_spec: None,
            errors: vec![],
            signals: vec![],
            signal_masks: vec![],
            side_effects: vec![],
            state_transitions: vec![],
            constraints: vec![],
            locks: vec![],
            struct_specs: vec![],
        };

        // Convert capabilities
        if let Some(caps) = json_data.capabilities {
            for cap in caps {
                spec.capabilities.push(CapabilitySpec {
                    capability: cap.capability,
                    name: cap.name,
                    action: Self::parse_capability_action(&cap.action),
                    allows: cap.allows,
                    without_cap: cap.without_cap,
                    check_condition: cap.check_condition,
                    priority: cap.priority,
                    alternatives: cap.alternatives.unwrap_or_default(),
                });
            }
        }

        Some(spec)
    }

    /// Parse a single API specification file
    fn parse_spec_file(&self, api_name: &str) -> Result<ApiSpec> {
        let spec_path = self.debugfs_path.join(format!("kapi/specs/{}", api_name));
        let content = fs::read_to_string(&spec_path)
            .with_context(|| format!("Failed to read {}", spec_path.display()))?;

        // Try JSON parsing first
        if let Some(spec) = self.try_parse_json(&content) {
            return Ok(spec);
        }

        // Fall back to plain text parsing
        let mut spec = ApiSpec {
            name: api_name.to_string(),
            api_type: "unknown".to_string(),
            description: None,
            long_description: None,
            version: None,
            context_flags: Vec::new(),
            param_count: None,
            error_count: None,
            examples: None,
            notes: None,
            since_version: None,
            subsystem: None,
            sysfs_path: None,
            permissions: None,
            socket_state: None,
            protocol_behaviors: vec![],
            addr_families: vec![],
            buffer_spec: None,
            async_spec: None,
            net_data_transfer: None,
            capabilities: vec![],
            parameters: vec![],
            return_spec: None,
            errors: vec![],
            signals: vec![],
            signal_masks: vec![],
            side_effects: vec![],
            state_transitions: vec![],
            constraints: vec![],
            locks: vec![],
            struct_specs: vec![],
        };

        // Parse the content
        let mut collecting_multiline = false;
        let mut multiline_buffer = String::new();
        let mut multiline_field = "";
        let mut parsing_capability = false;
        let mut current_capability: Option<CapabilitySpec> = None;

        for line in content.lines() {
            // Handle capability sections
            if line.starts_with("Capabilities (") {
                continue; // Skip the header
            }
            if line.starts_with("  ") && line.contains(" (") && line.ends_with("):") {
                // Start of a capability entry like "  CAP_IPC_LOCK (14):"
                if let Some(cap) = current_capability.take() {
                    spec.capabilities.push(cap);
                }

                let parts: Vec<&str> = line.trim().split(" (").collect();
                if parts.len() == 2 {
                    let cap_name = parts[0].to_string();
                    let cap_id = parts[1].trim_end_matches("):").parse().unwrap_or(0);
                    current_capability = Some(CapabilitySpec {
                        capability: cap_id,
                        name: cap_name,
                        action: String::new(),
                        allows: String::new(),
                        without_cap: String::new(),
                        check_condition: None,
                        priority: None,
                        alternatives: Vec::new(),
                    });
                    parsing_capability = true;
                }
                continue;
            }
            if parsing_capability && line.starts_with("    ") {
                // Parse capability fields
                if let Some(ref mut cap) = current_capability {
                    if let Some(action) = line.strip_prefix("    Action: ") {
                        cap.action = action.to_string();
                    } else if let Some(allows) = line.strip_prefix("    Allows: ") {
                        cap.allows = allows.to_string();
                    } else if let Some(without) = line.strip_prefix("    Without: ") {
                        cap.without_cap = without.to_string();
                    } else if let Some(cond) = line.strip_prefix("    Condition: ") {
                        cap.check_condition = Some(cond.to_string());
                    } else if let Some(prio) = line.strip_prefix("    Priority: ") {
                        cap.priority = prio.parse().ok();
                    } else if let Some(alts) = line.strip_prefix("    Alternatives: ") {
                        cap.alternatives =
                            alts.split(", ").filter_map(|s| s.parse().ok()).collect();
                    }
                }
                continue;
            }
            if parsing_capability && !line.starts_with("  ") {
                // End of capabilities section
                if let Some(cap) = current_capability.take() {
                    spec.capabilities.push(cap);
                }
                parsing_capability = false;
            }

            // Handle section headers
            if line.starts_with("Parameters (") {
                if let Some(count_str) = line
                    .strip_prefix("Parameters (")
                    .and_then(|s| s.strip_suffix("):"))
                {
                    spec.param_count = count_str.parse().ok();
                }
                continue;
            } else if line.starts_with("Errors (") {
                if let Some(count_str) = line
                    .strip_prefix("Errors (")
                    .and_then(|s| s.strip_suffix("):"))
                {
                    spec.error_count = count_str.parse().ok();
                }
                continue;
            } else if line.starts_with("Examples:") {
                collecting_multiline = true;
                multiline_field = "examples";
                multiline_buffer.clear();
                continue;
            } else if line.starts_with("Notes:") {
                collecting_multiline = true;
                multiline_field = "notes";
                multiline_buffer.clear();
                continue;
            }

            // Handle multiline sections
            if collecting_multiline {
                if line.trim().is_empty() && multiline_buffer.ends_with("\n\n") {
                    collecting_multiline = false;
                    match multiline_field {
                        "examples" => spec.examples = Some(multiline_buffer.trim().to_string()),
                        "notes" => spec.notes = Some(multiline_buffer.trim().to_string()),
                        _ => {}
                    }
                    multiline_buffer.clear();
                } else {
                    if !multiline_buffer.is_empty() {
                        multiline_buffer.push('\n');
                    }
                    multiline_buffer.push_str(line);
                }
                continue;
            }

            // Parse regular fields
            if let Some(desc) = line.strip_prefix("Description: ") {
                spec.description = Some(desc.to_string());
            } else if let Some(long_desc) = line.strip_prefix("Long description: ") {
                spec.long_description = Some(long_desc.to_string());
            } else if let Some(version) = line.strip_prefix("Version: ") {
                spec.version = Some(version.to_string());
            } else if let Some(since) = line.strip_prefix("Since: ") {
                spec.since_version = Some(since.to_string());
            } else if let Some(flags) = line.strip_prefix("Context flags: ") {
                spec.context_flags = flags.split_whitespace().map(str::to_string).collect();
            } else if let Some(subsys) = line.strip_prefix("Subsystem: ") {
                spec.subsystem = Some(subsys.to_string());
            } else if let Some(path) = line.strip_prefix("Sysfs Path: ") {
                spec.sysfs_path = Some(path.to_string());
            } else if let Some(perms) = line.strip_prefix("Permissions: ") {
                spec.permissions = Some(perms.to_string());
            }
        }

        // Handle any remaining capability
        if let Some(cap) = current_capability.take() {
            spec.capabilities.push(cap);
        }

        // Determine API type based on name
        if api_name.starts_with("sys_") {
            spec.api_type = "syscall".to_string();
        } else if api_name.contains("_ioctl") || api_name.starts_with("ioctl_") {
            spec.api_type = "ioctl".to_string();
        } else if api_name.contains("sysfs")
            || api_name.ends_with("_show")
            || api_name.ends_with("_store")
        {
            spec.api_type = "sysfs".to_string();
        } else {
            spec.api_type = "function".to_string();
        }

        Ok(spec)
    }
}

impl ApiExtractor for DebugfsExtractor {
    fn extract_all(&self) -> Result<Vec<ApiSpec>> {
        let api_names = self.parse_list_file()?;
        let mut specs = Vec::new();

        for name in api_names {
            match self.parse_spec_file(&name) {
                Ok(spec) => specs.push(spec),
                Err(_e) => {} // Silently skip files that fail to parse
            }
        }

        Ok(specs)
    }

    fn extract_by_name(&self, name: &str) -> Result<Option<ApiSpec>> {
        let api_names = self.parse_list_file()?;

        if api_names.contains(&name.to_string()) {
            Ok(Some(self.parse_spec_file(name)?))
        } else {
            Ok(None)
        }
    }

    fn display_api_details(
        &self,
        api_name: &str,
        formatter: &mut dyn OutputFormatter,
        writer: &mut dyn Write,
    ) -> Result<()> {
        if let Some(spec) = self.extract_by_name(api_name)? {
            display_api_spec(&spec, formatter, writer)?;
        } else {
            writeln!(writer, "API '{api_name}' not found in debugfs")?;
        }

        Ok(())
    }
}

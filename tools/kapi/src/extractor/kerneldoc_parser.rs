use super::{
    ApiSpec, CapabilitySpec, ConstraintSpec, ErrorSpec, LockSpec, ParamSpec,
    ReturnSpec, SideEffectSpec, SignalSpec, StateTransitionSpec, StructSpec,
    StructFieldSpec,
};
use anyhow::Result;
use std::collections::HashMap;

/// Real kerneldoc parser that extracts KAPI annotations
pub struct KerneldocParserImpl;

impl KerneldocParserImpl {
    pub fn new() -> Self {
        KerneldocParserImpl
    }

    pub fn parse_kerneldoc(
        &self,
        doc: &str,
        name: &str,
        api_type: &str,
        _signature: Option<&str>,
    ) -> Result<ApiSpec> {
        let mut spec = ApiSpec {
            name: name.to_string(),
            api_type: api_type.to_string(),
            description: None,
            long_description: None,
            version: None,
            context_flags: vec![],
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

        // Parse line by line
        let lines: Vec<&str> = doc.lines().collect();
        let mut i = 0;

        // Extract main description from function name line
        if let Some(first_line) = lines.first() {
            if let Some((_, desc)) = first_line.split_once(" - ") {
                spec.description = Some(desc.trim().to_string());
            }
        }

        // Keep track of parameters we've seen
        let mut param_map: HashMap<String, ParamSpec> = HashMap::new();
        let mut struct_fields: Vec<StructFieldSpec> = Vec::new();
        let mut current_lock: Option<LockSpec> = None;
        let mut current_signal: Option<SignalSpec> = None;
        let mut current_capability: Option<CapabilitySpec> = None;

        while i < lines.len() {
            let line = lines[i].trim();

            // Skip empty lines
            if line.is_empty() {
                i += 1;
                continue;
            }

            // Parse @param lines
            if let Some(rest) = line.strip_prefix("@") {
                if let Some((param_name, desc)) = rest.split_once(':') {
                    let param_name = param_name.trim();
                    let desc = desc.trim();
                    if !param_name.contains('-') {
                        // This is a basic parameter description - add to map
                        param_map.insert(param_name.to_string(), ParamSpec {
                            index: param_map.len() as u32,
                            name: param_name.to_string(),
                            type_name: String::new(),
                            description: desc.to_string(),
                            flags: 0,
                            param_type: 0,
                            constraint_type: 0,
                            constraint: None,
                            min_value: None,
                            max_value: None,
                            valid_mask: None,
                            enum_values: vec![],
                            size: None,
                            alignment: None,
                        });
                    }
                }
            }
            // Parse long-desc
            else if let Some(rest) = line.strip_prefix("long-desc:") {
                spec.long_description = Some(self.collect_multiline_value(&lines, i, rest));
            }
            // Parse context-flags
            else if let Some(rest) = line.strip_prefix("context-flags:") {
                spec.context_flags = self.parse_context_flags(rest.trim());
            }
            // Parse param-count
            else if let Some(rest) = line.strip_prefix("param-count:") {
                spec.param_count = rest.trim().parse().ok();
            }
            // Parse param-type
            else if let Some(rest) = line.strip_prefix("param-type:") {
                let parts: Vec<&str> = rest.split(',').map(|s| s.trim()).collect();
                if parts.len() >= 2 {
                    if let Some(param) = param_map.get_mut(parts[0]) {
                        param.param_type = self.parse_param_type(parts[1]);
                    }
                }
            }
            // Parse param-flags
            else if let Some(rest) = line.strip_prefix("param-flags:") {
                let parts: Vec<&str> = rest.split(',').map(|s| s.trim()).collect();
                if parts.len() >= 2 {
                    if let Some(param) = param_map.get_mut(parts[0]) {
                        param.flags = self.parse_param_flags(parts[1]);
                    }
                }
            }
            // Parse param-range
            else if let Some(rest) = line.strip_prefix("param-range:") {
                let parts: Vec<&str> = rest.split(',').map(|s| s.trim()).collect();
                if parts.len() >= 3 {
                    if let Some(param) = param_map.get_mut(parts[0]) {
                        param.min_value = parts[1].parse().ok();
                        param.max_value = parts[2].parse().ok();
                        param.constraint_type = 1; // KAPI_CONSTRAINT_RANGE
                    }
                }
            }
            // Parse param-constraint
            else if let Some(rest) = line.strip_prefix("param-constraint:") {
                let parts: Vec<&str> = rest.splitn(2, ',').map(|s| s.trim()).collect();
                if parts.len() >= 2 {
                    if let Some(param) = param_map.get_mut(parts[0]) {
                        param.constraint = Some(parts[1].to_string());
                    }
                }
            }
            // Parse error
            else if let Some(rest) = line.strip_prefix("error:") {
                // Parse error in format: "ERROR_CODE, description"
                let parts: Vec<&str> = rest.splitn(2, ',').map(|s| s.trim()).collect();
                if parts.len() >= 2 {
                    let error_name = parts[0].to_string();
                    let description = parts[1].to_string();

                    // Look for desc: line on the next line
                    let mut full_description = description;
                    if i + 1 < lines.len() {
                        if let Some(desc_line) = lines[i + 1].strip_prefix("*   desc:") {
                            full_description = desc_line.trim().to_string();
                        } else if let Some(desc_line) = lines[i + 1].strip_prefix("* desc:") {
                            full_description = desc_line.trim().to_string();
                        }
                    }

                    // Map common error names to codes
                    let error_code = match error_name.as_str() {
                        "E2BIG" => -7,
                        "EACCES" => -13,
                        "EAGAIN" => -11,
                        "EBADF" => -9,
                        "EBUSY" => -16,
                        "EFAULT" => -14,
                        "EINTR" => -4,
                        "EINVAL" => -22,
                        "EIO" => -5,
                        "EISDIR" => -21,
                        "ELIBBAD" => -80,
                        "ELOOP" => -40,
                        "EMFILE" => -24,
                        "ENAMETOOLONG" => -36,
                        "ENFILE" => -23,
                        "ENOENT" => -2,
                        "ENOEXEC" => -8,
                        "ENOMEM" => -12,
                        "ENOTDIR" => -20,
                        "EOPNOTSUPP" => -95,
                        "EPERM" => -1,
                        "ESRCH" => -3,
                        "ETXTBSY" => -26,
                        _ => 0,
                    };

                    spec.errors.push(ErrorSpec {
                        error_code,
                        name: error_name,
                        condition: String::new(),
                        description: full_description,
                    });
                }
            }
            // Parse lock
            else if let Some(rest) = line.strip_prefix("lock:") {
                // Save previous lock if any
                if let Some(lock) = current_lock.take() {
                    spec.locks.push(lock);
                }

                let parts: Vec<&str> = rest.split(',').map(|s| s.trim()).collect();
                if parts.len() >= 2 {
                    current_lock = Some(LockSpec {
                        lock_name: parts[0].to_string(),
                        lock_type: self.parse_lock_type(parts[1]),
                        scope: super::KAPI_LOCK_INTERNAL, // default: acquired and released
                        description: String::new(),
                    });
                }
            }
            // Parse lock scope
            else if let Some(rest) = line.strip_prefix("lock-scope:") {
                if let Some(lock) = current_lock.as_mut() {
                    lock.scope = match rest.trim() {
                        "internal" => super::KAPI_LOCK_INTERNAL,
                        "acquires" => super::KAPI_LOCK_ACQUIRES,
                        "releases" => super::KAPI_LOCK_RELEASES,
                        "caller_held" => super::KAPI_LOCK_CALLER_HELD,
                        _ => super::KAPI_LOCK_INTERNAL,
                    };
                }
            }
            else if let Some(rest) = line.strip_prefix("lock-desc:") {
                if let Some(lock) = current_lock.as_mut() {
                    lock.description = self.collect_multiline_value(&lines, i, rest);
                }
            }
            // Parse signal
            else if let Some(rest) = line.strip_prefix("signal:") {
                // Save previous signal if any
                if let Some(signal) = current_signal.take() {
                    spec.signals.push(signal);
                }

                let signal_name = rest.trim().to_string();
                current_signal = Some(SignalSpec {
                    signal_num: 0,
                    signal_name,
                    direction: 1,
                    action: 0,
                    target: None,
                    condition: None,
                    description: None,
                    restartable: false,
                    timing: 0,
                    priority: 0,
                    interruptible: false,
                    queue: None,
                    sa_flags: 0,
                    sa_flags_required: 0,
                    sa_flags_forbidden: 0,
                    state_required: 0,
                    state_forbidden: 0,
                    error_on_signal: None,
                });
            }
            // Parse signal attributes
            else if let Some(rest) = line.strip_prefix("signal-direction:") {
                if let Some(signal) = current_signal.as_mut() {
                    signal.direction = self.parse_signal_direction(rest.trim());
                }
            }
            else if let Some(rest) = line.strip_prefix("signal-action:") {
                if let Some(signal) = current_signal.as_mut() {
                    signal.action = self.parse_signal_action(rest.trim());
                }
            }
            else if let Some(rest) = line.strip_prefix("signal-condition:") {
                if let Some(signal) = current_signal.as_mut() {
                    signal.condition = Some(self.collect_multiline_value(&lines, i, rest));
                }
            }
            else if let Some(rest) = line.strip_prefix("signal-desc:") {
                if let Some(signal) = current_signal.as_mut() {
                    signal.description = Some(self.collect_multiline_value(&lines, i, rest));
                }
            }
            else if let Some(rest) = line.strip_prefix("signal-timing:") {
                if let Some(signal) = current_signal.as_mut() {
                    signal.timing = self.parse_signal_timing(rest.trim());
                }
            }
            else if let Some(rest) = line.strip_prefix("signal-priority:") {
                if let Some(signal) = current_signal.as_mut() {
                    signal.priority = rest.trim().parse().unwrap_or(0);
                }
            }
            else if line.strip_prefix("signal-interruptible:").is_some() {
                if let Some(signal) = current_signal.as_mut() {
                    signal.interruptible = true;
                }
            }
            else if let Some(rest) = line.strip_prefix("signal-state-req:") {
                if let Some(signal) = current_signal.as_mut() {
                    signal.state_required = self.parse_signal_state(rest.trim());
                }
            }
            // Parse side-effect
            else if let Some(rest) = line.strip_prefix("side-effect:") {
                let full_effect = self.collect_multiline_value(&lines, i, rest);
                let parts: Vec<&str> = full_effect.splitn(3, ',').map(|s| s.trim()).collect();
                if parts.len() >= 3 {
                    let mut effect = SideEffectSpec {
                        effect_type: self.parse_effect_type(parts[0]),
                        target: parts[1].to_string(),
                        condition: None,
                        description: parts[2].to_string(),
                        reversible: false,
                    };

                    // Check for additional attributes
                    if let Some(pos) = parts[2].find("condition=") {
                        let cond_str = &parts[2][pos + 10..];
                        if let Some(end) = cond_str.find(',') {
                            effect.condition = Some(cond_str[..end].to_string());
                        } else {
                            effect.condition = Some(cond_str.to_string());
                        }
                    }

                    if parts[2].contains("reversible=yes") {
                        effect.reversible = true;
                    }

                    spec.side_effects.push(effect);
                }
            }
            // Parse state-trans
            else if let Some(rest) = line.strip_prefix("state-trans:") {
                let parts: Vec<&str> = rest.split(',').map(|s| s.trim()).collect();
                if parts.len() >= 4 {
                    spec.state_transitions.push(StateTransitionSpec {
                        object: parts[0].to_string(),
                        from_state: parts[1].to_string(),
                        to_state: parts[2].to_string(),
                        condition: None,
                        description: parts[3].to_string(),
                    });
                }
            }
            // Parse capability
            else if let Some(rest) = line.strip_prefix("capability:") {
                // Save previous capability if any
                if let Some(cap) = current_capability.take() {
                    spec.capabilities.push(cap);
                }

                let parts: Vec<&str> = rest.split(',').map(|s| s.trim()).collect();
                if parts.len() >= 3 {
                    current_capability = Some(CapabilitySpec {
                        capability: self.parse_capability_value(parts[0]),
                        action: parts[1].to_string(),
                        name: parts[2].to_string(),
                        allows: String::new(),
                        without_cap: String::new(),
                        check_condition: None,
                        priority: Some(0),
                        alternatives: vec![],
                    });
                }
            }
            // Parse capability attributes
            else if let Some(rest) = line.strip_prefix("capability-allows:") {
                if let Some(cap) = current_capability.as_mut() {
                    cap.allows = self.collect_multiline_value(&lines, i, rest);
                }
            }
            else if let Some(rest) = line.strip_prefix("capability-without:") {
                if let Some(cap) = current_capability.as_mut() {
                    cap.without_cap = self.collect_multiline_value(&lines, i, rest);
                }
            }
            else if let Some(rest) = line.strip_prefix("capability-condition:") {
                if let Some(cap) = current_capability.as_mut() {
                    cap.check_condition = Some(self.collect_multiline_value(&lines, i, rest));
                }
            }
            else if let Some(rest) = line.strip_prefix("capability-priority:") {
                if let Some(cap) = current_capability.as_mut() {
                    cap.priority = rest.trim().parse().ok();
                }
            }
            // Parse constraint
            else if let Some(rest) = line.strip_prefix("constraint:") {
                let parts: Vec<&str> = rest.splitn(2, ',').map(|s| s.trim()).collect();
                if parts.len() >= 2 {
                    spec.constraints.push(ConstraintSpec {
                        name: parts[0].to_string(),
                        description: parts[1].to_string(),
                        expression: None,
                    });
                }
            }
            // Parse constraint-expr
            else if let Some(rest) = line.strip_prefix("constraint-expr:") {
                let parts: Vec<&str> = rest.splitn(2, ',').map(|s| s.trim()).collect();
                if parts.len() >= 2 {
                    // Find matching constraint and update it
                    if let Some(constraint) = spec.constraints.iter_mut().find(|c| c.name == parts[0]) {
                        constraint.expression = Some(parts[1].to_string());
                    }
                }
            }
            // Parse struct-field
            else if let Some(rest) = line.strip_prefix("struct-field:") {
                let parts: Vec<&str> = rest.split(',').map(|s| s.trim()).collect();
                if parts.len() >= 3 {
                    struct_fields.push(StructFieldSpec {
                        name: parts[0].to_string(),
                        field_type: self.parse_field_type(parts[1]),
                        type_name: parts[1].to_string(),
                        offset: 0,
                        size: 0,
                        flags: 0,
                        constraint_type: 0,
                        min_value: 0,
                        max_value: 0,
                        valid_mask: 0,
                        description: parts[2].to_string(),
                    });
                }
            }
            // Parse struct-field-range
            else if let Some(rest) = line.strip_prefix("struct-field-range:") {
                let parts: Vec<&str> = rest.split(',').map(|s| s.trim()).collect();
                if parts.len() >= 3 {
                    // Update the field with range
                    if let Some(field) = struct_fields.iter_mut().find(|f| f.name == parts[0]) {
                        field.min_value = parts[1].parse().unwrap_or(0);
                        field.max_value = parts[2].parse().unwrap_or(0);
                        field.constraint_type = 1; // KAPI_CONSTRAINT_RANGE
                    }
                }
            }
            // Parse examples
            else if let Some(rest) = line.strip_prefix("examples:") {
                spec.examples = Some(self.collect_multiline_value(&lines, i, rest));
            }
            // Parse notes
            else if let Some(rest) = line.strip_prefix("notes:") {
                spec.notes = Some(self.collect_multiline_value(&lines, i, rest));
            }
            // Parse since-version
            else if let Some(rest) = line.strip_prefix("since-version:") {
                spec.since_version = Some(rest.trim().to_string());
            }
            // Parse return-type
            else if let Some(rest) = line.strip_prefix("return-type:") {
                if spec.return_spec.is_none() {
                    spec.return_spec = Some(ReturnSpec {
                        type_name: rest.trim().to_string(),
                        description: String::new(),
                        return_type: self.parse_param_type(rest.trim()),
                        check_type: 0,
                        success_value: None,
                        success_min: None,
                        success_max: None,
                        error_values: vec![],
                    });
                }
            }
            // Parse return-check-type
            else if let Some(rest) = line.strip_prefix("return-check-type:") {
                if let Some(ret) = spec.return_spec.as_mut() {
                    ret.check_type = self.parse_return_check_type(rest.trim());
                }
            }
            // Parse return-success
            else if let Some(rest) = line.strip_prefix("return-success:") {
                if let Some(ret) = spec.return_spec.as_mut() {
                    ret.success_value = rest.trim().parse().ok();
                }
            }

            i += 1;
        }

        // Save any remaining items
        if let Some(lock) = current_lock {
            spec.locks.push(lock);
        }
        if let Some(signal) = current_signal {
            spec.signals.push(signal);
        }
        if let Some(cap) = current_capability {
            spec.capabilities.push(cap);
        }

        // Convert param_map to vec preserving order
        let mut params: Vec<ParamSpec> = param_map.into_values().collect();
        params.sort_by_key(|p| p.index);
        spec.parameters = params;

        // Create struct spec if we have fields
        if !struct_fields.is_empty() {
            spec.struct_specs.push(StructSpec {
                name: "struct sched_attr".to_string(),
                size: 120, // Default for sched_attr
                alignment: 8,
                field_count: struct_fields.len() as u32,
                fields: struct_fields,
                description: "Structure specification".to_string(),
            });
        }

        Ok(spec)
    }

    fn collect_multiline_value(&self, lines: &[&str], start_idx: usize, first_part: &str) -> String {
        let mut result = String::from(first_part.trim());
        let mut i = start_idx + 1;

        // Continue collecting lines until we hit another annotation or end
        while i < lines.len() {
            let line = lines[i];

            // Stop if we hit another annotation (contains ':' and starts with valid keyword)
            if self.is_annotation_line(line) {
                break;
            }

            // Add continuation lines
            if !line.trim().is_empty() && line.starts_with("  ") {
                if !result.is_empty() {
                    result.push(' ');
                }
                result.push_str(line.trim());
            } else if line.trim().is_empty() {
                // Empty line might be part of multiline
                i += 1;
                continue;
            } else {
                // Non-continuation line, stop
                break;
            }

            i += 1;
        }

        result
    }

    fn is_annotation_line(&self, line: &str) -> bool {
        let annotations = [
            "param-", "error-", "lock", "signal", "side-effect:",
            "state-trans:", "capability", "constraint", "struct-",
            "return-", "examples:", "notes:", "since-", "context-",
            "long-desc:"
        ];

        for ann in &annotations {
            if line.trim_start().starts_with(ann) {
                return true;
            }
        }
        false
    }

    fn parse_context_flags(&self, flags: &str) -> Vec<String> {
        flags.split('|')
            .map(|f| f.trim().to_string())
            .collect()
    }

    fn parse_param_type(&self, type_str: &str) -> u32 {
        match type_str {
            "KAPI_TYPE_INT" => 1,
            "KAPI_TYPE_UINT" => 2,
            "KAPI_TYPE_LONG" => 3,
            "KAPI_TYPE_ULONG" => 4,
            "KAPI_TYPE_STRING" => 5,
            "KAPI_TYPE_USER_PTR" => 6,
            _ => 0,
        }
    }

    fn parse_field_type(&self, type_str: &str) -> u32 {
        match type_str {
            "__s32" | "int" => 1,
            "__u32" | "unsigned int" => 2,
            "__s64" | "long" => 3,
            "__u64" | "unsigned long" => 4,
            _ => 0,
        }
    }

    fn parse_param_flags(&self, flags: &str) -> u32 {
        let mut result = 0;
        for flag in flags.split('|') {
            match flag.trim() {
                "KAPI_PARAM_IN" => result |= 1,
                "KAPI_PARAM_OUT" => result |= 2,
                "KAPI_PARAM_INOUT" => result |= 3,
                "KAPI_PARAM_USER" => result |= 4,
                _ => {}
            }
        }
        result
    }

    fn parse_lock_type(&self, type_str: &str) -> u32 {
        match type_str {
            "KAPI_LOCK_SPINLOCK" => 0,
            "KAPI_LOCK_MUTEX" => 1,
            "KAPI_LOCK_RWLOCK" => 2,
            _ => 3,
        }
    }

    fn parse_signal_direction(&self, dir: &str) -> u32 {
        match dir {
            "KAPI_SIGNAL_SEND" => 1,
            "KAPI_SIGNAL_RECEIVE" => 2,
            _ => 0,
        }
    }

    fn parse_signal_action(&self, action: &str) -> u32 {
        match action {
            "KAPI_SIGNAL_ACTION_DEFAULT" => 0,
            "KAPI_SIGNAL_ACTION_IGNORE" => 1,
            "KAPI_SIGNAL_ACTION_CUSTOM" => 2,
            _ => 0,
        }
    }

    fn parse_signal_timing(&self, timing: &str) -> u32 {
        match timing {
            "KAPI_SIGNAL_TIME_BEFORE" => 0,
            "KAPI_SIGNAL_TIME_DURING" => 1,
            "KAPI_SIGNAL_TIME_AFTER" => 2,
            _ => 0,
        }
    }

    fn parse_signal_state(&self, state: &str) -> u32 {
        match state {
            "KAPI_SIGNAL_STATE_RUNNING" => 1,
            "KAPI_SIGNAL_STATE_SLEEPING" => 2,
            _ => 0,
        }
    }

    fn parse_effect_type(&self, type_str: &str) -> u32 {
        let mut result = 0;
        for flag in type_str.split('|') {
            match flag.trim() {
                "KAPI_EFFECT_MODIFY_STATE" => result |= 1,
                "KAPI_EFFECT_PROCESS_STATE" => result |= 2,
                "KAPI_EFFECT_SCHEDULE" => result |= 4,
                _ => {}
            }
        }
        result
    }

    fn parse_capability_value(&self, cap: &str) -> i32 {
        match cap {
            "CAP_SYS_NICE" => 23,
            _ => 0,
        }
    }

    fn parse_return_check_type(&self, check: &str) -> u32 {
        match check {
            "KAPI_RETURN_ERROR_CHECK" => 1,
            "KAPI_RETURN_SUCCESS_CHECK" => 2,
            _ => 0,
        }
    }
}
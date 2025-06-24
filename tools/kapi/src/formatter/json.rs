use super::OutputFormatter;
use crate::extractor::{
    AddrFamilySpec, AsyncSpec, BufferSpec, CapabilitySpec, ConstraintSpec, ErrorSpec, LockSpec,
    ParamSpec, ProtocolBehaviorSpec, ReturnSpec, SideEffectSpec, SignalMaskSpec, SignalSpec,
    SocketStateSpec, StateTransitionSpec, StructSpec,
};
use serde::Serialize;
use std::io::Write;

pub struct JsonFormatter {
    data: JsonData,
}

#[derive(Serialize)]
struct JsonData {
    #[serde(skip_serializing_if = "Option::is_none")]
    apis: Option<Vec<JsonApi>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    api_details: Option<JsonApiDetails>,
}

#[derive(Serialize)]
struct JsonApi {
    name: String,
    api_type: String,
}

#[derive(Serialize)]
struct JsonApiDetails {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    long_description: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    context_flags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    examples: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    since_version: Option<String>,
    // Sysfs-specific fields
    #[serde(skip_serializing_if = "Option::is_none")]
    subsystem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sysfs_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    permissions: Option<String>,
    // Networking-specific fields
    #[serde(skip_serializing_if = "Option::is_none")]
    socket_state: Option<SocketStateSpec>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    protocol_behaviors: Vec<ProtocolBehaviorSpec>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    addr_families: Vec<AddrFamilySpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    buffer_spec: Option<BufferSpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    async_spec: Option<AsyncSpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    net_data_transfer: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    capabilities: Vec<CapabilitySpec>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    state_transitions: Vec<StateTransitionSpec>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    side_effects: Vec<SideEffectSpec>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    parameters: Vec<ParamSpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    return_spec: Option<ReturnSpec>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    errors: Vec<ErrorSpec>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    locks: Vec<LockSpec>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    struct_specs: Vec<StructSpec>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    signals: Vec<SignalSpec>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    signal_masks: Vec<SignalMaskSpec>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    constraints: Vec<ConstraintSpec>,
}

impl JsonFormatter {
    pub fn new() -> Self {
        JsonFormatter {
            data: JsonData {
                apis: None,
                api_details: None,
            },
        }
    }
}

impl OutputFormatter for JsonFormatter {
    fn begin_document(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn end_document(&mut self, w: &mut dyn Write) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(&self.data)?;
        writeln!(w, "{json}")?;
        Ok(())
    }

    fn begin_api_list(&mut self, _w: &mut dyn Write, _title: &str) -> std::io::Result<()> {
        self.data.apis = Some(Vec::new());
        Ok(())
    }

    fn api_item(&mut self, _w: &mut dyn Write, name: &str, api_type: &str) -> std::io::Result<()> {
        if let Some(apis) = &mut self.data.apis {
            apis.push(JsonApi {
                name: name.to_string(),
                api_type: api_type.to_string(),
            });
        }
        Ok(())
    }

    fn end_api_list(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn total_specs(&mut self, _w: &mut dyn Write, _count: usize) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_api_details(&mut self, _w: &mut dyn Write, name: &str) -> std::io::Result<()> {
        self.data.api_details = Some(JsonApiDetails {
            name: name.to_string(),
            description: None,
            long_description: None,
            context_flags: Vec::new(),
            examples: None,
            notes: None,
            since_version: None,
            subsystem: None,
            sysfs_path: None,
            permissions: None,
            socket_state: None,
            protocol_behaviors: Vec::new(),
            addr_families: Vec::new(),
            buffer_spec: None,
            async_spec: None,
            net_data_transfer: None,
            capabilities: Vec::new(),
            state_transitions: Vec::new(),
            side_effects: Vec::new(),
            parameters: Vec::new(),
            return_spec: None,
            errors: Vec::new(),
            locks: Vec::new(),
            struct_specs: Vec::new(),
            signals: Vec::new(),
            signal_masks: Vec::new(),
            constraints: Vec::new(),
        });
        Ok(())
    }

    fn end_api_details(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn description(&mut self, _w: &mut dyn Write, desc: &str) -> std::io::Result<()> {
        if let Some(details) = &mut self.data.api_details {
            details.description = Some(desc.to_string());
        }
        Ok(())
    }

    fn long_description(&mut self, _w: &mut dyn Write, desc: &str) -> std::io::Result<()> {
        if let Some(details) = &mut self.data.api_details {
            details.long_description = Some(desc.to_string());
        }
        Ok(())
    }

    fn begin_context_flags(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn context_flag(&mut self, _w: &mut dyn Write, flag: &str) -> std::io::Result<()> {
        if let Some(details) = &mut self.data.api_details {
            details.context_flags.push(flag.to_string());
        }
        Ok(())
    }

    fn end_context_flags(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_parameters(&mut self, _w: &mut dyn Write, _count: u32) -> std::io::Result<()> {
        Ok(())
    }

    fn end_parameters(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_errors(&mut self, _w: &mut dyn Write, _count: u32) -> std::io::Result<()> {
        Ok(())
    }

    fn end_errors(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn examples(&mut self, _w: &mut dyn Write, examples: &str) -> std::io::Result<()> {
        if let Some(details) = &mut self.data.api_details {
            details.examples = Some(examples.to_string());
        }
        Ok(())
    }

    fn notes(&mut self, _w: &mut dyn Write, notes: &str) -> std::io::Result<()> {
        if let Some(details) = &mut self.data.api_details {
            details.notes = Some(notes.to_string());
        }
        Ok(())
    }

    fn since_version(&mut self, _w: &mut dyn Write, version: &str) -> std::io::Result<()> {
        if let Some(details) = &mut self.data.api_details {
            details.since_version = Some(version.to_string());
        }
        Ok(())
    }

    fn sysfs_subsystem(&mut self, _w: &mut dyn Write, subsystem: &str) -> std::io::Result<()> {
        if let Some(details) = &mut self.data.api_details {
            details.subsystem = Some(subsystem.to_string());
        }
        Ok(())
    }

    fn sysfs_path(&mut self, _w: &mut dyn Write, path: &str) -> std::io::Result<()> {
        if let Some(details) = &mut self.data.api_details {
            details.sysfs_path = Some(path.to_string());
        }
        Ok(())
    }

    fn sysfs_permissions(&mut self, _w: &mut dyn Write, perms: &str) -> std::io::Result<()> {
        if let Some(details) = &mut self.data.api_details {
            details.permissions = Some(perms.to_string());
        }
        Ok(())
    }

    // Networking-specific methods
    fn socket_state(&mut self, _w: &mut dyn Write, state: &SocketStateSpec) -> std::io::Result<()> {
        if let Some(details) = &mut self.data.api_details {
            details.socket_state = Some(state.clone());
        }
        Ok(())
    }

    fn begin_protocol_behaviors(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn protocol_behavior(
        &mut self,
        _w: &mut dyn Write,
        behavior: &ProtocolBehaviorSpec,
    ) -> std::io::Result<()> {
        if let Some(details) = &mut self.data.api_details {
            details.protocol_behaviors.push(behavior.clone());
        }
        Ok(())
    }

    fn end_protocol_behaviors(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_addr_families(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn addr_family(&mut self, _w: &mut dyn Write, family: &AddrFamilySpec) -> std::io::Result<()> {
        if let Some(details) = &mut self.data.api_details {
            details.addr_families.push(family.clone());
        }
        Ok(())
    }

    fn end_addr_families(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn buffer_spec(&mut self, _w: &mut dyn Write, spec: &BufferSpec) -> std::io::Result<()> {
        if let Some(details) = &mut self.data.api_details {
            details.buffer_spec = Some(spec.clone());
        }
        Ok(())
    }

    fn async_spec(&mut self, _w: &mut dyn Write, spec: &AsyncSpec) -> std::io::Result<()> {
        if let Some(details) = &mut self.data.api_details {
            details.async_spec = Some(spec.clone());
        }
        Ok(())
    }

    fn net_data_transfer(&mut self, _w: &mut dyn Write, desc: &str) -> std::io::Result<()> {
        if let Some(details) = &mut self.data.api_details {
            details.net_data_transfer = Some(desc.to_string());
        }
        Ok(())
    }

    fn begin_capabilities(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn capability(&mut self, _w: &mut dyn Write, cap: &CapabilitySpec) -> std::io::Result<()> {
        if let Some(details) = &mut self.data.api_details {
            details.capabilities.push(cap.clone());
        }
        Ok(())
    }

    fn end_capabilities(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    // Stub implementations for new methods
    fn parameter(&mut self, _w: &mut dyn Write, param: &ParamSpec) -> std::io::Result<()> {
        if let Some(details) = &mut self.data.api_details {
            details.parameters.push(param.clone());
        }
        Ok(())
    }

    fn return_spec(&mut self, _w: &mut dyn Write, ret: &ReturnSpec) -> std::io::Result<()> {
        if let Some(details) = &mut self.data.api_details {
            details.return_spec = Some(ret.clone());
        }
        Ok(())
    }

    fn error(&mut self, _w: &mut dyn Write, error: &ErrorSpec) -> std::io::Result<()> {
        if let Some(details) = &mut self.data.api_details {
            details.errors.push(error.clone());
        }
        Ok(())
    }

    fn begin_signals(&mut self, _w: &mut dyn Write, _count: u32) -> std::io::Result<()> {
        Ok(())
    }

    fn signal(&mut self, _w: &mut dyn Write, signal: &SignalSpec) -> std::io::Result<()> {
        if let Some(api_details) = &mut self.data.api_details {
            api_details.signals.push(signal.clone());
        }
        Ok(())
    }

    fn end_signals(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_signal_masks(&mut self, _w: &mut dyn Write, _count: u32) -> std::io::Result<()> {
        Ok(())
    }

    fn signal_mask(&mut self, _w: &mut dyn Write, mask: &SignalMaskSpec) -> std::io::Result<()> {
        if let Some(api_details) = &mut self.data.api_details {
            api_details.signal_masks.push(mask.clone());
        }
        Ok(())
    }

    fn end_signal_masks(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_side_effects(&mut self, _w: &mut dyn Write, _count: u32) -> std::io::Result<()> {
        Ok(())
    }

    fn side_effect(&mut self, _w: &mut dyn Write, effect: &SideEffectSpec) -> std::io::Result<()> {
        if let Some(details) = &mut self.data.api_details {
            details.side_effects.push(effect.clone());
        }
        Ok(())
    }

    fn end_side_effects(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_state_transitions(&mut self, _w: &mut dyn Write, _count: u32) -> std::io::Result<()> {
        Ok(())
    }

    fn state_transition(
        &mut self,
        _w: &mut dyn Write,
        trans: &StateTransitionSpec,
    ) -> std::io::Result<()> {
        if let Some(details) = &mut self.data.api_details {
            details.state_transitions.push(trans.clone());
        }
        Ok(())
    }

    fn end_state_transitions(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_constraints(&mut self, _w: &mut dyn Write, _count: u32) -> std::io::Result<()> {
        Ok(())
    }

    fn constraint(
        &mut self,
        _w: &mut dyn Write,
        constraint: &ConstraintSpec,
    ) -> std::io::Result<()> {
        if let Some(api_details) = &mut self.data.api_details {
            api_details.constraints.push(constraint.clone());
        }
        Ok(())
    }

    fn end_constraints(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_locks(&mut self, _w: &mut dyn Write, _count: u32) -> std::io::Result<()> {
        Ok(())
    }

    fn lock(&mut self, _w: &mut dyn Write, lock: &LockSpec) -> std::io::Result<()> {
        if let Some(details) = &mut self.data.api_details {
            details.locks.push(lock.clone());
        }
        Ok(())
    }

    fn end_locks(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_struct_specs(&mut self, _w: &mut dyn Write, _count: u32) -> std::io::Result<()> {
        Ok(())
    }

    fn struct_spec(&mut self, _w: &mut dyn Write, spec: &StructSpec) -> std::io::Result<()> {
        if let Some(ref mut details) = self.data.api_details {
            details.struct_specs.push(spec.clone());
        }
        Ok(())
    }

    fn end_struct_specs(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }
}

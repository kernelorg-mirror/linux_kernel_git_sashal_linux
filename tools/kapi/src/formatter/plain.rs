use super::OutputFormatter;
use crate::extractor::{
    AddrFamilySpec, AsyncSpec, BufferSpec, CapabilitySpec, ConstraintSpec, ErrorSpec, LockSpec,
    ParamSpec, ProtocolBehaviorSpec, ReturnSpec, SideEffectSpec, SignalMaskSpec, SignalSpec,
    SocketStateSpec, StateTransitionSpec,
};
use std::io::Write;

pub struct PlainFormatter;

impl PlainFormatter {
    pub fn new() -> Self {
        PlainFormatter
    }
}

impl OutputFormatter for PlainFormatter {
    fn begin_document(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn end_document(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_api_list(&mut self, w: &mut dyn Write, title: &str) -> std::io::Result<()> {
        writeln!(w, "\n{title}:")?;
        writeln!(w, "{}", "-".repeat(title.len() + 1))
    }

    fn api_item(&mut self, w: &mut dyn Write, name: &str, _api_type: &str) -> std::io::Result<()> {
        writeln!(w, "  {name}")
    }

    fn end_api_list(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn total_specs(&mut self, w: &mut dyn Write, count: usize) -> std::io::Result<()> {
        writeln!(w, "\nTotal specifications found: {count}")
    }

    fn begin_api_details(&mut self, w: &mut dyn Write, name: &str) -> std::io::Result<()> {
        writeln!(w, "\nDetailed information for {name}:")?;
        writeln!(w, "{}=", "=".repeat(25 + name.len()))
    }

    fn end_api_details(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn description(&mut self, w: &mut dyn Write, desc: &str) -> std::io::Result<()> {
        writeln!(w, "Description: {desc}")
    }

    fn long_description(&mut self, w: &mut dyn Write, desc: &str) -> std::io::Result<()> {
        writeln!(w, "\nDetailed Description:")?;
        writeln!(w, "{desc}")
    }

    fn begin_context_flags(&mut self, w: &mut dyn Write) -> std::io::Result<()> {
        writeln!(w, "\nExecution Context:")
    }

    fn context_flag(&mut self, w: &mut dyn Write, flag: &str) -> std::io::Result<()> {
        writeln!(w, "  - {flag}")
    }

    fn end_context_flags(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_parameters(&mut self, w: &mut dyn Write, count: u32) -> std::io::Result<()> {
        writeln!(w, "\nParameters ({count}):")
    }

    fn parameter(&mut self, w: &mut dyn Write, param: &ParamSpec) -> std::io::Result<()> {
        writeln!(
            w,
            "  [{}] {} ({})",
            param.index, param.name, param.type_name
        )?;
        if !param.description.is_empty() {
            writeln!(w, "      {}", param.description)?;
        }

        // Display flags
        let mut flags = Vec::new();
        if param.flags & 0x01 != 0 {
            flags.push("IN");
        }
        if param.flags & 0x02 != 0 {
            flags.push("OUT");
        }
        if param.flags & 0x04 != 0 {
            flags.push("INOUT");
        }
        if param.flags & 0x08 != 0 {
            flags.push("USER");
        }
        if param.flags & 0x10 != 0 {
            flags.push("OPTIONAL");
        }
        if !flags.is_empty() {
            writeln!(w, "      Flags: {}", flags.join(" | "))?;
        }

        // Display constraints
        if let Some(constraint) = &param.constraint {
            writeln!(w, "      Constraint: {constraint}")?;
        }
        if let (Some(min), Some(max)) = (param.min_value, param.max_value) {
            writeln!(w, "      Range: {min} to {max}")?;
        }
        if let Some(mask) = param.valid_mask {
            writeln!(w, "      Valid mask: 0x{mask:x}")?;
        }
        Ok(())
    }

    fn end_parameters(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn return_spec(&mut self, w: &mut dyn Write, ret: &ReturnSpec) -> std::io::Result<()> {
        writeln!(w, "\nReturn Value:")?;
        writeln!(w, "  Type: {}", ret.type_name)?;
        writeln!(w, "  {}", ret.description)?;
        if let Some(val) = ret.success_value {
            writeln!(w, "  Success value: {val}")?;
        }
        if let (Some(min), Some(max)) = (ret.success_min, ret.success_max) {
            writeln!(w, "  Success range: {min} to {max}")?;
        }
        Ok(())
    }

    fn begin_errors(&mut self, w: &mut dyn Write, count: u32) -> std::io::Result<()> {
        writeln!(w, "\nPossible Errors ({count}):")
    }

    fn error(&mut self, w: &mut dyn Write, error: &ErrorSpec) -> std::io::Result<()> {
        writeln!(w, "  {} ({})", error.name, error.error_code)?;
        if !error.condition.is_empty() {
            writeln!(w, "      Condition: {}", error.condition)?;
        }
        if !error.description.is_empty() {
            writeln!(w, "      {}", error.description)?;
        }
        Ok(())
    }

    fn end_errors(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn examples(&mut self, w: &mut dyn Write, examples: &str) -> std::io::Result<()> {
        writeln!(w, "\nExamples:")?;
        writeln!(w, "{examples}")
    }

    fn notes(&mut self, w: &mut dyn Write, notes: &str) -> std::io::Result<()> {
        writeln!(w, "\nNotes:")?;
        writeln!(w, "{notes}")
    }

    fn since_version(&mut self, w: &mut dyn Write, version: &str) -> std::io::Result<()> {
        writeln!(w, "\nAvailable since: {version}")
    }

    fn sysfs_subsystem(&mut self, w: &mut dyn Write, subsystem: &str) -> std::io::Result<()> {
        writeln!(w, "Subsystem: {subsystem}")
    }

    fn sysfs_path(&mut self, w: &mut dyn Write, path: &str) -> std::io::Result<()> {
        writeln!(w, "Sysfs Path: {path}")
    }

    fn sysfs_permissions(&mut self, w: &mut dyn Write, perms: &str) -> std::io::Result<()> {
        writeln!(w, "Permissions: {perms}")
    }

    // Networking-specific methods
    fn socket_state(&mut self, w: &mut dyn Write, state: &SocketStateSpec) -> std::io::Result<()> {
        writeln!(w, "\nSocket State Requirements:")?;
        if !state.required_states.is_empty() {
            writeln!(w, "  Required states: {:?}", state.required_states)?;
        }
        if !state.forbidden_states.is_empty() {
            writeln!(w, "  Forbidden states: {:?}", state.forbidden_states)?;
        }
        if let Some(result) = &state.resulting_state {
            writeln!(w, "  Resulting state: {result}")?;
        }
        if let Some(cond) = &state.condition {
            writeln!(w, "  Condition: {cond}")?;
        }
        if let Some(protos) = &state.applicable_protocols {
            writeln!(w, "  Applicable protocols: {protos}")?;
        }
        Ok(())
    }

    fn begin_protocol_behaviors(&mut self, w: &mut dyn Write) -> std::io::Result<()> {
        writeln!(w, "\nProtocol-Specific Behaviors:")
    }

    fn protocol_behavior(
        &mut self,
        w: &mut dyn Write,
        behavior: &ProtocolBehaviorSpec,
    ) -> std::io::Result<()> {
        writeln!(
            w,
            "  {} - {}",
            behavior.applicable_protocols, behavior.behavior
        )?;
        if let Some(flags) = &behavior.protocol_flags {
            writeln!(w, "    Flags: {flags}")?;
        }
        Ok(())
    }

    fn end_protocol_behaviors(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_addr_families(&mut self, w: &mut dyn Write) -> std::io::Result<()> {
        writeln!(w, "\nSupported Address Families:")
    }

    fn addr_family(&mut self, w: &mut dyn Write, family: &AddrFamilySpec) -> std::io::Result<()> {
        writeln!(w, "  {} ({}):", family.family_name, family.family)?;
        writeln!(w, "    Struct size: {} bytes", family.addr_struct_size)?;
        writeln!(
            w,
            "    Address length: {}-{} bytes",
            family.min_addr_len, family.max_addr_len
        )?;
        if let Some(format) = &family.addr_format {
            writeln!(w, "    Format: {format}")?;
        }
        writeln!(
            w,
            "    Features: wildcard={}, multicast={}, broadcast={}",
            family.supports_wildcard, family.supports_multicast, family.supports_broadcast
        )?;
        if let Some(special) = &family.special_addresses {
            writeln!(w, "    Special addresses: {special}")?;
        }
        if family.port_range_max > 0 {
            writeln!(
                w,
                "    Port range: {}-{}",
                family.port_range_min, family.port_range_max
            )?;
        }
        Ok(())
    }

    fn end_addr_families(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn buffer_spec(&mut self, w: &mut dyn Write, spec: &BufferSpec) -> std::io::Result<()> {
        writeln!(w, "\nBuffer Specification:")?;
        if let Some(behaviors) = &spec.buffer_behaviors {
            writeln!(w, "  Behaviors: {behaviors}")?;
        }
        if let Some(min) = spec.min_buffer_size {
            writeln!(w, "  Min size: {min} bytes")?;
        }
        if let Some(max) = spec.max_buffer_size {
            writeln!(w, "  Max size: {max} bytes")?;
        }
        if let Some(optimal) = spec.optimal_buffer_size {
            writeln!(w, "  Optimal size: {optimal} bytes")?;
        }
        Ok(())
    }

    fn async_spec(&mut self, w: &mut dyn Write, spec: &AsyncSpec) -> std::io::Result<()> {
        writeln!(w, "\nAsynchronous Operation:")?;
        if let Some(modes) = &spec.supported_modes {
            writeln!(w, "  Supported modes: {modes}")?;
        }
        if let Some(errno) = spec.nonblock_errno {
            writeln!(w, "  Non-blocking errno: {errno}")?;
        }
        Ok(())
    }

    fn net_data_transfer(&mut self, w: &mut dyn Write, desc: &str) -> std::io::Result<()> {
        writeln!(w, "\nNetwork Data Transfer: {desc}")
    }

    fn begin_capabilities(&mut self, w: &mut dyn Write) -> std::io::Result<()> {
        writeln!(w, "\nRequired Capabilities:")
    }

    fn capability(&mut self, w: &mut dyn Write, cap: &CapabilitySpec) -> std::io::Result<()> {
        writeln!(w, "  {} ({}) - {}", cap.name, cap.capability, cap.action)?;
        if !cap.allows.is_empty() {
            writeln!(w, "    Allows: {}", cap.allows)?;
        }
        if !cap.without_cap.is_empty() {
            writeln!(w, "    Without capability: {}", cap.without_cap)?;
        }
        if let Some(cond) = &cap.check_condition {
            writeln!(w, "    Condition: {cond}")?;
        }
        Ok(())
    }

    fn end_capabilities(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    // Signal-related methods
    fn begin_signals(&mut self, w: &mut dyn Write, count: u32) -> std::io::Result<()> {
        writeln!(w, "\nSignal Specifications ({count}):")
    }

    fn signal(&mut self, w: &mut dyn Write, signal: &SignalSpec) -> std::io::Result<()> {
        write!(w, "  {} ({})", signal.signal_name, signal.signal_num)?;

        // Display direction
        let direction = match signal.direction {
            0 => "SEND",
            1 => "RECEIVE",
            2 => "HANDLE",
            3 => "IGNORE",
            _ => "UNKNOWN",
        };
        write!(w, " - {direction}")?;

        // Display action
        let action = match signal.action {
            0 => "DEFAULT",
            1 => "TERMINATE",
            2 => "COREDUMP",
            3 => "STOP",
            4 => "CONTINUE",
            5 => "IGNORE",
            6 => "CUSTOM",
            7 => "DISCARD",
            _ => "UNKNOWN",
        };
        writeln!(w, " - {action}")?;

        if let Some(target) = &signal.target {
            writeln!(w, "      Target: {target}")?;
        }
        if let Some(condition) = &signal.condition {
            writeln!(w, "      Condition: {condition}")?;
        }
        if let Some(desc) = &signal.description {
            writeln!(w, "      {desc}")?;
        }

        // Display timing
        let timing = match signal.timing {
            0 => "BEFORE",
            1 => "DURING",
            2 => "AFTER",
            3 => "EXIT",
            _ => "UNKNOWN",
        };
        writeln!(w, "      Timing: {timing}")?;
        writeln!(w, "      Priority: {}", signal.priority)?;

        if signal.restartable {
            writeln!(w, "      Restartable: yes")?;
        }
        if signal.interruptible {
            writeln!(w, "      Interruptible: yes")?;
        }
        if let Some(error) = signal.error_on_signal {
            writeln!(w, "      Error on signal: {error}")?;
        }
        Ok(())
    }

    fn end_signals(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_signal_masks(&mut self, w: &mut dyn Write, count: u32) -> std::io::Result<()> {
        writeln!(w, "\nSignal Masks ({count}):")
    }

    fn signal_mask(&mut self, w: &mut dyn Write, mask: &SignalMaskSpec) -> std::io::Result<()> {
        writeln!(w, "  {}", mask.name)?;
        if !mask.description.is_empty() {
            writeln!(w, "      {}", mask.description)?;
        }
        Ok(())
    }

    fn end_signal_masks(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    // Side effects and state transitions
    fn begin_side_effects(&mut self, w: &mut dyn Write, count: u32) -> std::io::Result<()> {
        writeln!(w, "\nSide Effects ({count}):")
    }

    fn side_effect(&mut self, w: &mut dyn Write, effect: &SideEffectSpec) -> std::io::Result<()> {
        writeln!(w, "  {} - {}", effect.target, effect.description)?;
        if let Some(condition) = &effect.condition {
            writeln!(w, "      Condition: {condition}")?;
        }
        if effect.reversible {
            writeln!(w, "      Reversible: yes")?;
        }
        Ok(())
    }

    fn end_side_effects(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_state_transitions(&mut self, w: &mut dyn Write, count: u32) -> std::io::Result<()> {
        writeln!(w, "\nState Transitions ({count}):")
    }

    fn state_transition(
        &mut self,
        w: &mut dyn Write,
        trans: &StateTransitionSpec,
    ) -> std::io::Result<()> {
        writeln!(
            w,
            "  {} : {} -> {}",
            trans.object, trans.from_state, trans.to_state
        )?;
        if let Some(condition) = &trans.condition {
            writeln!(w, "      Condition: {condition}")?;
        }
        if !trans.description.is_empty() {
            writeln!(w, "      {}", trans.description)?;
        }
        Ok(())
    }

    fn end_state_transitions(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    // Constraints and locks
    fn begin_constraints(&mut self, w: &mut dyn Write, count: u32) -> std::io::Result<()> {
        writeln!(w, "\nAdditional Constraints ({count}):")
    }

    fn constraint(
        &mut self,
        w: &mut dyn Write,
        constraint: &ConstraintSpec,
    ) -> std::io::Result<()> {
        writeln!(w, "  {}", constraint.name)?;
        if !constraint.description.is_empty() {
            writeln!(w, "      {}", constraint.description)?;
        }
        if let Some(expr) = &constraint.expression {
            writeln!(w, "      Expression: {expr}")?;
        }
        Ok(())
    }

    fn end_constraints(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_locks(&mut self, w: &mut dyn Write, count: u32) -> std::io::Result<()> {
        writeln!(w, "\nLocking Requirements ({count}):")
    }

    fn lock(&mut self, w: &mut dyn Write, lock: &LockSpec) -> std::io::Result<()> {
        write!(w, "  {}", lock.lock_name)?;

        // Display lock type
        let lock_type = match lock.lock_type {
            0 => "NONE",
            1 => "MUTEX",
            2 => "SPINLOCK",
            3 => "RWLOCK",
            4 => "SEQLOCK",
            5 => "RCU",
            6 => "SEMAPHORE",
            7 => "CUSTOM",
            _ => "UNKNOWN",
        };
        writeln!(w, " ({lock_type})")?;

        let scope_str = match lock.scope {
            0 => "acquired and released",
            1 => "acquired (not released)",
            2 => "released (held on entry)",
            3 => "held by caller",
            _ => "unknown",
        };
        writeln!(w, "      Scope: {scope_str}")?;

        if !lock.description.is_empty() {
            writeln!(w, "      {}", lock.description)?;
        }
        Ok(())
    }

    fn end_locks(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_struct_specs(&mut self, w: &mut dyn Write, count: u32) -> std::io::Result<()> {
        writeln!(w, "\nStructure Specifications ({count}):")
    }

    fn struct_spec(&mut self, w: &mut dyn Write, spec: &crate::extractor::StructSpec) -> std::io::Result<()> {
        writeln!(w, "  {} (size={}, align={}):", spec.name, spec.size, spec.alignment)?;
        if !spec.description.is_empty() {
            writeln!(w, "      {}", spec.description)?;
        }

        if !spec.fields.is_empty() {
            writeln!(w, "      Fields ({}):", spec.field_count)?;
            for field in &spec.fields {
                write!(w, "        - {} ({}):", field.name, field.type_name)?;
                if !field.description.is_empty() {
                    write!(w, " {}", field.description)?;
                }
                writeln!(w)?;

                // Show constraints if present
                if field.min_value != 0 || field.max_value != 0 {
                    writeln!(w, "          Range: [{}, {}]", field.min_value, field.max_value)?;
                }
                if field.valid_mask != 0 {
                    writeln!(w, "          Mask: {:#x}", field.valid_mask)?;
                }
            }
        }
        Ok(())
    }

    fn end_struct_specs(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }
}

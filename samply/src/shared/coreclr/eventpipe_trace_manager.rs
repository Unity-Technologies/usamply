use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::shared::jit_category_manager::JitCategoryManager;
use crate::shared::lib_mappings::{LibMappingAdd, LibMappingInfo, LibMappingOp, LibMappingOpQueue};
use crate::shared::timestamp_converter::TimestampConverter;
use coreclr_tracing::{CoreClrEvent, EventMetadata, ModuleLoadUnloadEvent};
use debugid::CodeId;
use coreclr_tracing::nettrace::EventPipeParser;
use fxprof_processed_profile::{
    LibraryHandle, LibraryInfo, Profile, Symbol, SymbolTable,
};
use wholesym::samply_symbols::debug_id_and_code_id_for_jitdump;

pub struct EventpipeTraceManager {
    pending_trace_paths: Vec<(u32, PathBuf)>,
    processors: Vec<SingleDotnetTraceProcessor>,
    unlink_after_open: bool,
}

impl EventpipeTraceManager {
    pub fn new(unlink_after_open: bool) -> Self {
        EventpipeTraceManager {
            pending_trace_paths: Vec::new(),
            processors: Vec::new(),
            unlink_after_open,
        }
    }

    pub fn add_dotnet_trace_path(
        &mut self,
        path: impl Into<PathBuf>,
        process_id: u32,
    ) {
        let path: PathBuf = path.into();
        log::info!("Adding dotnet trace path: {:?} for pid {}", path, process_id);
        self.pending_trace_paths.push((process_id, path));
    }

    pub fn process_pending_records(
        &mut self,
        jit_category_manager: &mut JitCategoryManager,
        profile: &mut Profile,
        timestamp_converter: &TimestampConverter,
    ) {
        self.pending_trace_paths.retain_mut(|(process_id, path)| {
            fn trace_reader_for_path(
                path: &Path,
                unlink_after_open: bool,
            ) -> Option<(EventPipeParser<std::fs::File>, PathBuf)> {
                let file = std::fs::File::open(path).ok()?;
                let reader = EventPipeParser::new(file).ok()?;
                if unlink_after_open {
                    std::fs::remove_file(path).ok()?;
                }
                Some((reader, path.into()))
            }
            let Some((reader, _actual_path)) = trace_reader_for_path(path, self.unlink_after_open)
            else {
                return true;
            };

            let (debug_id, code_id_bytes) = debug_id_and_code_id_for_jitdump(123, 234, 0);
            let code_id = CodeId::from_binary(&code_id_bytes);
            let name = path
                .file_name()
                .unwrap_or(path.as_os_str())
                .to_string_lossy()
                .into_owned();
            let path = path.to_string_lossy().into_owned();

            let lib_handle = profile.add_lib(LibraryInfo {
                debug_name: name.clone(),
                debug_path: path.clone(),
                name,
                path: path.clone(),
                debug_id,
                code_id: Some(code_id.to_string()),
                arch: None,
                symbol_table: None,
            });

            self.processors
                .push(SingleDotnetTraceProcessor::new(reader, lib_handle, *process_id));

            let _ = std::fs::remove_file(&path).is_err_and(|e| { log::warn!("Failed to remove {}: {}", path, e); true } );

            false // "Do not retain", i.e. remove from pending_jitdump_paths
        });

        for nettrace in &mut self.processors {
            nettrace.process_pending_records(
                jit_category_manager,
                profile,
                timestamp_converter,
            );
        }
    }

    pub fn finish(
        mut self,
        jit_category_manager: &mut JitCategoryManager,
        profile: &mut Profile,
        timestamp_converter: &TimestampConverter,
    ) -> Vec<LibMappingOpQueue> {
        self.process_pending_records(jit_category_manager, profile, timestamp_converter);
        self.processors
            .into_iter()
            .map(|processor| processor.finish(profile))
            .collect()
    }
}

struct SingleDotnetTraceProcessor {
    /// Some() until end
    reader: Option<EventPipeParser<std::fs::File>>,
    lib_handle: LibraryHandle,
    lib_mapping_ops: LibMappingOpQueue,
    symbols: Vec<Symbol>,

    modules: HashMap<u64, (EventMetadata, ModuleLoadUnloadEvent)>,
    seen_method_loads: HashSet<(u64, String)>,

    /// The relative_address of the next JIT function.
    ///
    /// We define the relative address space for Jitdump files as follows:
    /// Pretend that all JIT code is located in sequence, without gaps, in
    /// the order of JIT_CODE_LOAD entries in the file. A given JIT function's
    /// relative address is the sum of the `code_size`s of all the `JIT_CODE_LOAD`
    /// entries that came before it in the file.
    cumulative_address: u32,

    // The process ID of this process
    process_id: u32,
}

impl SingleDotnetTraceProcessor {
    pub fn new(reader: EventPipeParser<std::fs::File>, lib_handle: LibraryHandle, process_id: u32) -> Self {
        Self {
            reader: Some(reader),
            lib_handle,
            lib_mapping_ops: Default::default(),
            symbols: Default::default(),
            modules: Default::default(),
            seen_method_loads: Default::default(),
            cumulative_address: 0,
            process_id,
        }
    }

    pub fn process_pending_records(
        &mut self,
        jit_category_manager: &mut JitCategoryManager,
        profile: &mut Profile,
        timestamp_converter: &TimestampConverter,
    ) {
        if self.reader.is_none() {
            return;
        }

        let mut last_timestamp = 0;

        loop {
            let event = self.reader.as_mut().unwrap().next_event();
            match event {
                Ok(Some(ne)) => {
                    last_timestamp = ne.timestamp;
                    if let Some((event_meta, coreclr_event)) = coreclr_tracing::eventpipe::decode_coreclr_event(&ne) {
                        self.process_coreclr_event(
                            &event_meta.with_pid(self.process_id),
                            &coreclr_event,
                            jit_category_manager,
                            profile,
                            timestamp_converter,
                        );
                    }
                }
                Ok(None) => {
                    // last_timestamp is wrong here, but there's no explicit "close" (I don't think?)
                    // assume that the last event that we get has a timestamp that's roughly OK for
                    // end of process
                    self.lib_mapping_ops
                        .push(last_timestamp, LibMappingOp::Clear);
                    self.close_and_commit_symbol_table(profile);
                    return;
                }
                Err(err) => {
                    log::trace!("dotnet trace manager got error, ignoring: {:?}", err);
                    self.lib_mapping_ops
                        .push(last_timestamp, LibMappingOp::Clear);
                    self.close_and_commit_symbol_table(profile);
                    return;
                }
            }
        }
    }

    fn process_coreclr_event(
        &mut self,
        event_meta: &EventMetadata,
        event_coreclr: &CoreClrEvent,
        jit_category_manager: &mut JitCategoryManager,
        profile: &mut Profile,
        _timestamp_converter: &TimestampConverter,
    ) {
        match event_coreclr {
            CoreClrEvent::ModuleLoad(event) => {
                let module_id = event.module_id;
                //log::trace!("Loading module {} {} at {}", module_id, event.module_il_path, event.common.timestamp);
                self.modules.insert(module_id, (event_meta.clone(), event.clone()));
            }
            CoreClrEvent::ModuleUnload(event) => {
                let module_id = event.module_id;
                self.modules.remove(&module_id);
            }
            CoreClrEvent::MethodLoad(event) |
            CoreClrEvent::MethodDCEnd(event) => {
                let dc_end = match event_coreclr {
                    CoreClrEvent::MethodDCEnd(_) => true,
                    _ => false,
                };

                let start_avma = event.method_start_address;
                let end_avma = event.method_start_address + event.method_size as u64;

                let msig = (event.method_start_address, event.method_name.clone());
                if !dc_end {
                    self.seen_method_loads.insert(msig);
                } else if self.seen_method_loads.contains(&msig) {
                    // we already saw a normal MethodLoad for this; skip it, so that
                    // we don't flag this method as being valid from 0 time
                    return;
                }

                let relative_address_at_start = self.cumulative_address;
                self.cumulative_address += event.method_size;

                let symbol_name = event.method_name.to_string();
                self.symbols.push(Symbol {
                    address: relative_address_at_start,
                    size: if event.method_size == 0 {
                        None
                    } else {
                        Some(event.method_size)
                    },
                    name: symbol_name.clone(),
                });

                let lib_handle = self.lib_handle;

                log::trace!(
                    "MethodLoad: addr = 0x{:x} symbol_name = {:?} size = {} {}",
                    start_avma, symbol_name, event.method_size, if dc_end { "(DCEnd)" } else { "" }
                );

                let (category, js_frame) =
                    jit_category_manager.classify_jit_symbol(&symbol_name, profile);
                // If this is a method we haven't seen before but we see it in the DCEnd
                // rundown, assume that it's valid for the entire range of the trace.
                // This isn't necessarily correct, but it's the best we can do given
                // the information we get.
                let start_ts = if dc_end { 0 } else { event_meta.timestamp };

                self.lib_mapping_ops.push_unsorted(
                    start_ts,
                    LibMappingOp::Add(LibMappingAdd {
                        start_avma,
                        end_avma,
                        relative_address_at_start,
                        info: LibMappingInfo::new_jit_function(lib_handle, category, js_frame),
                    }),
                );
            }
            CoreClrEvent::ReadyToRunGetEntryPoint(_event) => {
                // Can't actually do anything with this, as we don't have a size. These methods just
                // won't be seen in the profile when we're using tracing only (like when attaching).
            }
            CoreClrEvent::GcAllocationTick(_event) => {}
            CoreClrEvent::MethodUnload(_event) => {}
            CoreClrEvent::GcTriggered(_event) => {}
            CoreClrEvent::GcSampledObjectAllocation(_event) => {}
            CoreClrEvent::GcStart(_event) => {}
            CoreClrEvent::GcEnd(_event) => {}
        }
    }

    fn close_and_commit_symbol_table(&mut self, profile: &mut Profile) {
        if self.reader.is_none() {
            // We're already closed.
            return;
        }

        let symbol_table = SymbolTable::new(std::mem::take(&mut self.symbols));
        profile.set_lib_symbol_table(self.lib_handle, Arc::new(symbol_table));
        self.reader = None;
    }

    pub fn finish(mut self, profile: &mut Profile) -> LibMappingOpQueue {
        self.close_and_commit_symbol_table(profile);
        self.lib_mapping_ops
    }
}

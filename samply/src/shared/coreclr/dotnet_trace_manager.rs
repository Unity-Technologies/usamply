use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::shared::jit_category_manager::JitCategoryManager;
use crate::shared::jit_function_recycler::JitFunctionRecycler;
use crate::shared::lib_mappings::{LibMappingAdd, LibMappingInfo, LibMappingOp, LibMappingOpQueue};
use crate::shared::timestamp_converter::TimestampConverter;
use debugid::CodeId;
use eventpipe::{EventPipeParser, NettraceEvent};
use fxprof_processed_profile::{
    CategoryHandle, LibraryHandle, LibraryInfo, MarkerTiming, Profile, Symbol, SymbolTable,
    ThreadHandle,
};
use wholesym::samply_symbols::debug_id_and_code_id_for_jitdump;

use super::{eventpipe_event_to_coreclr_event, CoreClrEvent, ModuleLoadUnloadEvent};

pub struct DotnetTraceManager {
    pending_trace_paths: Vec<PathBuf>,
    processors: Vec<SingleDotnetTraceProcessor>,
    unlink_after_open: bool,
}

impl DotnetTraceManager {
    pub fn new(unlink_after_open: bool) -> Self {
        DotnetTraceManager {
            pending_trace_paths: Vec::new(),
            processors: Vec::new(),
            unlink_after_open,
        }
    }

    pub fn add_dotnet_trace_path(
        &mut self,
        thread: ThreadHandle,
        path: impl Into<PathBuf>,
        fallback_dir: Option<PathBuf>,
    ) {
        let path: PathBuf = path.into();
        eprintln!("Adding dotnet trace path: {:?}", path);
        self.pending_trace_paths.push(path);
    }

    pub fn process_pending_records(
        &mut self,
        jit_category_manager: &mut JitCategoryManager,
        profile: &mut Profile,
        mut recycler: Option<&mut JitFunctionRecycler>,
        timestamp_converter: &TimestampConverter,
    ) {
        self.pending_trace_paths.retain_mut(|path| {
            fn trace_reader_for_path(
                path: &Path,
                unlink_after_open: bool,
            ) -> Option<(EventPipeParser<std::fs::File>, PathBuf)> {
                let mut file = std::fs::File::open(path).ok()?;
                let mut reader = EventPipeParser::new(file).ok()?;
                if unlink_after_open {
                    std::fs::remove_file(&path).ok()?;
                }
                Some((reader, path.into()))
            }
            let Some((reader, actual_path)) = trace_reader_for_path(path, self.unlink_after_open)
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
                path,
                debug_id,
                code_id: Some(code_id.to_string()),
                arch: None,
                symbol_table: None,
            });

            self.processors
                .push(SingleDotnetTraceProcessor::new(reader, lib_handle));
            false // "Do not retain", i.e. remove from pending_jitdump_paths
        });

        for jitdump in &mut self.processors {
            jitdump.process_pending_records(
                jit_category_manager,
                profile,
                recycler.as_deref_mut(),
                timestamp_converter,
            );
        }
    }

    pub fn finish(
        mut self,
        jit_category_manager: &mut JitCategoryManager,
        profile: &mut Profile,
        recycler: Option<&mut JitFunctionRecycler>,
        timestamp_converter: &TimestampConverter,
    ) -> Vec<LibMappingOpQueue> {
        self.process_pending_records(jit_category_manager, profile, recycler, timestamp_converter);
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

    modules: HashMap<u64, ModuleLoadUnloadEvent>,

    /// The relative_address of the next JIT function.
    ///
    /// We define the relative address space for Jitdump files as follows:
    /// Pretend that all JIT code is located in sequence, without gaps, in
    /// the order of JIT_CODE_LOAD entries in the file. A given JIT function's
    /// relative address is the sum of the `code_size`s of all the `JIT_CODE_LOAD`
    /// entries that came before it in the file.
    cumulative_address: u32,
}

impl SingleDotnetTraceProcessor {
    pub fn new(reader: EventPipeParser<std::fs::File>, lib_handle: LibraryHandle) -> Self {
        Self {
            reader: Some(reader),
            lib_handle,
            lib_mapping_ops: Default::default(),
            symbols: Default::default(),
            modules: Default::default(),
            cumulative_address: 0,
        }
    }

    pub fn process_pending_records(
        &mut self,
        jit_category_manager: &mut JitCategoryManager,
        profile: &mut Profile,
        mut recycler: Option<&mut JitFunctionRecycler>,
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
                    if let Some(coreclr_event) = eventpipe_event_to_coreclr_event(0, &ne) {
                        self.process_coreclr_event(
                            &coreclr_event,
                            jit_category_manager,
                            profile,
                            &mut recycler,
                            timestamp_converter,
                        );
                    } else {
                        /*
                        match ne.event_id {
                            144 | 145 | 146 | 150 | 151 | 152 | 153 | 154 | 155 | 160 | 187 => { }
                            _ => {
                                eprintln!("Unknown event: {} / {}", ne.provider_name, ne.event_id);
                            }
                        }
                        */
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
                    eprintln!("Got error: {:?}", err);
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
        coreclr_event: &CoreClrEvent,
        jit_category_manager: &mut JitCategoryManager,
        profile: &mut Profile,
        recycler: &mut Option<&mut JitFunctionRecycler>,
        timestamp_converter: &TimestampConverter,
    ) {
        match coreclr_event {
            CoreClrEvent::ModuleLoad(event) => {
                let module_id = event.module_id;
                self.modules.insert(module_id, event.clone());
            }
            CoreClrEvent::ModuleUnload(event) => {
                let module_id = event.module_id;
                //if let Some(module) = self.modules.remove(&module_id) {
                //}
            }
            CoreClrEvent::MethodLoad(event) => {
                let start_avma = event.start_address;
                let end_avma = event.start_address + event.size as u64;

                let relative_address_at_start = self.cumulative_address;
                self.cumulative_address += event.size;

                let symbol_name = event.name.to_string();
                self.symbols.push(Symbol {
                    address: relative_address_at_start,
                    size: if event.size == 0 {
                        None
                    } else {
                        Some(event.size)
                    },
                    name: symbol_name.clone(),
                });

                let (lib_handle, relative_address_at_start) =
                    if let Some(recycler) = recycler.as_deref_mut() {
                        recycler.recycle(
                            start_avma,
                            end_avma,
                            relative_address_at_start,
                            &symbol_name,
                            self.lib_handle,
                        )
                    } else {
                        (self.lib_handle, relative_address_at_start)
                    };

                log::trace!(
                    "MethodLoad: addr = 0x{:x} symbol_name = {:?} size = {}",
                    start_avma, symbol_name, event.size
                );

                let (category, js_frame) =
                    jit_category_manager.classify_jit_symbol(&symbol_name, profile);
                let start_ts = if event.dc_end {
                    if let Some(module) = self.modules.get(&event.module_id) {
                        module.common.timestamp
                    } else {
                        log::trace!("Module already unloaded {}, using event timestamp...", event.module_id);
                        event.common.timestamp
                    }
                } else {
                    event.common.timestamp
                };

                self.lib_mapping_ops.push(
                    start_ts,
                    LibMappingOp::Add(LibMappingAdd {
                        start_avma,
                        end_avma,
                        relative_address_at_start,
                        info: LibMappingInfo::new_jit_function(lib_handle, category, js_frame),
                    }),
                );
            }
            CoreClrEvent::ReadyToRunMethodEntryPoint(event) => {
                let address = event.start_address;
                let name = format!("{}.{}", event.name.namespace, event.name.name);

                // Can't actually do anything with this, as we don't have a size. These methods just
                // won't be seen in the profile when we're using tracing only (like when attaching).
            }
            CoreClrEvent::GcAllocationTick(event) => {}
            CoreClrEvent::MethodUnload(_) => {}
            CoreClrEvent::GcTriggered(event) => {}
            CoreClrEvent::GcSampledObjectAllocation(event) => {}
            CoreClrEvent::GcStart(event) => {}
            CoreClrEvent::GcEnd(event) => {}
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
        self.lib_mapping_ops.sort();
        self.lib_mapping_ops
    }
}

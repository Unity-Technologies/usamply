use super::CoreClrProviderProps;

#[allow(unused)]
mod constants {
    pub const CORECLR_GC_KEYWORD: u64 = 0x1; // https://learn.microsoft.com/en-us/dotnet/fundamentals/diagnostics/runtime-garbage-collection-events
    pub const CORECLR_GC_HANDLE_KEYWORD: u64 = 0x2;
    pub const CORECLR_BINDER_KEYWORD: u64 = 0x4; // https://learn.microsoft.com/en-us/dotnet/fundamentals/diagnostics/runtime-loader-binder-events
    pub const CORECLR_LOADER_KEYWORD: u64 = 0x8; // https://learn.microsoft.com/en-us/dotnet/fundamentals/diagnostics/runtime-loader-binder-events
    pub const CORECLR_JIT_KEYWORD: u64 = 0x10; // https://learn.microsoft.com/en-us/dotnet/fundamentals/diagnostics/runtime-method-events
    pub const CORECLR_NGEN_KEYWORD: u64 = 0x20; // https://learn.microsoft.com/en-us/dotnet/fundamentals/diagnostics/runtime-method-events
    pub const CORECLR_RUNDOWN_START_KEYWORD: u64 = 0x00000040;
    pub const CORECLR_INTEROP_KEYWORD: u64 = 0x2000; // https://learn.microsoft.com/en-us/dotnet/fundamentals/diagnostics/runtime-interop-events
    pub const CORECLR_CONTENTION_KEYWORD: u64 = 0x4000;
    pub const CORECLR_EXCEPTION_KEYWORD: u64 = 0x8000; // https://learn.microsoft.com/en-us/dotnet/fundamentals/diagnostics/runtime-exception-events
    pub const CORECLR_THREADING_KEYWORD: u64 = 0x10000; // https://learn.microsoft.com/en-us/dotnet/fundamentals/diagnostics/runtime-thread-events
    pub const CORECLR_JIT_TO_NATIVE_METHOD_MAP_KEYWORD: u64 = 0x20000;
    pub const CORECLR_GC_SAMPLED_OBJECT_ALLOCATION_HIGH_KEYWORD: u64 = 0x200000; // https://medium.com/criteo-engineering/build-your-own-net-memory-profiler-in-c-allocations-1-2-9c9f0c86cefd
    pub const CORECLR_GC_HEAP_AND_TYPE_NAMES: u64 = 0x1000000;
    pub const CORECLR_GC_SAMPLED_OBJECT_ALLOCATION_LOW_KEYWORD: u64 = 0x2000000;
    pub const CORECLR_STACK_KEYWORD: u64 = 0x40000000; // https://learn.microsoft.com/en-us/dotnet/framework/performance/stack-etw-event (note: says .NET Framework, but applies to CoreCLR also)
    pub const CORECLR_COMPILATION_KEYWORD: u64 = 0x1000000000;
    pub const CORECLR_COMPILATION_DIAGNOSTIC_KEYWORD: u64 = 0x2000000000;
    pub const CORECLR_TYPE_DIAGNOSTIC_KEYWORD: u64 = 0x8000000000;
}

/// Given a set of CoreClrProviderProps, return the list of appropriate
/// provider strings for xperf or dotnet-trace.
pub fn coreclr_provider_args(props: CoreClrProviderProps) -> Vec<String> {
    let mut providers = vec![];

    // Enabling all the DotNETRuntime keywords is very expensive. In particular,
    // enabling the NGenKeyword causes info to be generated for every NGen'd method; we should
    // instead use the native PDB info from ModuleLoad events to get this information.
    //
    // Also enabling the rundown keyword causes a bunch of DCStart/DCEnd events to be generated,
    // which is only useful if we're tracing an already running process.
    // if STACK is enabled, then every CoreCLR event will also generate a stack event right afterwards
    use constants::*;
    let mut info_keywords = CORECLR_LOADER_KEYWORD;
    info_keywords |=
        CORECLR_COMPILATION_DIAGNOSTIC_KEYWORD | CORECLR_JIT_TO_NATIVE_METHOD_MAP_KEYWORD;
    if props.event_stacks {
        info_keywords |= CORECLR_STACK_KEYWORD;
    }
    if props.gc_markers || props.gc_suspensions || props.gc_detailed_allocs {
        info_keywords |= CORECLR_GC_KEYWORD;
    }

    let mut verbose_keywords = CORECLR_JIT_KEYWORD | CORECLR_NGEN_KEYWORD;

    // if we're attaching, ask for a rundown of method info at the start of collection
    let rundown_verbose_keywords = if props.is_attach {
        CORECLR_LOADER_KEYWORD | CORECLR_JIT_KEYWORD | CORECLR_NGEN_KEYWORD | CORECLR_RUNDOWN_START_KEYWORD
    } else {
        CORECLR_JIT_KEYWORD | CORECLR_NGEN_KEYWORD
    };

    if props.gc_detailed_allocs {
        info_keywords |= CORECLR_GC_SAMPLED_OBJECT_ALLOCATION_HIGH_KEYWORD
            | CORECLR_GC_SAMPLED_OBJECT_ALLOCATION_LOW_KEYWORD;
    }

    verbose_keywords = verbose_keywords | info_keywords;
    info_keywords = 0;

    if info_keywords != 0 {
        providers.push(format!(
            "Microsoft-Windows-DotNETRuntime:0x{:x}:4",
            info_keywords
        ));
    }

    if verbose_keywords != 0 {
        // For some reason, we don't get JIT MethodLoad (non-Verbose) in Info level,
        // even though we should. This is OK though, because non-Verbose MethodLoad doesn't
        // include the method string names (we would have to pull it out based on MethodID,
        // and I'm not sure which events include the mapping -- MethodJittingStarted is also
        // verbose).
        providers.push(format!(
            "Microsoft-Windows-DotNETRuntime:0x{:x}:5",
            verbose_keywords
        ));
    }

    if rundown_verbose_keywords != 0 {
        providers.push(format!(
            "Microsoft-Windows-DotNETRuntimeRundown:0x{:x}:5",
            rundown_verbose_keywords
        ));
    }

    //providers.push(format!("Microsoft-Windows-DotNETRuntime"));

    providers
}

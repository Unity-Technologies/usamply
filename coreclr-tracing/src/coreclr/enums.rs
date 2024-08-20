use bitflags::bitflags;

use std::fmt::Display;

use binrw::BinRead;
use num_derive::FromPrimitive;

#[derive(BinRead, Debug, FromPrimitive, Clone, Copy)]
#[br(repr = u32)]
pub enum GcReason {
    AllocSmall = 0,
    Induced = 1,
    LowMemory = 2,
    Empty = 3,
    AllocLargeObjectHeap = 4,
    OutOfSpaceSmallObjectHeap = 5,
    OutOfSpaceLargeObjectHeap = 6,
    InducedNotForced = 7,
    Stress = 8,
    InducedLowMemory = 9,
}

impl Display for GcReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GcReason::AllocSmall => f.write_str("Small object heap allocation"),
            GcReason::Induced => f.write_str("Induced"),
            GcReason::LowMemory => f.write_str("Low memory"),
            GcReason::Empty => f.write_str("Empty"),
            GcReason::AllocLargeObjectHeap => f.write_str("Large object heap allocation"),
            GcReason::OutOfSpaceSmallObjectHeap => {
                f.write_str("Out of space (for small object heap)")
            }
            GcReason::OutOfSpaceLargeObjectHeap => {
                f.write_str("Out of space (for large object heap)")
            }
            GcReason::InducedNotForced => f.write_str("Induced but not forced as blocking"),
            GcReason::Stress => f.write_str("Stress"),
            GcReason::InducedLowMemory => f.write_str("Induced low memory"),
        }
    }
}

#[derive(BinRead, Debug, FromPrimitive, Clone, Copy)]
#[br(repr = u32)]
pub enum GcAllocationKind {
    Small = 0,
    Large = 1,
    Pinned = 2,
}

impl Display for GcAllocationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GcAllocationKind::Small => f.write_str("Small"),
            GcAllocationKind::Large => f.write_str("Large"),
            GcAllocationKind::Pinned => f.write_str("Pinned"),
        }
    }
}

#[derive(BinRead, Debug, FromPrimitive, Clone, Copy)]
#[br(repr = u32)]
pub enum GcType {
    Blocking = 0,
    Background = 1,
    BlockingDuringBackground = 2,
}

impl Display for GcType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GcType::Blocking => f.write_str("Blocking GC"),
            GcType::Background => f.write_str("Background GC"),
            GcType::BlockingDuringBackground => f.write_str("Blocking GC during background GC"),
        }
    }
}

#[derive(BinRead, Debug, FromPrimitive, Clone, Copy)]
#[br(repr = u32)]
pub enum GcSuspendEeReason {
    Other = 0,
    GC = 1,
    AppDomainShutdown = 2,
    CodePitching = 3,
    Shutdown = 4,
    Debugger = 5,
    GcPrep = 6,
    DebuggerSweep = 7,
}

impl Display for GcSuspendEeReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GcSuspendEeReason::Other => f.write_str("Other"),
            GcSuspendEeReason::GC => f.write_str("GC"),
            GcSuspendEeReason::AppDomainShutdown => f.write_str("AppDomain shutdown"),
            GcSuspendEeReason::CodePitching => f.write_str("Code pitching"),
            GcSuspendEeReason::Shutdown => f.write_str("Shutdown"),
            GcSuspendEeReason::Debugger => f.write_str("Debugger"),
            GcSuspendEeReason::GcPrep => f.write_str("GC prep"),
            GcSuspendEeReason::DebuggerSweep => f.write_str("Debugger sweep"),
        }
    }
}

bitflags! {
    #[derive(PartialEq, Eq)]
    pub struct CoreClrMethodFlags: u32 {
        const dynamic = 0x1;
        const generic = 0x2;
        const has_shared_generic_code = 0x4;
        const jitted = 0x8;
        const jit_helper = 0x10;
        const profiler_rejected_precompiled_code = 0x20;
        const ready_to_run_rejected_precompiled_code = 0x40;

        // next three bits are the tiered compilation level
        const opttier_bit0 = 0x80;
        const opttier_bit1 = 0x100;
        const opttier_bit2 = 0x200;

        // extent flags/value (hot/cold)
        const extent_bit_0 = 0x10000000; // 0x1 == cold, 0x0 = hot
        const extent_bit_1 = 0x20000000; // always 0 for now looks like
        const extent_bit_2 = 0x40000000;
        const extent_bit_3 = 0x80000000;

        const _ = !0;
    }

    #[derive(PartialEq, Eq)]
    pub struct TieredCompilationSettings: u32 {
        const none = 0x0;
        const quick_jit = 0x1;
        const quick_jit_for_loops = 0x2;
        const tiered_pgo = 0x4;
        const ready_to_run = 0x8;
    }
}

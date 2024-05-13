use crate::shared::recording_props::{RecordingMode, RecordingProps};

pub fn gfx_xperf_args(props: &RecordingProps, recording_mode: &RecordingMode) -> Vec<String> {
    let mut providers = vec![];

    if !props.gfx {
        return providers;
    }

    let _is_attach = match recording_mode {
        RecordingMode::All => true,
        RecordingMode::Pid(_) => true,
        RecordingMode::Launch(_) => false,
    };

    const DXGKRNL_BASE_KEYWORD: u64 = 0x1;

    // er I don't know what level 1 is.
    let level_1_dxgkrnl_keywords = DXGKRNL_BASE_KEYWORD;

    if level_1_dxgkrnl_keywords != 0 {
        providers.push(format!(
            "Microsoft-Windows-DxgKrnl:0x{:x}:1",
            level_1_dxgkrnl_keywords
        ));
    }

    providers
}

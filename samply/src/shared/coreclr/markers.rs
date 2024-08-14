use fxprof_processed_profile::{
    MarkerFieldFormat, MarkerFieldSchema, MarkerLocation, MarkerSchema, MarkerStaticField, StaticSchemaMarker,
    StringHandle, CategoryHandle, Profile
};

// String is type name
#[derive(Debug, Clone)]
pub struct CoreClrGcAllocTickMarker(pub StringHandle, pub usize, pub usize, pub CategoryHandle);

impl StaticSchemaMarker for CoreClrGcAllocTickMarker {
    const UNIQUE_MARKER_TYPE_NAME: &'static str = "GC Alloc Tick";

    fn schema() -> MarkerSchema {
        MarkerSchema {
            type_name: Self::UNIQUE_MARKER_TYPE_NAME.into(),
            locations: vec![
                MarkerLocation::MarkerChart,
                MarkerLocation::MarkerTable,
                MarkerLocation::TimelineMemory,
            ],
            chart_label: Some("GC Alloc".into()),
            tooltip_label: Some("GC Alloc: {marker.data.clrtype} ({marker.data.size} bytes)".into()),
            table_label: Some("GC Alloc".into()),
            fields: vec![
                MarkerFieldSchema {
                    key: "clrtype".into(),
                    label: "CLR Type".into(),
                    format: MarkerFieldFormat::String,
                    searchable: true,
                },
                MarkerFieldSchema {
                    key: "size".into(),
                    label: "Total size of all objects".into(),
                    format: MarkerFieldFormat::Bytes,
                    searchable: false,
                },
                MarkerFieldSchema {
                    key: "objcount".into(),
                    label: "Number of objects allocated".into(),
                    format: MarkerFieldFormat::Integer,
                    searchable: false,
                },
            ],
            static_fields: vec![MarkerStaticField {
                    label: "Description".into(),
                    value: "CoreCLR GC Allocation Tick".into(),
                },
            ],
        }
    }

    fn name(&self, profile: &mut Profile) -> StringHandle {
        profile.intern_string(Self::UNIQUE_MARKER_TYPE_NAME)
    }

    fn category(&self, _profile: &mut Profile) -> CategoryHandle {
        self.3
    }

    fn string_field_value(&self, _field_index: u32) -> StringHandle {
        self.0
    }

    fn number_field_value(&self, field_index: u32) -> f64 {
        if field_index == 1 {
            self.1 as f64
        } else if field_index == 2 {
            self.2 as f64
        } else {
            panic!("Unexpected field_index");
        }
    }
}

#[derive(Debug, Clone)]
pub struct CoreClrGcAllocMarker(pub StringHandle, pub usize, pub CategoryHandle);

impl StaticSchemaMarker for CoreClrGcAllocMarker {
    const UNIQUE_MARKER_TYPE_NAME: &'static str = "GC Alloc";

    fn schema() -> MarkerSchema {
        MarkerSchema {
            type_name: Self::UNIQUE_MARKER_TYPE_NAME.into(),
            locations: vec![
                MarkerLocation::MarkerChart,
                MarkerLocation::MarkerTable,
                MarkerLocation::TimelineMemory,
            ],
            chart_label: Some("GC Alloc".into()),
            tooltip_label: Some(
                "GC Alloc: {marker.data.clrtype} ({marker.data.size} bytes)".into(),
            ),
            table_label: Some("GC Alloc".into()),
            fields: vec![
                MarkerFieldSchema {
                    key: "clrtype".into(),
                    label: "CLR Type".into(),
                    format: MarkerFieldFormat::String,
                    searchable: true,
                },
                MarkerFieldSchema {
                    key: "size".into(),
                    label: "Size".into(),
                    format: MarkerFieldFormat::Bytes,
                    searchable: false,
                },
            ],
            static_fields: vec![MarkerStaticField {
                label: "Description".into(),
                value: "GC Allocation".into(),
            }],
        }
    }

    fn name(&self, profile: &mut Profile) -> StringHandle {
        profile.intern_string("GC Alloc")
    }

    fn category(&self, _profile: &mut Profile) -> CategoryHandle {
        self.2
    }

    fn string_field_value(&self, _field_index: u32) -> StringHandle {
        self.0
    }

    fn number_field_value(&self, _field_index: u32) -> f64 {
        self.1 as f64
    }
}

#[derive(Debug, Clone)]
pub struct CoreClrGcEventMarker(pub StringHandle, pub StringHandle, pub CategoryHandle);

impl StaticSchemaMarker for CoreClrGcEventMarker {
    const UNIQUE_MARKER_TYPE_NAME: &'static str = "GC Event";

    fn schema() -> MarkerSchema {
        MarkerSchema {
            type_name: Self::UNIQUE_MARKER_TYPE_NAME.into(),
            locations: vec![
                MarkerLocation::MarkerChart,
                MarkerLocation::MarkerTable,
                MarkerLocation::TimelineMemory,
            ],
            chart_label: Some("{marker.data.event}".into()),
            tooltip_label: Some("{marker.data.event}".into()),
            table_label: Some("{marker.data.event}".into()),
            fields: vec![MarkerFieldSchema {
                key: "event".into(),
                label: "Event".into(),
                format: MarkerFieldFormat::String,
                searchable: true,
            }],
            static_fields: vec![MarkerStaticField {
                label: "Description".into(),
                value: "CoreCLR GC Event".into(),
            }],
        }
    }

    fn name(&self, _profile: &mut Profile) -> StringHandle {
        self.0
    }

    fn category(&self, _profile: &mut Profile) -> CategoryHandle {
        self.2
    }

    fn string_field_value(&self, _field_index: u32) -> StringHandle {
        self.1
    }

    fn number_field_value(&self, _field_index: u32) -> f64 {
        unreachable!()
    }
}

#[derive(Debug, Clone)]
pub struct CoreClrGcMarker(pub CategoryHandle);

impl StaticSchemaMarker for CoreClrGcMarker {
    const UNIQUE_MARKER_TYPE_NAME: &'static str = "GC";

    fn schema() -> MarkerSchema {
        MarkerSchema {
            type_name: Self::UNIQUE_MARKER_TYPE_NAME.into(),
            locations: vec![
                MarkerLocation::MarkerChart,
                MarkerLocation::MarkerTable,
                MarkerLocation::TimelineMemory,
            ],
            chart_label: Some("GC".into()),
            tooltip_label: Some("GC".into()),
            table_label: Some("GC".into()),
            fields: vec![],
            static_fields: vec![MarkerStaticField {
                label: "Description".into(),
                value: "CoreCLR GC".into(),
            }],
        }
    }

    fn name(&self, profile: &mut Profile) -> StringHandle {
        profile.intern_string(Self::UNIQUE_MARKER_TYPE_NAME)
    }

    fn category(&self, _profile: &mut Profile) -> CategoryHandle {
        self.0
    }

    fn string_field_value(&self, _field_index: u32) -> StringHandle {
        unreachable!()
    }

    fn number_field_value(&self, _field_index: u32) -> f64 {
        unreachable!()
    }
}

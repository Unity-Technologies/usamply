use fxprof_processed_profile::{
    MarkerDynamicField, MarkerFieldFormat, MarkerLocation, MarkerSchema, MarkerSchemaField,
    MarkerStaticField, ProfilerMarker,
};
use serde_json::json;

// String is type name
#[derive(Debug, Clone)]
pub struct CoreClrGcAllocTickMarker(pub String, pub usize, pub usize);

impl ProfilerMarker for CoreClrGcAllocTickMarker {
    const MARKER_TYPE_NAME: &'static str = "GC Alloc Tick";

    fn json_marker_data(&self) -> serde_json::Value {
        json!({
            "type": Self::MARKER_TYPE_NAME,
            "clrtype": self.0,
            "totalsize": self.1,
            "objcount": self.2,
        })
    }

    fn schema() -> MarkerSchema {
        MarkerSchema {
            type_name: Self::MARKER_TYPE_NAME,
            locations: vec![
                MarkerLocation::MarkerChart,
                MarkerLocation::MarkerTable,
                MarkerLocation::TimelineMemory,
            ],
            chart_label: Some("GC Alloc"),
            tooltip_label: Some("GC Alloc: {marker.data.clrtype} ({marker.data.size})"),
            table_label: Some("GC Alloc"),
            fields: vec![
                MarkerSchemaField::Dynamic(MarkerDynamicField {
                    key: "clrtype",
                    label: "CLR Type",
                    format: MarkerFieldFormat::String,
                    searchable: true,
                }),
                MarkerSchemaField::Dynamic(MarkerDynamicField {
                    key: "size",
                    label: "Total size of all objects",
                    format: MarkerFieldFormat::Bytes,
                    searchable: false,
                }),
                MarkerSchemaField::Dynamic(MarkerDynamicField {
                    key: "objcount",
                    label: "Number of objects allocated",
                    format: MarkerFieldFormat::Integer,
                    searchable: false,
                }),
                MarkerSchemaField::Static(MarkerStaticField {
                    label: "Description",
                    value: "CoreCLR GC Allocation Tick",
                }),
            ],
        }
    }
}

#[derive(Debug, Clone)]
pub struct CoreClrGcAllocMarker(pub String, pub usize);

impl ProfilerMarker for CoreClrGcAllocMarker {
    const MARKER_TYPE_NAME: &'static str = "GC Alloc";

    fn json_marker_data(&self) -> serde_json::Value {
        json!({
            "type": Self::MARKER_TYPE_NAME,
            "clrtype": self.0,
            "size": self.1,
        })
    }

    fn schema() -> MarkerSchema {
        MarkerSchema {
            type_name: Self::MARKER_TYPE_NAME,
            locations: vec![
                MarkerLocation::MarkerChart,
                MarkerLocation::MarkerTable,
                MarkerLocation::TimelineMemory,
            ],
            chart_label: Some("GC Alloc"),
            tooltip_label: Some("GC Alloc: {marker.data.clrtype} ({marker.data.size})"),
            table_label: Some("GC Alloc"),
            fields: vec![
                MarkerSchemaField::Dynamic(MarkerDynamicField {
                    key: "clrtype",
                    label: "CLR Type",
                    format: MarkerFieldFormat::String,
                    searchable: true,
                }),
                MarkerSchemaField::Dynamic(MarkerDynamicField {
                    key: "size",
                    label: "Size",
                    format: MarkerFieldFormat::Bytes,
                    searchable: false,
                }),
                MarkerSchemaField::Static(MarkerStaticField {
                    label: "Description",
                    value: "CoreCLR GC Allocation",
                }),
            ],
        }
    }
}

#[derive(Debug, Clone)]
pub struct CoreClrGcMarker();

impl ProfilerMarker for CoreClrGcMarker {
    const MARKER_TYPE_NAME: &'static str = "GC";

    fn json_marker_data(&self) -> serde_json::Value {
        json!({
            "type": Self::MARKER_TYPE_NAME,
        })
    }

    fn schema() -> MarkerSchema {
        MarkerSchema {
            type_name: Self::MARKER_TYPE_NAME,
            locations: vec![
                MarkerLocation::MarkerChart,
                MarkerLocation::MarkerTable,
                MarkerLocation::TimelineMemory,
            ],
            chart_label: Some("GC"),
            tooltip_label: Some("GC"),
            table_label: Some("GC"),
            fields: vec![MarkerSchemaField::Static(MarkerStaticField {
                label: "Description",
                value: "CoreCLR GC",
            })],
        }
    }
}

#[derive(Debug, Clone)]
pub struct CoreClrGcEventMarker(pub String);

impl ProfilerMarker for CoreClrGcEventMarker {
    const MARKER_TYPE_NAME: &'static str = "GC Event";

    fn json_marker_data(&self) -> serde_json::Value {
        json!({
            "type": Self::MARKER_TYPE_NAME,
            "event": self.0,
        })
    }

    fn schema() -> MarkerSchema {
        MarkerSchema {
            type_name: Self::MARKER_TYPE_NAME,
            locations: vec![
                MarkerLocation::MarkerChart,
                MarkerLocation::MarkerTable,
                MarkerLocation::TimelineMemory,
            ],
            chart_label: Some("{marker.data.event}"),
            tooltip_label: Some("{marker.data.event}"),
            table_label: Some("{marker.data.event}"),
            fields: vec![
                MarkerSchemaField::Dynamic(MarkerDynamicField {
                    key: "event",
                    label: "Event",
                    format: MarkerFieldFormat::String,
                    searchable: true,
                }),
                MarkerSchemaField::Static(MarkerStaticField {
                    label: "Description",
                    value: "CoreCLR Generic GC Event",
                }),
            ],
        }
    }
}

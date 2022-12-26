use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};

use crate::category::{
    Category, CategoryHandle, CategoryPairHandle, SerializableSubcategoryColumn, Subcategory,
};
use crate::fast_hash_map::FastHashMap;
use crate::func_table::{FuncIndex, FuncTable};
use crate::global_lib_table::{GlobalLibIndex, GlobalLibTable};
use crate::resource_table::ResourceTable;
use crate::serialization_helpers::SerializableSingleValueColumn;
use crate::thread_string_table::{ThreadInternalStringIndex, ThreadStringTable};

#[derive(Debug, Clone, Default)]
pub struct FrameTable {
    addresses: Vec<Option<u32>>,
    categories: Vec<CategoryHandle>,
    subcategories: Vec<Subcategory>,
    funcs: Vec<FuncIndex>,
    internal_frame_to_frame_index: FastHashMap<InternalFrame, usize>,
}

impl FrameTable {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn index_for_frame(
        &mut self,
        string_table: &mut ThreadStringTable,
        resource_table: &mut ResourceTable,
        func_table: &mut FuncTable,
        global_libs: &GlobalLibTable,
        frame: InternalFrame,
    ) -> usize {
        let addresses = &mut self.addresses;
        let funcs = &mut self.funcs;
        let categories = &mut self.categories;
        let subcategories = &mut self.subcategories;
        *self
            .internal_frame_to_frame_index
            .entry(frame.clone())
            .or_insert_with(|| {
                let frame_index = addresses.len();
                let (address, location_string_index, resource) = match frame.location {
                    InternalFrameLocation::UnknownAddress(address) => {
                        let location_string = format!("0x{:x}", address);
                        let s = string_table.index_for_string(&location_string);
                        (None, s, None)
                    }
                    InternalFrameLocation::AddressInLib(address, lib_index) => {
                        let location_string = format!("0x{:x}", address);
                        let s = string_table.index_for_string(&location_string);
                        let res =
                            resource_table.resource_for_lib(lib_index, global_libs, string_table);
                        (Some(address), s, Some(res))
                    }
                    InternalFrameLocation::Label(string_index) => (None, string_index, None),
                };
                let func_index = func_table.index_for_func(location_string_index, resource);
                let CategoryPairHandle(category, subcategory_index) = frame.category_pair;
                let subcategory = match subcategory_index {
                    Some(index) => Subcategory::Normal(index),
                    None => Subcategory::Other(category),
                };
                addresses.push(address);
                categories.push(category);
                subcategories.push(subcategory);
                funcs.push(func_index);
                frame_index
            })
    }

    pub fn as_serializable<'a>(&'a self, categories: &'a [Category]) -> impl Serialize + 'a {
        SerializableFrameTable {
            table: self,
            categories,
        }
    }
}

struct SerializableFrameTable<'a> {
    table: &'a FrameTable,
    categories: &'a [Category],
}

impl<'a> Serialize for SerializableFrameTable<'a> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let len = self.table.addresses.len();
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("length", &len)?;
        map.serialize_entry(
            "address",
            &SerializableFrameTableAddressColumn(&self.table.addresses),
        )?;
        map.serialize_entry("inlineDepth", &SerializableSingleValueColumn(0u32, len))?;
        map.serialize_entry("category", &self.table.categories)?;
        map.serialize_entry(
            "subcategory",
            &SerializableSubcategoryColumn(&self.table.subcategories, self.categories),
        )?;
        map.serialize_entry("func", &self.table.funcs)?;
        map.serialize_entry("nativeSymbol", &SerializableSingleValueColumn((), len))?;
        map.serialize_entry("innerWindowID", &SerializableSingleValueColumn((), len))?;
        map.serialize_entry("implementation", &SerializableSingleValueColumn((), len))?;
        map.serialize_entry("line", &SerializableSingleValueColumn((), len))?;
        map.serialize_entry("column", &SerializableSingleValueColumn((), len))?;
        map.serialize_entry("optimizations", &SerializableSingleValueColumn((), len))?;
        map.end()
    }
}

struct SerializableFrameTableAddressColumn<'a>(&'a [Option<u32>]);

impl<'a> Serialize for SerializableFrameTableAddressColumn<'a> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for address in self.0 {
            match address {
                Some(address) => seq.serialize_element(&address)?,
                None => seq.serialize_element(&-1)?,
            }
        }
        seq.end()
    }
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct InternalFrame {
    pub location: InternalFrameLocation,
    pub category_pair: CategoryPairHandle,
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub enum InternalFrameLocation {
    UnknownAddress(u64),
    AddressInLib(u32, GlobalLibIndex),
    Label(ThreadInternalStringIndex),
}
//! Tests that IdInformation works on files where the IPI is missing (empty stream).

use pdb2 as pdb;

use pdb::{FallibleIterator, IdIndex, PDB};

fn open_file() -> std::fs::File {
    let path = "fixtures/symbol_server/0ea7c70545374958ad3307514bdfc8642-wntdll.pdb";
    std::fs::File::open(path).expect("missing fixtures, please run scripts/download from the root")
}

#[test]
fn test_missing_ipi() {
    let mut pdb = PDB::open(open_file()).expect("opening pdb");

    let id_information = pdb.id_information().expect("get id information");

    // Check ItemInformation API
    assert_eq!(id_information.len(), 0);
    assert!(id_information.is_empty());

    // Check ItemIter API
    let mut iter = id_information.iter();
    assert!(iter.next().expect("iter empty IPI").is_none());

    // Check ItemFinder API
    let finder = id_information.finder();
    assert_eq!(finder.max_index(), IdIndex(0));
    finder.find(IdIndex(0)).expect_err("find index");
    finder.find(IdIndex(4097)).expect_err("find index");
}

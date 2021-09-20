#[macro_use]
pub mod util;

pub mod key;

pub mod pfs0;

pub mod nca;

use std::{fs::File, io::Write};
use crate::util::new_shared;

#[test]
fn pfs0_test() {
    println!("PFS0 test...");

    let pfs0_reader = new_shared(File::open("test.nsp").unwrap());
    let mut pfs0 = pfs0::PFS0::new(pfs0_reader).unwrap();

    let files = pfs0.list_files().unwrap();
    println!("Files: {:?}", pfs0.list_files().unwrap());

    let mut idx: usize = 0;
    for file in files.iter() {
        println!("Saving '{}'...", file);

        let size = pfs0.get_file_size(idx);
        let mut file_buf = vec![0u8; size];
        pfs0.read_file(idx, 0, &mut file_buf).unwrap();

        let mut out_file = File::create(file).unwrap();
        out_file.write_all(&mut file_buf).unwrap();

        println!("Saved!");

        idx += 1;
    }
}

#[test]
fn nca_test() {
    println!("NCA test...");

    let keyset = key::Keyset::from(File::open("prod.keys").unwrap()).unwrap();

    let nca_reader = new_shared(File::open("test.nca").unwrap());
    let mut nca = nca::NCA::new(nca_reader, keyset).unwrap();

    for fs in nca.filesystems.iter_mut() {
        if let Some(pfs0) = fs.pfs0.as_mut() {
            let files = pfs0.list_files().unwrap();

            for i in 0..files.len() {
                let file_name = &files[i];
                println!("Saving file '{}' from NCA PFS0 section...", file_name);
                let file_size = pfs0.get_file_size(i);
                let mut file_buf = vec![0u8; file_size];
                pfs0.read_file(i, 0, &mut file_buf).unwrap();

                let mut out_file = File::create(format!("pfs0-{}", file_name)).unwrap();
                out_file.write(&file_buf).unwrap();
                println!("Saved!");
            }
        }
    }
}
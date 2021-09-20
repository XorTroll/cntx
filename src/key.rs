use std::io::{BufReader, Result, BufRead};
use hex::FromHex;

use crate::util::ReadSeek;

#[derive(Clone, Debug)]
pub struct Keyset {
    pub header_key: [u8; 0x20],
    pub key_area_keys_application: Vec<[u8; 0x10]>,
    pub key_area_keys_ocean: Vec<[u8; 0x10]>,
    pub key_area_keys_system: Vec<[u8; 0x10]>
}

impl Keyset {
    fn get_key_name_idx(base_name: &str, name: &String) -> Option<usize> {
        if name.starts_with(base_name) && (name.len() == base_name.len() + 2) {
            let idx_str = &name[name.len() - 2..];
            u8::from_str_radix(idx_str, 16).ok().map(|s| s as usize)
        }
        else {
            None
        }
    }

    pub fn from<R: ReadSeek>(reader: R) -> Result<Self> {
        let lines = BufReader::new(reader).lines();

        let mut keyset = Keyset {
            header_key: [0; 0x20],
            key_area_keys_application: Vec::new(),
            key_area_keys_ocean: Vec::new(),
            key_area_keys_system: Vec::new()
        };

        for line in lines {
            if let Ok(line_str) = line {
                let items: Vec<_> = line_str.split("=").collect();
                assert!(items.len() == 2);

                let mut key = String::from(items[0]);
                key.retain(|c| !c.is_whitespace());
                let mut value = String::from(items[1]);
                value.retain(|c| !c.is_whitespace());

                let key_data = Vec::from_hex(value).expect("Invalid hex key");

                if key.eq("header_key") {
                    keyset.header_key = key_data.clone().try_into().unwrap();
                }
                else if let Some(idx) = Self::get_key_name_idx("key_area_key_application_", &key) {
                    if idx >= keyset.key_area_keys_application.len() {
                        keyset.key_area_keys_application.resize(idx, [0; 0x10]);
                    }

                    keyset.key_area_keys_application.insert(idx, key_data.clone().try_into().unwrap());
                }
                else if let Some(idx) = Self::get_key_name_idx("key_area_key_ocean_", &key) {
                    if idx >= keyset.key_area_keys_ocean.len() {
                        keyset.key_area_keys_ocean.resize(idx, [0; 0x10]);
                    }

                    keyset.key_area_keys_ocean.insert(idx, key_data.clone().try_into().unwrap());
                }
                else if let Some(idx) = Self::get_key_name_idx("key_area_key_system_", &key) {
                    if idx >= keyset.key_area_keys_system.len() {
                        keyset.key_area_keys_system.resize(idx, [0; 0x10]);
                    }

                    keyset.key_area_keys_system.insert(idx, key_data.clone().try_into().unwrap());
                }
            }
        }

        Ok(keyset)
    }
}
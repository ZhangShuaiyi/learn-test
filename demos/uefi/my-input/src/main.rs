#![no_main]
#![no_std]

use core::fmt::Write;

use log::info;
use uefi::prelude::*;
use uefi::proto::console::text::{Key, ScanCode};

#[entry]
fn main(_image_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    uefi_services::init(&mut system_table).unwrap();
    system_table.stdout().write_str("Hello world!\n").unwrap();
    let mut events = unsafe { [system_table.stdin().wait_for_key_event().unsafe_clone()] };
    loop {
        system_table
            .boot_services()
            .wait_for_event(&mut events)
            .unwrap();
        match system_table.stdin().read_key().unwrap() {
            Some(Key::Printable(key)) => {
                let c: char = key.into(); 
                system_table.stdout().write_char(c).unwrap();
                if '\r' == c {
                    system_table.stdout().write_char('\n').unwrap();
                }
            }
            Some(Key::Special(ScanCode::ESCAPE)) => {
                break;
            }
            _ => {}
        }
    }
    info!("end loop!");
    Status::SUCCESS
}

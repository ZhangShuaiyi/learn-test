#![no_main]
#![no_std]

use core::fmt::Write;

use log::info;
use uefi::prelude::*;

#[entry]
fn main(_image_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    uefi_services::init(&mut system_table).unwrap();
    info!("Hello First!");
    system_table.boot_services().stall(5_000_000);
    system_table.stdout().clear().unwrap();
    info!("Hello Second!");
    system_table.boot_services().stall(5_000_000);

    system_table.stdout().write_str("Hello Third!\n").unwrap();
    system_table.boot_services().stall(5_000_000);
    Status::SUCCESS
}

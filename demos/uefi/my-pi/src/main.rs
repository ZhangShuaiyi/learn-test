#![no_main]
#![no_std]

use log::info;

use uefi::proto::pi::mp::MpServices;
use uefi::table::boot::SearchType;
use uefi::{prelude::*, Identify};

#[entry]
fn main(_image_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    uefi_services::init(&mut system_table).unwrap();
    system_table.stdout().clear().unwrap();
    let boot_services = system_table.boot_services();

    let mp_handle = *boot_services
        .locate_handle_buffer(SearchType::ByProtocol(&MpServices::GUID))
        .unwrap()
        .first()
        .unwrap();
    let mp = boot_services
        .open_protocol_exclusive::<MpServices>(mp_handle)
        .unwrap();
    let count = mp.get_number_of_processors().unwrap();

    for i in 0..count.total {
        let info = mp.get_processor_info(i).unwrap();
        info!("cpu{}: is_bsp:{}", i, info.is_bsp());
        info!("cpu{}: location:{:?}", i, info.location);
    }

    // boot_services.stall(10_000_000);
    drop(mp);
    let mut events = unsafe { [system_table.stdin().wait_for_key_event().unsafe_clone()] };
    system_table
        .boot_services()
        .wait_for_event(&mut events)
        .unwrap();
    // system_table.stdin().read_key().unwrap();
    Status::SUCCESS
}

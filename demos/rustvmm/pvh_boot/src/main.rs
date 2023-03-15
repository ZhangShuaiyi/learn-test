use std::fs::File;

use linux_loader;
use linux_loader::loader::KernelLoader;
use linux_loader::loader::elf::PvhBootCapability::PvhEntryPresent;
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::{GuestAddress, Address};

type GuestMemoryMmap = vm_memory::GuestMemoryMmap<AtomicBitmap>;

const MEMORY_SIZE: usize = 512 << 20;

const HIMEM_START: u64 = 0x100000;

const KERNEL_PATH: &str = "/opt/kata/share/kata-containers/vmlinux-5.19.2-96";

fn main() {
    let guest_addr = GuestAddress(0x0);
    let guest_mem = GuestMemoryMmap::from_ranges(&[(guest_addr, MEMORY_SIZE)]).unwrap();

    let mut kernel_file = File::open(KERNEL_PATH).expect("open kernel file failed");

    let kernel_entry_addr: GuestAddress;
    let entry = linux_loader::loader::elf::Elf::load(&guest_mem, None, &mut kernel_file, Some(GuestAddress(HIMEM_START))).unwrap();
    println!("kernel_load: 0x{:x} kernel_end:0x{:x}",
        entry.kernel_load.raw_value(), entry.kernel_end as u64);
    if let PvhEntryPresent(pvh_entry_addr) = entry.pvh_boot_cap {
        // println!("kernel pvh entry addr: 0x{:x}", pvh_entry_addr.0);
        kernel_entry_addr = pvh_entry_addr;
    } else {
        println!("Kernel lacks PVH header");
        std::process::exit(1);
    }
    println!("kernel pvh entry addr: 0x{:x}", kernel_entry_addr.0);

    // std::thread::sleep(std::time::Duration::from_secs(200));
}

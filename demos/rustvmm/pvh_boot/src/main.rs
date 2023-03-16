use std::fs::File;
use std::sync::{Arc, Mutex};
use std::io::{Seek, SeekFrom};

use linux_loader;
use linux_loader::loader::KernelLoader;
use linux_loader::loader::elf::PvhBootCapability::PvhEntryPresent;
use linux_loader::loader::elf::start_info::{
    hvm_memmap_table_entry, hvm_modlist_entry, hvm_start_info,
};
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::{GuestAddress, Bytes, Address, GuestMemory};
use kvm_ioctls::{Kvm, VcpuExit};
use kvm_bindings::{kvm_pit_config, kvm_userspace_memory_region, kvm_segment, KVM_PIT_SPEAKER_DUMMY};
use vm_superio::{serial::SerialEvents, Serial, Trigger};
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::eventfd::EFD_NONBLOCK;
use vmm_sys_util::poll::{PollContext, PollEvents};
use vmm_sys_util::terminal::Terminal;

type GuestMemoryMmap = vm_memory::GuestMemoryMmap<AtomicBitmap>;

const MEMORY_SIZE: usize = 512 << 20;
const CMDLINE_MAX_SIZE: usize = 4096;

const KVM_TSS_ADDRESS: u64 = 0xfffb_d000;
const BOOT_GDT_START: GuestAddress = GuestAddress(0x500);
/// Address for the hvm_start_info struct used in PVH boot
const PVH_INFO_START: GuestAddress = GuestAddress(0x6000);
/// Starting address of array of modules of hvm_modlist_entry type.
/// Used to enable initrd support using the PVH boot ABI.
pub const MODLIST_START: GuestAddress = GuestAddress(0x6040);
/// Address of memory map table used in PVH boot. Can overlap
/// with the zero page address since they are mutually exclusive.
const MEMMAP_START: GuestAddress = GuestAddress(0x7000);

const HIMEM_START: u64 = 0x100000;
const CMDLINE_START: GuestAddress = GuestAddress(0x20000);

const XEN_HVM_START_MAGIC_VALUE: u32 = 0x336ec578;

const KERNEL_PATH: &str = "/opt/kata/share/kata-containers/vmlinux-5.19.2-96";
const INITRD_PATH: &str = "/root/datas/centos-no-kernel-initramfs.img";
// const DEFAULT_KERNEL_CMDLINE: &str = "console=ttyS0 noapic reboot=k panic=1 pci=off acpi=off";
const DEFAULT_KERNEL_CMDLINE: &str = "console=ttyS0 noapic reboot=k panic=1 pci=off acpi=off rdinit=/bin/bash";

fn main() {
    // create vm
    let kvm = Kvm::new().expect("open kvm device failed");
    let vm = kvm.create_vm().expect("create vm failed");

    vm.create_irq_chip().unwrap();
    let pit_config = kvm_pit_config {
        flags: KVM_PIT_SPEAKER_DUMMY,
        ..Default::default()
    };
    vm.create_pit2(pit_config).unwrap();

    let guest_addr = GuestAddress(0x0);
    let guest_mem = GuestMemoryMmap::from_ranges(&[(guest_addr, MEMORY_SIZE)]).unwrap();
    let host_addr = guest_mem.get_host_address(guest_addr).unwrap();
    println!("host_addr: 0x{:x}", host_addr as u64);
    let mem_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: 0,
        memory_size: MEMORY_SIZE as u64,
        userspace_addr: host_addr as u64,
        flags: 0,
    };
    unsafe {
        vm.set_user_memory_region(mem_region)
            .expect("set user memory region failed")
    };
    vm.set_tss_address(KVM_TSS_ADDRESS as usize)
        .expect("set tss failed");

    // create vcpu and set cpuid
    let vcpu = vm.create_vcpu(0).expect("create vcpu failed");
    let kvm_cpuid = kvm.get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES).unwrap();
    vcpu.set_cpuid2(&kvm_cpuid).unwrap();

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

    // load initrd
    let mut initramfs_file = File::open(INITRD_PATH).expect("open initrd file failed");
    let initramfs_size = match initramfs_file.seek(SeekFrom::End(0)) {
        Ok(size) => size.try_into().unwrap(),
        Err(e) => panic!("initramfs file seek to end failed: {:?}", e),
    };
    initramfs_file.seek(SeekFrom::Start(0)).unwrap();
    let first_region = guest_mem.find_region(GuestAddress::new(0)).unwrap();
    assert!(
        initramfs_size <= first_region.size(),
        "too big initrd"
    );
    let initrd_addr =
        GuestAddress((first_region.size() - initramfs_size) as u64 & !(4096 - 1));
    guest_mem
        .read_from(
            initrd_addr,
            &mut initramfs_file,
            initramfs_size,
        )
        .unwrap();
    println!("initramfs loaded address = 0x{:x} size = 0x{:x}", initrd_addr.raw_value(), initramfs_size);

    // set regs
    let mut regs = vcpu.get_regs().unwrap();
    regs.rip = kernel_entry_addr.raw_value();
    regs.rbx = PVH_INFO_START.raw_value();
    // regs.rsp = BOOT_STACK_POINTER;
    // regs.rbp = BOOT_STACK_POINTER;
    regs.rflags = 0x0000000000000002u64;
    vcpu.set_regs(&regs).unwrap();

    const CR0_PE: u64 = 0x1;
    // // set sregs
    // let mut sregs = vcpu.get_sregs().unwrap();
    // sregs.cr0 = CR0_PE;
    // sregs.cr4 = 0;
    // sregs.cs.base = 0;
    // sregs.cs.limit = 0x0000ffff;
    // sregs.cs.selector = 1<<3;
    // sregs.ds.base = 0;
    // sregs.ds.limit = 0x0000ffff;
    // sregs.ds.selector = 2<<3;
    // sregs.es.base = 0;
    // sregs.es.limit = 0x0000ffff;
    // sregs.es.selector = 2<<3;
    // sregs.ss.base = 0;
    // sregs.ss.limit = 0x0000ffff;
    // sregs.ss.selector = 2<<3;
    // sregs.tr.base = 0;
    // sregs.tr.limit = 0x67;
    // sregs.tr.selector = 3<<3;
    // vcpu.set_sregs(&sregs).unwrap();

    const BOOT_GDT_MAX: usize = 4;
    let gdt_table: [u64; BOOT_GDT_MAX] = {
        // Configure GDT entries as specified by PVH boot protocol
        [
            gdt_entry(0, 0, 0),               // NULL
            gdt_entry(0xc09b, 0, 0xffffffff), // CODE
            gdt_entry(0xc093, 0, 0xffffffff), // DATA
            gdt_entry(0x008b, 0, 0x67),       // TSS
        ]
    };
    // set sregs
    let mut sregs = vcpu.get_sregs().unwrap();
    // let code_seg = seg_with_st(1, 0b1011);
    // let data_seg = seg_with_st(2, 0b0011);
    // let tss_seg = seg_with_st(3, 0b1011);
    let code_seg = segment_from_gdt(gdt_table[1], 1);
    let data_seg = segment_from_gdt(gdt_table[2], 2);
    let tss_seg = segment_from_gdt(gdt_table[3], 3);

    // Write segments
    write_gdt_table(&gdt_table[..], &guest_mem);
    sregs.gdt.base = BOOT_GDT_START.raw_value();
    sregs.gdt.limit = std::mem::size_of_val(&gdt_table) as u16 - 1;

    sregs.cs = code_seg;
    sregs.ds = data_seg;
    sregs.es = data_seg;
    sregs.fs = data_seg;
    sregs.gs = data_seg;
    sregs.ss = data_seg;
    sregs.tr = tss_seg;

    sregs.cr0 = CR0_PE;
    sregs.cr4 = 0;
    
    vcpu.set_sregs(&sregs).unwrap();

    let boot_cmdline = linux_loader::cmdline::Cmdline::try_from(DEFAULT_KERNEL_CMDLINE, CMDLINE_MAX_SIZE).unwrap();
    linux_loader::loader::load_cmdline(&guest_mem, CMDLINE_START, &boot_cmdline).unwrap();

    let mut start_info = hvm_start_info::default();
    start_info.magic = XEN_HVM_START_MAGIC_VALUE;
    start_info.version = 1;
    start_info.nr_modules = 0;
    start_info.cmdline_paddr = CMDLINE_START.raw_value();
    start_info.memmap_paddr = MEMMAP_START.raw_value();

    let ramdisk_mod = hvm_modlist_entry{
        paddr: initrd_addr.raw_value(),
        size: initramfs_size as u64,
        ..Default::default()
    };
    start_info.nr_modules += 1;
    // 配置initramfs的加载地址
    start_info.modlist_paddr = MODLIST_START.raw_value();
    // Write the modlist struct to guest memory.
    guest_mem.write_obj(ramdisk_mod, MODLIST_START).unwrap();

    // Vector to hold the memory maps which needs to be written to guest memory
    // at MEMMAP_START after all of the mappings are recorded.
    let mut memmap: Vec<hvm_memmap_table_entry> = Vec::new();

    const E820_RAM: u32 = 1;
    const EBDA_START: u64 = 0x9fc00;
    const FIRST_ADDR_PAST_32BITS: u64 = 1 << 32;
    const MEM_32BIT_GAP_SIZE: u64 = 768 << 20;
    const MMIO_MEM_START: u64 = FIRST_ADDR_PAST_32BITS - MEM_32BIT_GAP_SIZE;

    // Create the memory map entries.
    add_memmap_entry(&mut memmap, 0, EBDA_START, E820_RAM);
    let mem_end = guest_mem.last_addr();
    let first_addr_past_32bits = GuestAddress(FIRST_ADDR_PAST_32BITS);
    let end_32bit_gap_start = GuestAddress(MMIO_MEM_START);
    let himem_start = GuestAddress(HIMEM_START);
    
    if mem_end < first_addr_past_32bits {
        add_memmap_entry(
            &mut memmap,
            himem_start.raw_value(),
            mem_end.unchecked_offset_from(himem_start) + 1,
            E820_RAM,
        );
    } else {
        add_memmap_entry(
            &mut memmap,
            himem_start.raw_value(),
            end_32bit_gap_start.unchecked_offset_from(himem_start),
            E820_RAM,
        );

        if mem_end > first_addr_past_32bits {
            add_memmap_entry(
                &mut memmap,
                first_addr_past_32bits.raw_value(),
                mem_end.unchecked_offset_from(first_addr_past_32bits) + 1,
                E820_RAM,
            );
        }
    }

    start_info.memmap_entries = memmap.len() as u32;

    // Copy the vector with the memmap table to the MEMMAP_START address
    // which is already saved in the memmap_paddr field of hvm_start_info struct.
    let mut memmap_start_addr = MEMMAP_START;
    guest_mem
        .checked_offset(
            memmap_start_addr,
            std::mem::size_of::<hvm_memmap_table_entry>() * start_info.memmap_entries as usize,
        ).unwrap();
    
       // For every entry in the memmap vector, create a MemmapTableEntryWrapper
    // and write it to guest memory.
    for memmap_entry in memmap {
        guest_mem
            .write_obj(memmap_entry, memmap_start_addr).unwrap();
        memmap_start_addr =
            memmap_start_addr.unchecked_add(std::mem::size_of::<hvm_memmap_table_entry>() as u64);
    }

    // The hvm_start_info struct itself must be stored at PVH_START_INFO
    // address, and %rbx will be initialized to contain PVH_INFO_START prior to
    // starting the guest, as required by the PVH ABI.
    let start_info_addr = PVH_INFO_START;

    guest_mem
        .checked_offset(start_info_addr, std::mem::size_of::<hvm_start_info>()).unwrap();
    guest_mem
        .write_obj(start_info, start_info_addr).unwrap();

    const COM1: u16 = 0x3f8;
    let com_evt_1 = EventFdTrigger::new(EventFd::new(EFD_NONBLOCK).unwrap());
    let stdio_serial = Arc::new(Mutex::new(Serial::with_events(
        com_evt_1.try_clone().unwrap(),
        DummySerialEvent,
        std::io::stdout(),
    )));
    let stdio_serial_read = stdio_serial.clone();

    std::thread::spawn(move || {
        loop {
            match vcpu.run().expect("run failed") {
                VcpuExit::Hlt => {
                    println!("VcpuExit Hlt");
                    break;
                }
                VcpuExit::MmioRead(_, _) => {}
                VcpuExit::MmioWrite(_, _) => {}
                VcpuExit::IoIn(addr, data) => {
                    if addr >= COM1 && addr - COM1 < 8 {
                        data[0] = stdio_serial_read.lock().unwrap().read((addr - COM1) as u8);
                    }
                }
                VcpuExit::IoOut(addr, data) => {
                    if addr >= COM1 && addr - COM1 < 8 {
                        let _ = stdio_serial_read
                            .lock()
                            .unwrap()
                            .write((addr - COM1) as u8, data[0]);
                    }
                }
                VcpuExit::Shutdown => {
                    println!("KVM_EXIT_SHUTDOWN");
                    break;
                }
                exit_reason => {
                    println!("KVM_EXIT: {:?}", exit_reason);
                    break;
                    // panic!("KVM_EXIT: {:?}", exit_reason);
                }
            }
        }
    });

    let stdin = std::io::stdin().lock();
    stdin.set_raw_mode().expect("set terminal raw mode failed");

    let poll: PollContext<u8> = PollContext::new().unwrap();
    poll.add(&stdin, 1).unwrap();
    loop {
        let events: PollEvents<u8> = poll.wait().unwrap();
        for event in events.iter_readable() {
            match event.token() {
                1 => {
                    let mut out = [0u8; 64];
                    match stdin.read_raw(&mut out[..]) {
                        Ok(0) => {}
                        Ok(count) => {
                            stdio_serial
                                .lock()
                                .unwrap()
                                .enqueue_raw_bytes(&out[..count])
                                .expect("enqueue bytes failed");
                        }
                        Err(e) => {
                            println!("error while reading stdin: {:?}", e);
                        }
                    }
                }
                _ => unreachable!(),
            }
        }
    }
    // std::thread::sleep(std::time::Duration::from_secs(300));
}

fn add_memmap_entry(memmap: &mut Vec<hvm_memmap_table_entry>, addr: u64, size: u64, mem_type: u32) {
    // Add the table entry to the vector
    memmap.push(hvm_memmap_table_entry {
        addr,
        size,
        type_: mem_type,
        reserved: 0,
    });
}

/// Constructor for a conventional segment GDT (or LDT) entry. Derived from the kernel's segment.h.
pub fn gdt_entry(flags: u16, base: u32, limit: u32) -> u64 {
    (((base as u64) & 0xff000000u64) << (56 - 24))
        | (((flags as u64) & 0x0000f0ffu64) << 40)
        | (((limit as u64) & 0x000f0000u64) << (48 - 16))
        | (((base as u64) & 0x00ffffffu64) << 16)
        | ((limit as u64) & 0x0000ffffu64)
}

// fn seg_with_st(selector_index: u16, type_: u8) -> kvm_segment {
//     kvm_segment {
//         base: 0,
//         limit: 0x000fffff,
//         selector: selector_index << 3,
//         // 0b1011: Code, Executed/Read, accessed
//         // 0b0011: Data, Read/Write, accessed
//         type_,
//         present: 1,
//         dpl: 0,
//         // If L-bit is set, then D-bit must be cleared.
//         db: 0,
//         s: 1,
//         l: 1,
//         g: 1,
//         avl: 0,
//         unusable: 0,
//         padding: 0,
//     }
// }

pub fn segment_from_gdt(entry: u64, table_index: u8) -> kvm_segment {
    kvm_segment {
        base: get_base(entry),
        limit: get_limit(entry),
        selector: (table_index * 8) as u16,
        type_: get_type(entry),
        present: get_p(entry),
        dpl: get_dpl(entry),
        db: get_db(entry),
        s: get_s(entry),
        l: get_l(entry),
        g: get_g(entry),
        avl: get_avl(entry),
        unusable: match get_p(entry) {
            0 => 1,
            _ => 0,
        },
        padding: 0,
    }
}

fn get_base(entry: u64) -> u64 {
    (((entry) & 0xFF00000000000000) >> 32)
        | (((entry) & 0x000000FF00000000) >> 16)
        | (((entry) & 0x00000000FFFF0000) >> 16)
}

fn get_limit(entry: u64) -> u32 {
    let limit: u32 =
        ((((entry) & 0x000F000000000000) >> 32) | ((entry) & 0x000000000000FFFF)) as u32;

    // Perform manual limit scaling if G flag is set
    match get_g(entry) {
        0 => limit,
        _ => (limit << 12) | 0xFFF, // G flag is either 0 or 1
    }
}

fn get_g(entry: u64) -> u8 {
    ((entry & 0x0080000000000000) >> 55) as u8
}

fn get_db(entry: u64) -> u8 {
    ((entry & 0x0040000000000000) >> 54) as u8
}

fn get_l(entry: u64) -> u8 {
    ((entry & 0x0020000000000000) >> 53) as u8
}

fn get_avl(entry: u64) -> u8 {
    ((entry & 0x0010000000000000) >> 52) as u8
}

fn get_p(entry: u64) -> u8 {
    ((entry & 0x0000800000000000) >> 47) as u8
}

fn get_dpl(entry: u64) -> u8 {
    ((entry & 0x0000600000000000) >> 45) as u8
}

fn get_s(entry: u64) -> u8 {
    ((entry & 0x0000100000000000) >> 44) as u8
}

fn get_type(entry: u64) -> u8 {
    ((entry & 0x00000F0000000000) >> 40) as u8
}

fn write_gdt_table(table: &[u64], guest_mem: &GuestMemoryMmap) {
    let boot_gdt_addr = BOOT_GDT_START;
    for (index, entry) in table.iter().enumerate() {
        let addr = guest_mem
            .checked_offset(boot_gdt_addr, index * std::mem::size_of::<u64>()).unwrap();
        guest_mem.write_obj(*entry, addr).unwrap();
    }
}

struct EventFdTrigger(EventFd);

impl Trigger for EventFdTrigger {
    type E = std::io::Error;

    fn trigger(&self) -> std::io::Result<()> {
        self.write(1)
    }
}

impl std::ops::Deref for EventFdTrigger {
    type Target = EventFd;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl EventFdTrigger {
    /// Clone an `EventFdTrigger`.
    pub fn try_clone(&self) -> std::io::Result<Self> {
        Ok(EventFdTrigger((**self).try_clone()?))
    }

    /// Create an `EventFdTrigger`.
    pub fn new(evt: EventFd) -> Self {
        Self(evt)
    }

    // /// Get the associated event fd out of an `EventFdTrigger`.
    // pub fn get_event(&self) -> EventFd {
    //     self.0.try_clone().unwrap()
    // }
}

struct DummySerialEvent;

impl SerialEvents for DummySerialEvent {
    fn buffer_read(&self) {}
    fn out_byte(&self) {}
    fn tx_lost_byte(&self) {}
    fn in_buffer_empty(&self) {}
}

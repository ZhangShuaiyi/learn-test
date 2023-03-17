use std::{
    fs::File,
    io::Cursor,
    sync::{Arc, Mutex},
};

use kvm_bindings::{
    kvm_pit_config, kvm_segment, kvm_userspace_memory_region, KVM_MAX_CPUID_ENTRIES,
    KVM_MEM_LOG_DIRTY_PAGES, KVM_PIT_SPEAKER_DUMMY,
};
use kvm_ioctls::{Kvm, VcpuExit};
use linux_loader::{
    bootparam::boot_params,
    configurator::{linux::LinuxBootConfigurator, BootConfigurator, BootParams},
    loader::{elf::Elf, load_cmdline, Cmdline, KernelLoader},
};
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory};
use vm_superio::{serial::SerialEvents, Serial, Trigger};
use vmm_sys_util::{
    eventfd::{EventFd, EFD_NONBLOCK},
    poll::{PollContext, PollEvents},
    terminal::Terminal,
};

type GuestMemoryMmap = vm_memory::GuestMemoryMmap<AtomicBitmap>;

const MEMORY_SIZE: usize = 512 << 20;

const KVM_TSS_ADDRESS: usize = 0xfffb_d000;
const X86_CR0_PE: u64 = 0x1;
const X86_CR4_PAE: u64 = 0x20;
const X86_CR0_PG: u64 = 0x80000000;
const EFER_LME: u64 = 0x100;
const EFER_LMA: u64 = 0x400;
const BOOT_GDT_OFFSET: u64 = 0x500;

const HIMEM_START: u64 = 0x100000;
const BOOT_CMD_START: u64 = 0x20000;
const BOOT_STACK_POINTER: u64 = 0x8ff0;
const ZERO_PAGE_START: u64 = 0x7000;

const KERNEL_PATH: &str = "/opt/kata/share/kata-containers/vmlinux-5.19.2-96";
const INITRD_PATH: &str = "/root/datas/centos-no-kernel-initramfs.img";
const BOOT_CMD: &str = "console=ttyS0 noapic reboot=k panic=1 pci=off acpi=off";
// in /bin/sh can run command
// exec /init
// const BOOT_CMD: &str = "console=ttyS0 noapic noacpi reboot=k panic=1 pci=off nomodule rdinit=/bin/sh";
// const BOOT_CMD: &str = "console=ttyS0 noapic reboot=k panic=1 pci=off";

fn main() {
    // create vm
    let kvm = Kvm::new().expect("open kvm device failed");
    let vm = kvm.create_vm().expect("create vm failed");

    // initialize irq chip and pit
    vm.create_irq_chip().unwrap();
    let pit_config = kvm_pit_config {
        flags: KVM_PIT_SPEAKER_DUMMY,
        ..Default::default()
    };
    vm.create_pit2(pit_config).unwrap();

    // create memory
    let guest_addr = GuestAddress(0x0);
    let guest_mem = GuestMemoryMmap::from_ranges(&[(guest_addr, MEMORY_SIZE)]).unwrap();
    let host_addr = guest_mem.get_host_address(guest_addr).unwrap();
    let mem_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: 0,
        memory_size: MEMORY_SIZE as u64,
        userspace_addr: host_addr as u64,
        flags: KVM_MEM_LOG_DIRTY_PAGES,
    };
    unsafe {
        vm.set_user_memory_region(mem_region)
            .expect("set user memory region failed")
    };
    vm.set_tss_address(KVM_TSS_ADDRESS as usize)
        .expect("set tss failed");

    // create vcpu and set cpuid
    let vcpu = vm.create_vcpu(0).expect("create vcpu failed");
    let kvm_cpuid = kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES).unwrap();
    vcpu.set_cpuid2(&kvm_cpuid).unwrap();

    // load linux kernel
    let mut kernel_file = File::open(KERNEL_PATH).expect("open kernel file failed");
    let kernel_entry = Elf::load(
        &guest_mem,
        None,
        &mut kernel_file,
        Some(GuestAddress(HIMEM_START)),
    )
    .unwrap()
    .kernel_load;

    println!("!!!! kernel_entry: {:x}", kernel_entry.raw_value());

    // load initrd
    let initrd_content = std::fs::read(INITRD_PATH).expect("read initrd file failed");
    let first_region = guest_mem.find_region(GuestAddress::new(0)).unwrap();
    assert!(
        initrd_content.len() <= first_region.size(),
        "too big initrd"
    );
    let initrd_addr =
        GuestAddress((first_region.size() - initrd_content.len()) as u64 & !(4096 - 1));
    guest_mem
        .read_from(
            initrd_addr,
            &mut Cursor::new(&initrd_content),
            initrd_content.len(),
        )
        .unwrap();

    // load boot command
    let mut boot_cmdline = Cmdline::new(0x10000).unwrap();
    boot_cmdline.insert_str(BOOT_CMD).unwrap();
    load_cmdline(&guest_mem, GuestAddress(BOOT_CMD_START), &boot_cmdline).unwrap();

    // set regs
    let mut regs = vcpu.get_regs().unwrap();
    regs.rip = kernel_entry.raw_value();
    regs.rsp = BOOT_STACK_POINTER;
    regs.rbp = BOOT_STACK_POINTER;
    regs.rsi = ZERO_PAGE_START;
    regs.rflags = 2;
    vcpu.set_regs(&regs).unwrap();

    // set sregs
    let mut sregs = vcpu.get_sregs().unwrap();
    const CODE_SEG: kvm_segment = seg_with_st(1, 0b1011);
    const DATA_SEG: kvm_segment = seg_with_st(2, 0b0011);

    // construct kvm_segment and set to segment registers
    sregs.cs = CODE_SEG;
    sregs.ds = DATA_SEG;
    sregs.es = DATA_SEG;
    sregs.fs = DATA_SEG;
    sregs.gs = DATA_SEG;
    sregs.ss = DATA_SEG;

    // construct gdt table, write to memory and set it to register
    let gdt_table: [u64; 3] = [
        0,                       // NULL
        to_gdt_entry(&CODE_SEG), // CODE
        to_gdt_entry(&DATA_SEG), // DATA
    ];
    let boot_gdt_addr = GuestAddress(BOOT_GDT_OFFSET);
    for (index, entry) in gdt_table.iter().enumerate() {
        let addr = guest_mem
            .checked_offset(boot_gdt_addr, index * std::mem::size_of::<u64>())
            .unwrap();
        guest_mem.write_obj(*entry, addr).unwrap();
    }
    sregs.gdt.base = BOOT_GDT_OFFSET;
    sregs.gdt.limit = std::mem::size_of_val(&gdt_table) as u16 - 1;

    // enable protected mode
    sregs.cr0 |= X86_CR0_PE;

    // set page table
    let boot_pml4_addr = GuestAddress(0xa000);
    let boot_pdpte_addr = GuestAddress(0xb000);
    let boot_pde_addr = GuestAddress(0xc000);

    guest_mem
        .write_slice(
            &(boot_pdpte_addr.raw_value() as u64 | 0b11).to_le_bytes(),
            boot_pml4_addr,
        )
        .unwrap();
    guest_mem
        .write_slice(
            &(boot_pde_addr.raw_value() as u64 | 0b11).to_le_bytes(),
            boot_pdpte_addr,
        )
        .unwrap();

    for i in 0..512 {
        guest_mem
            .write_slice(
                &((i << 21) | 0b10000011u64).to_le_bytes(),
                boot_pde_addr.unchecked_add(i * 8),
            )
            .unwrap();
    }
    sregs.cr3 = boot_pml4_addr.raw_value() as u64;
    sregs.cr4 |= X86_CR4_PAE;
    sregs.cr0 |= X86_CR0_PG;
    sregs.efer |= EFER_LMA | EFER_LME;
    vcpu.set_sregs(&sregs).unwrap();

    // crate and write boot_params
    let mut params = boot_params::default();
    // <https://www.kernel.org/doc/html/latest/x86/boot.html>
    const KERNEL_TYPE_OF_LOADER: u8 = 0xff;
    const KERNEL_BOOT_FLAG_MAGIC_NUMBER: u16 = 0xaa55;
    const KERNEL_HDR_MAGIC_NUMBER: u32 = 0x5372_6448;
    const KERNEL_MIN_ALIGNMENT_BYTES: u32 = 0x0100_0000;

    params.hdr.type_of_loader = KERNEL_TYPE_OF_LOADER;
    params.hdr.boot_flag = KERNEL_BOOT_FLAG_MAGIC_NUMBER;
    params.hdr.header = KERNEL_HDR_MAGIC_NUMBER;
    params.hdr.cmd_line_ptr = BOOT_CMD_START as u32;
    params.hdr.cmdline_size = 1 + BOOT_CMD.len() as u32;
    params.hdr.kernel_alignment = KERNEL_MIN_ALIGNMENT_BYTES;
    params.hdr.ramdisk_image = initrd_addr.raw_value() as u32;
    params.hdr.ramdisk_size = initrd_content.len() as u32;

    // Value taken from <https://elixir.bootlin.com/linux/v5.10.68/source/arch/x86/include/uapi/asm/e820.h#L31>
    const E820_RAM: u32 = 1;
    const EBDA_START: u64 = 0x9fc00;
    const FIRST_ADDR_PAST_32BITS: u64 = 1 << 32;
    const MEM_32BIT_GAP_SIZE: u64 = 768 << 20;
    const MMIO_MEM_START: u64 = FIRST_ADDR_PAST_32BITS - MEM_32BIT_GAP_SIZE;

    add_e820_entry(&mut params, 0, EBDA_START, E820_RAM);
    let last_addr = guest_mem.last_addr();
    let first_addr_past_32bits = GuestAddress(FIRST_ADDR_PAST_32BITS);
    let end_32bit_gap_start = GuestAddress(MMIO_MEM_START);
    let himem_start = GuestAddress(HIMEM_START);
    if last_addr < end_32bit_gap_start {
        add_e820_entry(
            &mut params,
            himem_start.raw_value() as u64,
            // it's safe to use unchecked_offset_from because
            // mem_end > himem_start
            last_addr.unchecked_offset_from(himem_start) as u64 + 1,
            E820_RAM,
        );
    } else {
        add_e820_entry(
            &mut params,
            himem_start.raw_value(),
            // it's safe to use unchecked_offset_from because
            // end_32bit_gap_start > himem_start
            end_32bit_gap_start.unchecked_offset_from(himem_start),
            E820_RAM,
        );

        if last_addr > first_addr_past_32bits {
            add_e820_entry(
                &mut params,
                first_addr_past_32bits.raw_value(),
                // it's safe to use unchecked_offset_from because
                // mem_end > first_addr_past_32bits
                last_addr.unchecked_offset_from(first_addr_past_32bits) + 1,
                E820_RAM,
            );
        }
    }
    LinuxBootConfigurator::write_bootparams(
        &BootParams::new(&params, GuestAddress(ZERO_PAGE_START)),
        &guest_mem,
    )
    .unwrap();

    // initialize devices
    const COM1: u16 = 0x3f8;
    let com_evt_1 = EventWrapper::new();
    vm.register_irqfd(&com_evt_1.0, 4).unwrap();
    let stdio_serial = Arc::new(Mutex::new(Serial::with_events(
        com_evt_1.try_clone().unwrap(),
        DummySerialEvent,
        std::io::stdout(),
    )));

    // run vcpu in another thread
    let exit_evt = EventWrapper::new();
    let vcpu_exit_evt = exit_evt.try_clone().unwrap();
    let stdio_serial_read = stdio_serial.clone();
    std::thread::spawn(move || {
        loop {
            match vcpu.run() {
                Ok(run) => match run {
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
                    VcpuExit::MmioRead(_, _) => {}
                    VcpuExit::MmioWrite(_, _) => {}
                    VcpuExit::Hlt => {
                        println!("KVM_EXIT_HLT");
                        break;
                    }
                    VcpuExit::Shutdown => {
                        println!("KVM_EXIT_SHUTDOWN");
                        break;
                    }
                    r => {
                        println!("KVM_EXIT: {:?}", r);
                    }
                },
                Err(e) => {
                    println!("KVM Run error: {:?}", e);
                    break;
                }
            }
        }
        vcpu_exit_evt.trigger().unwrap();
    });

    // process events
    let stdin = std::io::stdin().lock();
    stdin.set_raw_mode().expect("set terminal raw mode failed");

    let poll: PollContext<u8> = PollContext::new().unwrap();
    poll.add(&exit_evt.0, 0).unwrap();
    poll.add(&stdin, 1).unwrap();
    'l: loop {
        let events: PollEvents<u8> = poll.wait().unwrap();
        for event in events.iter_readable() {
            match event.token() {
                0 => {
                    println!("vcpu stopped, main loop exit");
                    break 'l;
                }
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
}

const fn seg_with_st(selector_index: u16, type_: u8) -> kvm_segment {
    kvm_segment {
        base: 0,
        limit: 0x000fffff,
        selector: selector_index << 3,
        // 0b1011: Code, Executed/Read, accessed
        // 0b0011: Data, Read/Write, accessed
        type_,
        present: 1,
        dpl: 0,
        // If L-bit is set, then D-bit must be cleared.
        db: 0,
        s: 1,
        l: 1,
        g: 1,
        avl: 0,
        unusable: 0,
        padding: 0,
    }
}

// Ref: <https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html> 3-10 Vol. 3A
const fn to_gdt_entry(seg: &kvm_segment) -> u64 {
    let base = seg.base;
    let limit = seg.limit as u64;
    // flags: G, DB, L, AVL
    let flags = (seg.g as u64 & 0x1) << 3
        | (seg.db as u64 & 0x1) << 2
        | (seg.l as u64 & 0x1) << 1
        | (seg.avl as u64 & 0x1);
    // access: P, DPL, S, Type
    let access = (seg.present as u64 & 0x1) << 7
        | (seg.dpl as u64 & 0x11) << 5
        | (seg.s as u64 & 0x1) << 4
        | (seg.type_ as u64 & 0x1111);
    ((base & 0xff00_0000u64) << 32)
        | ((base & 0x00ff_ffffu64) << 16)
        | (limit & 0x0000_ffffu64)
        | ((limit & 0x000f_0000u64) << 32)
        | (flags << 52)
        | (access << 40)
}

fn add_e820_entry(params: &mut boot_params, addr: u64, size: u64, mem_type: u32) {
    if params.e820_entries >= params.e820_table.len() as u8 {
        panic!();
    }
    params.e820_table[params.e820_entries as usize].addr = addr;
    params.e820_table[params.e820_entries as usize].size = size;
    params.e820_table[params.e820_entries as usize].type_ = mem_type;
    params.e820_entries += 1;
}

struct EventWrapper(EventFd);

impl EventWrapper {
    pub fn new() -> Self {
        Self(EventFd::new(EFD_NONBLOCK).unwrap())
    }

    pub fn try_clone(&self) -> std::io::Result<Self> {
        self.0.try_clone().map(Self)
    }
}

impl std::ops::Deref for EventWrapper {
    type Target = EventFd;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Trigger for EventWrapper {
    type E = std::io::Error;

    fn trigger(&self) -> std::io::Result<()> {
        self.0.write(1)
    }
}

struct DummySerialEvent;

impl SerialEvents for DummySerialEvent {
    fn buffer_read(&self) {}
    fn out_byte(&self) {}
    fn tx_lost_byte(&self) {}
    fn in_buffer_empty(&self) {}
}
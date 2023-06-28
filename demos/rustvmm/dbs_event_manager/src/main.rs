use std::{
    io::{Seek, SeekFrom},
    sync::{Arc, Mutex},
};

use dbs_arch::{
    cpuid::{VmSpec, VpmuFeatureLevel},
    gdt,
};
use dbs_boot::{
    add_e820_entry,
    bootparam::{boot_params, E820_RAM},
    mptable, BootParamsWrapper,
};
use dbs_device::device_manager::IoManager;
use dbs_device::resources::Resource;
use dbs_legacy_devices::{ConsoleHandler, SerialDevice};

use dbs_utils::epoll_manager::{
    EpollManager, EventOps, EventSet, Events, MutEventSubscriber,
};

// use event_manager::{
//     EventManager as BaseEventManager, EventOps, Events, MutEventSubscriber, SubscriberOps,
// };
use kvm_bindings::{
    kvm_pit_config, kvm_userspace_memory_region, KVM_MAX_CPUID_ENTRIES, KVM_PIT_SPEAKER_DUMMY,
};
use kvm_ioctls::{Kvm, VcpuExit};
use linux_loader::{
    configurator::BootConfigurator,
    loader::{load_cmdline, Cmdline, KernelLoader},
};
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};
// use vmm_sys_util::poll::{PollContext, PollEvents};
// use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::terminal::Terminal;

// type EventManager = BaseEventManager<Arc<Mutex<dyn MutEventSubscriber>>>;

// x86_64 boot constants. See https://www.kernel.org/doc/Documentation/x86/boot.txt for the full
// documentation.
// Header field: `boot_flag`. Must contain 0xaa55. This is the closest thing old Linux kernels
// have to a magic number.
const KERNEL_BOOT_FLAG_MAGIC: u16 = 0xaa55;
// Header field: `header`. Must contain the magic number `HdrS` (0x5372_6448).
const KERNEL_HDR_MAGIC: u32 = 0x5372_6448;
// Header field: `type_of_loader`. Unless using a pre-registered bootloader (which we aren't), this
// field must be set to 0xff.
const KERNEL_LOADER_OTHER: u8 = 0xff;
// Header field: `kernel_alignment`. Alignment unit required by a relocatable kernel.
const KERNEL_MIN_ALIGNMENT_BYTES: u32 = 0x0100_0000;

const MEMORY_SIZE: usize = 512 << 20;

// const KERNEL_PATH: &str = "/opt/kata/share/kata-containers/vmlinux-5.19.2-96";
const KERNEL_PATH: &str = "/root/datas/vmlinux-5.19-96";
const INITRD_PATH: &str = "/root/datas/centos-no-kernel-initramfs.img";
const BOOT_CMD: &str = "console=ttyS0 reboot=k panic=1 pci=off acpi=off";
// const BOOT_CMD: &str = "console=ttyS0 noapic reboot=k panic=1 pci=off acpi=off";

fn main() {
    let kvm = Kvm::new().expect("open kvm device failed");
    // 创建vm，内核会创建struct kvm，并加入vm_list链表，此时kvm.userspace_pid为进程pid
    // #遍历vm_list链表
    // >>> for kvm in list_for_each_entry("struct kvm", prog["vm_list"].address_of_(), "vm_list"): print('kvm:0x%lx' % (kvm))
    // >>> prog.type('struct kvm') #查看kvm结构体
    // >>> kvm = Object(prog, 'struct kvm', address=0xffffad3084029000) #根据地址查看变量
    let vm = kvm.create_vm().expect("create vm failed");

    // create memory
    let guest_addr = GuestAddress(0x0);
    let guest_mem = GuestMemoryMmap::<()>::from_ranges(&[(guest_addr, MEMORY_SIZE)]).unwrap();
    let host_addr = guest_mem.get_host_address(guest_addr).unwrap();
    let mem_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: 0,
        memory_size: MEMORY_SIZE as u64,
        userspace_addr: host_addr as u64,
        flags: 0,
    };
    println!("====host_addr:0x{:x}", host_addr as u64);
    unsafe {
        // 更新kvm.memslots[0].memslots[0]
        vm.set_user_memory_region(mem_region)
            .expect("set user memory region failed")
    };

    vm.set_tss_address(dbs_boot::layout::KVM_TSS_ADDRESS as usize)
        .unwrap();

    // initialize irq chip and pit
    // 初始化kvm.arch.vpic和kvm.arch.vioapic
    vm.create_irq_chip().unwrap();
    let pit_config = kvm_pit_config {
        flags: KVM_PIT_SPEAKER_DUMMY,
        ..Default::default()
    };
    // 初始化kvm.arch.vpit
    vm.create_pit2(pit_config).unwrap();

    // create vcpu and set cpuid
    // 初始化kvm.vcpus[0]
    let vcpu = vm.create_vcpu(0).expect("create vcpu failed");
    let base_cpuid = kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES).unwrap();
    let mut cpuid = base_cpuid.clone();
    let cpuid_vm_spec =
        VmSpec::new(0, 1, 1, 1, 1, VpmuFeatureLevel::Disabled).expect("Error creating vm_spec");
    dbs_arch::cpuid::process_cpuid(&mut cpuid, &cpuid_vm_spec).unwrap();
    // 更新kvm.vcpus[0].arch.cpuid_entries和kvm.vcpus[0].arch.cpuid_nent
    vcpu.set_cpuid2(&cpuid).unwrap();

    // 配置mptable
    mptable::setup_mptable(&guest_mem, 1, 1).unwrap();

    dbs_arch::regs::setup_msrs(&vcpu).unwrap();
    dbs_arch::regs::setup_fpu(&vcpu).unwrap();
    // 更新kvm.vcpus[0].arch.apic
    dbs_arch::interrupts::set_lint(&vcpu).unwrap();

    let gdt_table: [u64; dbs_boot::layout::BOOT_GDT_MAX] = [
        gdt::gdt_entry(0, 0, 0),            // NULL
        gdt::gdt_entry(0xa09b, 0, 0xfffff), // CODE
        gdt::gdt_entry(0xc093, 0, 0xfffff), // DATA
        gdt::gdt_entry(0x808b, 0, 0xfffff), // TSS
    ];
    let pgtable_addr = dbs_boot::setup_identity_mapping(&guest_mem).unwrap();
    // 通过vmcs_writeX更新vcpu的vmcs设置sreg
    dbs_arch::regs::setup_sregs(
        &guest_mem,
        &vcpu,
        pgtable_addr,
        &gdt_table,
        dbs_boot::layout::BOOT_GDT_OFFSET,
        dbs_boot::layout::BOOT_IDT_OFFSET,
    )
    .unwrap();

    let himem_start = GuestAddress(dbs_boot::layout::HIMEM_START);

    // load linux kernel
    let mut kernel_file = std::fs::File::open(KERNEL_PATH).expect("open kernel file failed");
    // 通过 "readelf -h /root/datas/vmlinux-5.19-96" 查看到 Entry point address 地址为0x1000000
    // 通过 "objdump -t /root/datas/vmlinux-5.19-96 | grep 1000000" 查看到0x1000000为phys_startup_64
    // phys_startup_64定义为 "phys_startup_64 = ABSOLUTE(startup_64 - LOAD_OFFSET);"
    let kernel_entry =
        linux_loader::loader::elf::Elf::load(&guest_mem, None, &mut kernel_file, Some(himem_start))
            .unwrap()
            .kernel_load;

    println!("===kernel_entry:0x{:x}", kernel_entry.raw_value());

    let mut initrd_file = std::fs::File::open(INITRD_PATH).expect("open initrd file failed");
    let initrd_size = match initrd_file.seek(SeekFrom::End(0)) {
        Ok(size) => size as usize,
        Err(e) => panic!("initramfs file seek to end failed: {:?}", e),
    };
    initrd_file.seek(SeekFrom::Start(0)).unwrap();
    // Get the target address
    let initrd_address = dbs_boot::initrd_load_addr(&guest_mem, initrd_size as u64).unwrap();
    // Load the image into memory
    guest_mem
        .read_from(GuestAddress(initrd_address), &mut initrd_file, initrd_size)
        .unwrap();
    println!(
        "initramfs loaded address = 0x{:x} size = 0x{:x}",
        initrd_address, initrd_size
    );

    // load boot command
    let mut boot_cmdline = Cmdline::new(0x10000);
    boot_cmdline.insert_str(BOOT_CMD).unwrap();
    load_cmdline(
        &guest_mem,
        GuestAddress(dbs_boot::layout::CMDLINE_START),
        &boot_cmdline,
    )
    .unwrap();

    let mut boot_params: BootParamsWrapper = BootParamsWrapper(boot_params::default());
    boot_params.0.hdr.type_of_loader = KERNEL_LOADER_OTHER;
    boot_params.0.hdr.boot_flag = KERNEL_BOOT_FLAG_MAGIC;
    boot_params.0.hdr.header = KERNEL_HDR_MAGIC;
    boot_params.0.hdr.kernel_alignment = KERNEL_MIN_ALIGNMENT_BYTES;
    boot_params.0.hdr.cmd_line_ptr = dbs_boot::layout::CMDLINE_START as u32;
    boot_params.0.hdr.cmdline_size = 1 + BOOT_CMD.len() as u32;
    boot_params.0.hdr.ramdisk_image = initrd_address as u32;
    boot_params.0.hdr.ramdisk_size = initrd_size as u32;

    // Add an entry for EBDA itself.
    add_e820_entry(
        &mut boot_params.0,
        0,
        dbs_boot::layout::EBDA_START,
        E820_RAM,
    )
    .unwrap();

    let last_addr = guest_mem.last_addr();
    let mmio_gap_start = GuestAddress(dbs_boot::layout::MMIO_LOW_START);
    let mmio_gap_end = GuestAddress(dbs_boot::layout::MMIO_LOW_START);
    if last_addr < GuestAddress(dbs_boot::layout::MMIO_LOW_END) {
        add_e820_entry(
            &mut boot_params.0,
            himem_start.raw_value() as u64,
            // it's safe to use unchecked_offset_from because
            // mem_end > himem_start
            last_addr.unchecked_offset_from(himem_start) as u64 + 1,
            E820_RAM,
        )
        .unwrap();
    } else {
        add_e820_entry(
            &mut boot_params.0,
            himem_start.raw_value(),
            mmio_gap_start.unchecked_offset_from(himem_start),
            E820_RAM,
        )
        .unwrap();

        if last_addr > mmio_gap_end {
            add_e820_entry(
                &mut boot_params.0,
                mmio_gap_end.raw_value() + 1,
                // The unchecked_offset_from is safe, guaranteed by the `if` condition above.
                // The unchecked + 1 is safe because:
                // * overflow could only occur if last_addr == u64::MAX and mmio_gap_end == 0
                // * mmio_gap_end > mmio_gap_start, which is a valid u64 => mmio_gap_end > 0
                last_addr.unchecked_offset_from(mmio_gap_end) + 1,
                E820_RAM,
            )
            .unwrap();
        }
    }

    linux_loader::configurator::linux::LinuxBootConfigurator::write_bootparams(
        &linux_loader::configurator::BootParams::new(
            &boot_params,
            GuestAddress(dbs_boot::layout::ZERO_PAGE_START),
        ),
        &guest_mem,
    )
    .unwrap();

    // 更新vcpu的rip寄存器
    dbs_arch::regs::setup_regs(
        &vcpu,
        kernel_entry.raw_value(),
        dbs_boot::layout::BOOT_STACK_POINTER,
        dbs_boot::layout::BOOT_STACK_POINTER,
        dbs_boot::layout::ZERO_PAGE_START,
    )
    .unwrap();

    //        COM Port      IO Port     gsi
    // ttyS0  COM1          0x3f8       4
    // ttyS1  COM2          0x2f8       3
    const COM: u16 = 0x3f8;
    let com_evt = EventFd::new(EFD_NONBLOCK).unwrap();
    // 必须添加register_irqfd，否则无法输入，COM1的gsi为4
    // 注册irqfd将struct kvm_kernel_irqfd添加到kvm.irqfds.items链表
    // 通过 "perf record -e kvm:kvm_set_irq -e kvm:kvm_pic_set_irq -e kvm:kvm_ioapic_set_irq -e kvm:kvm_apic_accept_irq -e kvm:kvm_inj_virq" 查看中断注入情况
    vm.register_irqfd(&com_evt, 4).unwrap();
    let stdio_serial = Arc::new(Mutex::new(SerialDevice::new(com_evt.try_clone().unwrap())));
    stdio_serial
        .lock()
        .unwrap()
        .set_output_stream(Some(Box::new(std::io::stdout())));

    let device_mgr = Arc::new(Mutex::new(IoManager::new()));
    let resources = [Resource::PioAddressRange {
        base: COM,
        size: 0x8,
    }];
    device_mgr
        .lock()
        .unwrap()
        .register_device_io(stdio_serial.clone(), &resources)
        .unwrap();

    std::thread::spawn(move || {
        loop {
            match vcpu.run() {
                Ok(exit_reason) => {
                    match exit_reason {
                        VcpuExit::Hlt => {
                            println!("VcpuExit Hlt");
                            break;
                        }
                        VcpuExit::MmioRead(_, _) => {}
                        VcpuExit::MmioWrite(_, _) => {}
                        VcpuExit::IoIn(addr, data) => {
                            if addr >= COM && addr - COM < 8 {
                                device_mgr.lock().unwrap().pio_read(addr, data).unwrap();
                            }
                        }
                        VcpuExit::IoOut(addr, data) => {
                            if addr >= COM && addr - COM < 8 {
                                device_mgr.lock().unwrap().pio_write(addr, data).unwrap();
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
                Err(e) => match e.errno() {
                    libc::EAGAIN => {}
                    libc::EINTR => {}
                    _ => {
                        println!("Emulation error: {}", e);
                        break;
                    }
                },
            }
        }
    });

    let handler = ConsoleEpollHandler {
        device: stdio_serial,
        stdin_handle: std::io::stdin(),
    };

    let event_manager = EpollManager::default();
    event_manager.add_subscriber(Box::new(handler));
    loop {
        match event_manager.handle_events(-1) {
            Ok(_) => (),
            Err(e) => eprintln!("Failed to handle events: {e:?}"),
        }
    }

    // let mut event_manager = EventManager::new().expect("epoll_manager: failed create new instance");
    // event_manager.add_subscriber(Arc::new(Mutex::new(handler)));
    // loop {
    //     match event_manager.run_with_timeout(-1) {
    //         Ok(_) => (),
    //         Err(e) => eprintln!("Failed to handle events: {e:?}"),
    //     }
    // }
}

struct ConsoleEpollHandler {
    device: Arc<Mutex<SerialDevice>>,
    stdin_handle: std::io::Stdin,
}

impl MutEventSubscriber for ConsoleEpollHandler {
    fn process(&mut self, events: Events, _: &mut EventOps) {
        let source = events.fd();
        let event_set = events.event_set();
        let supported_events = EventSet::IN;
        if !supported_events.contains(event_set) {
            println!(
                "Received unknown event: {:?} from source: {:?}",
                event_set, source
            );
            return;
        }

        if source == libc::STDIN_FILENO {
            let mut out = [0u8; 64];
            match self.stdin_handle.lock().read_raw(&mut out[..]) {
                Ok(0) => {}
                Ok(count) => {
                    self.device
                        .lock()
                        .unwrap()
                        .raw_input(&out[..count])
                        .expect("enqueue bytes failed");
                }
                Err(e) => {
                    println!("error while reading stdin: {:?}", e);
                }
            }
        }
    }

    fn init(&mut self, ops: &mut EventOps) {
        self.stdin_handle
            .lock()
            .set_raw_mode()
            .expect("set terminal raw mode failed");
        ops.add(Events::new(&self.stdin_handle, EventSet::IN))
            .expect("Cannot register event.");
    }
}

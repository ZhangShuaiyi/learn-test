use std::fs::OpenOptions;
use std::os::unix::io::AsRawFd;
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
// use dbs_device::resources::ResourceConstraint;
use dbs_device::resources::MsiIrqType::GenericMsi;
use dbs_device::resources::{DeviceResources, Resource};
use dbs_legacy_devices::{ConsoleHandler, SerialDevice};
use dbs_virtio_devices::block::aio::Aio;
use dbs_virtio_devices::block::{Block, LocalFile, Ufile};
use dbs_virtio_devices::mmio::{
    MmioV2Device, DRAGONBALL_FEATURE_INTR_USED, DRAGONBALL_FEATURE_PER_QUEUE_NOTIFY,
};
use dbs_virtio_devices::VirtioDevice;
// use dbs_virtio_devices::mmio::{DRAGONBALL_MMIO_DOORBELL_SIZE, MMIO_DEFAULT_CFG_SIZE,};
use dbs_interrupt::KvmIrqManager;

use dbs_utils::epoll_manager::{EpollManager, EventOps, EventSet, Events, MutEventSubscriber};

// use event_manager::{
//     EventManager as BaseEventManager, EventOps, Events, MutEventSubscriber, SubscriberOps,
// };
use kvm_bindings::{
    kvm_pit_config, kvm_userspace_memory_region, KVM_MAX_CPUID_ENTRIES, KVM_PIT_SPEAKER_DUMMY,
};
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use linux_loader::{
    configurator::BootConfigurator,
    loader::{load_cmdline, Cmdline, KernelLoader},
};
use vm_memory::atomic::GuestMemoryAtomic;
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap, GuestRegionMmap};
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};
// use vmm_sys_util::poll::{PollContext, PollEvents};
// use vmm_sys_util::epoll::EventSet;
use virtio_queue::QueueSync;
use vmm_sys_util::terminal::Terminal;

// type EventManager = BaseEventManager<Arc<Mutex<dyn MutEventSubscriber>>>;
type BlockDevice = Block<GuestMemoryAtomic<GuestMemoryMmap>>;
type DbsVirtioDevice =
    Box<dyn VirtioDevice<GuestMemoryAtomic<GuestMemoryMmap>, QueueSync, GuestRegionMmap>>;

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

//        COM Port      IO Port     gsi
// ttyS0  COM1          0x3f8       4
// ttyS1  COM2          0x2f8       3
const COM: u16 = 0x3f8;

const CPU_NUM: u8 = 2;
const MEMORY_SIZE: usize = 512 << 20;

const KERNEL_PATH: &str = "/opt/kata/share/kata-containers/vmlinux.container";
const INITRD_PATH: &str = "/root/datas/centos-no-kernel-initramfs.img";
const BLOCK_PATH: &str = "/root/datas/empty.raw";
const BOOT_CMD: &str = "console=ttyS0 reboot=k panic=1 pci=off virtio_mmio.device=8K@0xc0000000:6";
// const BOOT_CMD: &str = "console=ttyS0 reboot=k panic=1 pci=off acpi=off";
// const BOOT_CMD: &str = "console=ttyS0 noapic reboot=k panic=1 pci=off acpi=off";

struct VM {
    kvm: Kvm,
    fd: VmFd,
    guest_mem: GuestMemoryMmap,
    device_mgr: Arc<Mutex<IoManager>>,
    vcpus: Vec<VcpuFd>,
}

fn create_vcpus(vm: &mut VM) {
    let mut id: u8 = 0;
    let base_cpuid = vm.kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES).unwrap();
    while id < CPU_NUM {
        let vcpu = vm.fd.create_vcpu(id as u64).expect("create vcpu failed");
        let mut cpuid = base_cpuid.clone();
        let cpuid_vm_spec = VmSpec::new(id, CPU_NUM, 1, 1, 1, VpmuFeatureLevel::Disabled)
            .expect("Error creating vm_spec");
        dbs_arch::cpuid::process_cpuid(&mut cpuid, &cpuid_vm_spec).unwrap();
        vcpu.set_cpuid2(&cpuid).unwrap();

        dbs_arch::regs::setup_msrs(&vcpu).unwrap();
        dbs_arch::regs::setup_fpu(&vcpu).unwrap();
        dbs_arch::interrupts::set_lint(&vcpu).unwrap();

        let gdt_table: [u64; dbs_boot::layout::BOOT_GDT_MAX] = [
            gdt::gdt_entry(0, 0, 0),            // NULL
            gdt::gdt_entry(0xa09b, 0, 0xfffff), // CODE
            gdt::gdt_entry(0xc093, 0, 0xfffff), // DATA
            gdt::gdt_entry(0x808b, 0, 0xfffff), // TSS
        ];
        let pgtable_addr = dbs_boot::setup_identity_mapping(&vm.guest_mem).unwrap();
        dbs_arch::regs::setup_sregs(
            &vm.guest_mem,
            &vcpu,
            pgtable_addr,
            &gdt_table,
            dbs_boot::layout::BOOT_GDT_OFFSET,
            dbs_boot::layout::BOOT_IDT_OFFSET,
        )
        .unwrap();

        vm.vcpus.push(vcpu);
        id += 1;
    }
}

fn vcpu_run(vcpu: &VcpuFd, device_mgr: &Arc<Mutex<IoManager>>) {
    loop {
        match vcpu.run() {
            Ok(exit_reason) => {
                match exit_reason {
                    VcpuExit::Hlt => {
                        println!("VcpuExit Hlt");
                        break;
                    }
                    VcpuExit::MmioRead(addr, data) => {
                        device_mgr.lock().unwrap().mmio_read(addr, data).unwrap();
                    }
                    VcpuExit::MmioWrite(addr, data) => {
                        device_mgr.lock().unwrap().mmio_write(addr, data).unwrap();
                    }
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
}

fn main() {
    let kvm = Kvm::new().expect("open kvm device failed");
    let vm_fd = kvm.create_vm().expect("create vm failed");

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

    let device_mgr = Arc::new(Mutex::new(IoManager::new()));

    let mut vm = VM {
        kvm: kvm,
        fd: vm_fd,
        guest_mem: guest_mem,
        device_mgr: device_mgr,
        vcpus: Vec::new(),
    };

    unsafe {
        vm.fd
            .set_user_memory_region(mem_region)
            .expect("set user memory region failed")
    };

    vm.fd
        .set_tss_address(dbs_boot::layout::KVM_TSS_ADDRESS as usize)
        .unwrap();

    // initialize irq chip and pit
    vm.fd.create_irq_chip().unwrap();
    let pit_config = kvm_pit_config {
        flags: KVM_PIT_SPEAKER_DUMMY,
        ..Default::default()
    };
    vm.fd.create_pit2(pit_config).unwrap();

    // create vcpu and set cpuid
    // let vcpu = vm.fd.create_vcpu(0).expect("create vcpu failed");
    // let base_cpuid = vm.kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES).unwrap();
    // let mut cpuid = base_cpuid.clone();
    // let cpuid_vm_spec =
    //     VmSpec::new(0, 1, 1, 1, 1, VpmuFeatureLevel::Disabled).expect("Error creating vm_spec");
    // dbs_arch::cpuid::process_cpuid(&mut cpuid, &cpuid_vm_spec).unwrap();
    // vcpu.set_cpuid2(&cpuid).unwrap();
    create_vcpus(&mut vm);

    mptable::setup_mptable(&vm.guest_mem, CPU_NUM, CPU_NUM).unwrap();

    let himem_start = GuestAddress(dbs_boot::layout::HIMEM_START);

    // load linux kernel
    let mut kernel_file = std::fs::File::open(KERNEL_PATH).expect("open kernel file failed");
    let kernel_entry = linux_loader::loader::elf::Elf::load(
        &vm.guest_mem,
        None,
        &mut kernel_file,
        Some(himem_start),
    )
    .unwrap()
    .kernel_load;

    let mut initrd_file = std::fs::File::open(INITRD_PATH).expect("open initrd file failed");
    let initrd_size = match initrd_file.seek(SeekFrom::End(0)) {
        Ok(size) => size as usize,
        Err(e) => panic!("initramfs file seek to end failed: {:?}", e),
    };
    initrd_file.seek(SeekFrom::Start(0)).unwrap();
    // Get the target address
    let initrd_address = dbs_boot::initrd_load_addr(&vm.guest_mem, initrd_size as u64).unwrap();
    // Load the image into memory
    vm.guest_mem
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
        &vm.guest_mem,
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

    let last_addr = vm.guest_mem.last_addr();
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
        &vm.guest_mem,
    )
    .unwrap();

    for vcpu in &vm.vcpus {
        dbs_arch::regs::setup_regs(
            vcpu,
            kernel_entry.raw_value(),
            dbs_boot::layout::BOOT_STACK_POINTER,
            dbs_boot::layout::BOOT_STACK_POINTER,
            dbs_boot::layout::ZERO_PAGE_START,
        )
        .unwrap();
    }

    let com_evt = EventFd::new(EFD_NONBLOCK).unwrap();
    // 必须添加register_irqfd，否则无法输入，COM1的gsi为4
    vm.fd.register_irqfd(&com_evt, 4).unwrap();
    let stdio_serial = Arc::new(Mutex::new(SerialDevice::new(com_evt.try_clone().unwrap())));
    stdio_serial
        .lock()
        .unwrap()
        .set_output_stream(Some(Box::new(std::io::stdout())));

    let resources = [Resource::PioAddressRange {
        base: COM,
        size: 0x8,
    }];
    vm.device_mgr
        .lock()
        .unwrap()
        .register_device_io(stdio_serial.clone(), &resources)
        .unwrap();

    let handler = ConsoleEpollHandler {
        device: stdio_serial,
        stdin_handle: std::io::stdin(),
    };

    let event_manager = EpollManager::default();
    event_manager.add_subscriber(Box::new(handler));

    let mut block_files: Vec<Box<dyn Ufile>> = vec![];
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(BLOCK_PATH)
        .unwrap();
    let io_engine = Aio::new(file.as_raw_fd(), 128).unwrap();
    block_files.push(Box::new(LocalFile::new(file, false, io_engine).unwrap()));
    let blk_device: DbsVirtioDevice = Box::new(
        BlockDevice::new(
            block_files,
            true,
            Arc::new(vec![128]),
            event_manager.clone(),
            vec![],
        )
        .unwrap(),
    );

    let vm_fd = Arc::new(vm.fd);
    let irq_mgr = Arc::new(KvmIrqManager::new(vm_fd.clone()));
    {
        // let use_shared_irq = false;
        // let use_generic_irq = true;

        let features = DRAGONBALL_FEATURE_INTR_USED | DRAGONBALL_FEATURE_PER_QUEUE_NOTIFY;
        // Every emulated Virtio MMIO device needs a 4K configuration space,
        // and another 4K space for per queue notification.
        // const MMIO_ADDRESS_DEFAULT: ResourceConstraint = ResourceConstraint::MmioAddress {
        //     range: None,
        //     align: 0,
        //     size: MMIO_DEFAULT_CFG_SIZE + DRAGONBALL_MMIO_DOORBELL_SIZE,
        // };

        // let mut requests = vec![MMIO_ADDRESS_DEFAULT];
        // blk_device.get_resource_requirements(&mut requests, use_generic_irq);

        let mut resources = DeviceResources::new();
        let mmio_resource = Resource::MmioAddressRange {
            base: 0xc0000000,
            size: 0x2000,
        };
        resources.append(mmio_resource);
        let irq_resource = Resource::LegacyIrq(6);
        resources.append(irq_resource);
        let msi_resource = Resource::MsiIrq {
            ty: GenericMsi,
            base: 0x18,
            size: 2,
        };
        resources.append(msi_resource);
        let virtio_dev = match MmioV2Device::new(
            vm_fd.clone(),
            GuestMemoryAtomic::new(vm.guest_mem.clone()),
            irq_mgr.clone(),
            blk_device,
            resources.clone(),
            Some(features),
        ) {
            Ok(d) => Arc::new(d),
            Err(e) => {
                println!("{}", e);
                return;
            }
        };
        vm.device_mgr
            .lock()
            .unwrap()
            .register_device_io(virtio_dev, &resources)
            .unwrap();
    }

    let mut handlers = Vec::new();
    for (id, vcpu) in vm.vcpus.drain(..).enumerate() {
        let device_mgr_clone = vm.device_mgr.clone();
        let handler = std::thread::Builder::new()
            .name(format!("vcpu_{}", id))
            .spawn(move || {
                vcpu_run(&vcpu, &device_mgr_clone);
            })
            .unwrap();
        handlers.push(handler);
    }
    // println!("============vcpus:{}", vm.vcpus.len());

    loop {
        match event_manager.handle_events(-1) {
            Ok(_) => (),
            Err(e) => {
                eprintln!("Failed to handle events: {e:?}");
                break;
            }
        }
    }
    for handler in handlers {
        handler.join().unwrap();
    }
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

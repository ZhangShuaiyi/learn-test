use std::fs::OpenOptions;
use std::os::fd::IntoRawFd;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;

use anyhow::{anyhow, Context, Result};

use log::info;

use vmm_sys_util::eventfd::EventFd;

use crossbeam_channel::{unbounded, Receiver, Sender};
use dbs_utils::net::MacAddr;
use dragonball::api::v1::{
    BootSourceConfig, FsDeviceConfigInfo, FsMountConfigInfo, InstanceInfo, MemDeviceConfigInfo,
    VcpuResizeInfo, VirtioNetDeviceConfigInfo, VmmAction, VmmRequest, VmmResponse, VmmService,
    VsockDeviceConfigInfo,
};
use dragonball::vm::VmConfigInfo;
use dragonball::Vmm;

use slog::Drain;

const KVM_DEVICE: &str = "/dev/kvm";
const DRAGONBALL_VERSION: &str = "0.1.0";

fn main() {
    // RUST_LOG=debug ./target/debug/footest
    env_logger::init();
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::CompactFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();

    let log = slog::Logger::root(drain, slog::o!());
    let _guard = slog_scope::set_global_logger(log);

    let id: &str = "123456";
    let kvm = OpenOptions::new()
        .read(true)
        .write(true)
        .open(KVM_DEVICE)
        .unwrap();
    info!("{:?}", kvm);

    let seccomp = vec![];
    let vmm_shared_info = Arc::new(RwLock::new(InstanceInfo::new(
        String::from(id),
        DRAGONBALL_VERSION.to_string(),
    )));

    let to_vmm_fd = EventFd::new(libc::EFD_NONBLOCK)
        .unwrap_or_else(|_| panic!("Failed to create eventfd for vmm"));
    let api_event_fd2 = to_vmm_fd.try_clone().expect("Failed to dup eventfd");

    let (to_vmm, from_runtime) = unbounded();
    let (to_runtime, from_vmm) = unbounded();

    let vmm_service = VmmService::new(from_runtime, to_runtime);

    let to_vmm: Option<Sender<VmmRequest>> = Some(to_vmm);
    let from_vmm: Option<Receiver<VmmResponse>> = Some(from_vmm);

    info!("before Vmm::new");
    let vmm = Vmm::new(
        vmm_shared_info,
        api_event_fd2,
        seccomp.clone(),
        seccomp.clone(),
        Some(kvm.into_raw_fd()),
    )
    .expect("Failed to start vmm");

    info!("{:?} {:?}", to_vmm, from_vmm);

    let vmm_thread = thread::Builder::new()
        .name("vmm_master".to_owned())
        .spawn(move || {
            || -> Result<i32> {
                let exit_code = Vmm::run_vmm_event_loop(Arc::new(Mutex::new(vmm)), vmm_service);
                Ok(exit_code)
            }()
            .unwrap();
        })
        .expect("Failed to start vmm event loop");
    info!("{:?}", vmm_thread);

    let vm_config = VmConfigInfo {
        // connect unix socket console
        // socat "stdin,raw,echo=0,escape=0x1b" UNIX-CONNECT:/tmp/console.sock
        serial_path: Some(String::from("/tmp/console.sock")),
        mem_size_mib: 512,
        vcpu_count: 1,
        max_vcpu_count: 4,
        mem_type: String::from("shmem"),
        mem_file_path: String::from(""),
        ..Default::default()
    };
    info!("{:?}", vm_config);

    let action = VmmAction::SetVmConfiguration(vm_config);
    handle_request(&to_vmm, &from_vmm, &to_vmm_fd, action);

    let config = BootSourceConfig {
        kernel_path: String::from(
            "/opt/kata/share/kata-containers/vmlinux-dragonball-experimental.container",
        ),
        initrd_path: Some(String::from("/root/datas/centos-no-kernel-initramfs.img")),
        boot_args: Some(String::from(
            "console=ttyS0 reboot=k earlyprintk=ttyS0 initcall_debug panic=1 pci=off apic=debug",
        )),
    };
    let action = VmmAction::ConfigureBootSource(config);
    handle_request(&to_vmm, &from_vmm, &to_vmm_fd, action);

    let iface_cfg = VirtioNetDeviceConfigInfo {
        iface_id: String::from("eth10"),
        host_dev_name: String::from("tap10_kata"),
        guest_mac: MacAddr::from_bytes(&[0xfa, 0xa5, 0xba, 0x70, 0x69, 0x60]).ok(),
        use_shared_irq: Some(false),
        ..Default::default()
    };
    let action = VmmAction::InsertNetworkDevice(iface_cfg);
    handle_request(&to_vmm, &from_vmm, &to_vmm_fd, action);

    // In guest mount command
    // mkdir -p /mnt && mount -t virtiofs testShare /mnt
    let fs_cfg = FsDeviceConfigInfo {
        sock_path: String::from("/tmp/virtiofsd.sock"),
        tag: String::from("testShare"),
        num_queues: 1 as usize,
        queue_size: 1024 as u16,
        cache_size: 0 as u64,
        xattr: true,
        mode: String::from("virtio"),
        cache_policy: String::from("auto"),
        fuse_killpriv_v2: true,
        thread_pool_size: 1,
        use_shared_irq: Some(false),
        ..Default::default()
    };
    let action = VmmAction::InsertFsDevice(fs_cfg);
    handle_request(&to_vmm, &from_vmm, &to_vmm_fd, action);

    let vsock_cfg = VsockDeviceConfigInfo {
        id: String::from("root"),
        guest_cid: 3,
        uds_path: Some(String::from("/tmp/hvsock.sock")),
        ..Default::default()
    };
    let action = VmmAction::InsertVsockDevice(vsock_cfg);
    handle_request(&to_vmm, &from_vmm, &to_vmm_fd, action);

    handle_request(&to_vmm, &from_vmm, &to_vmm_fd, VmmAction::StartMicroVm);
    handle_request(
        &to_vmm,
        &from_vmm,
        &to_vmm_fd,
        VmmAction::GetVmConfiguration,
    );

    // reference setup_inline_virtiofs, called in setup_device_after_start_vm.
    let mount_cfg = FsMountConfigInfo {
        ops: "mount".to_string(),
        fstype: Some("passthroughfs".to_string()),
        source: Some("/root/traces/kata-3.0".to_string()),
        mountpoint: "/passthrough".to_string(),
        config: None,
        tag: "testShare".to_string(),
        prefetch_list_path: None,
        dax_threshold_size_kb: None,
    };
    let action = VmmAction::ManipulateFsBackendFs(mount_cfg);
    handle_request(&to_vmm, &from_vmm, &to_vmm_fd, action);

    thread::sleep(std::time::Duration::from_secs(60));
    let resize_cfg = VcpuResizeInfo {
        vcpu_count: Some(2),
    };
    let action = VmmAction::ResizeVcpu(resize_cfg);
    handle_request(&to_vmm, &from_vmm, &to_vmm_fd, action);

    let mem_id = "abcdef".to_string();
    thread::sleep(std::time::Duration::from_secs(60));
    let mut mem_cfg = MemDeviceConfigInfo {
        mem_id: mem_id,
        size_mib: 1024,
        capacity_mib: 2048,
        multi_region: true,
        host_numa_node_id: None,
        guest_numa_node_id: None,
        use_generic_irq: None,
        use_shared_irq: Some(false),
    };
    let action = VmmAction::InsertMemDevice(mem_cfg.clone());
    handle_request(&to_vmm, &from_vmm, &to_vmm_fd, action);

    thread::sleep(std::time::Duration::from_secs(60));
    mem_cfg.size_mib = 2048;
    let action = VmmAction::InsertMemDevice(mem_cfg);
    handle_request(&to_vmm, &from_vmm, &to_vmm_fd, action);

    vmm_thread.join().unwrap();
}

fn handle_request(
    to_vmm: &Option<Sender<VmmRequest>>,
    from_vmm: &Option<Receiver<VmmResponse>>,
    to_vmm_fd: &EventFd,
    vmm_action: VmmAction,
) {
    match send_request(&to_vmm, &from_vmm, &to_vmm_fd, vmm_action) {
        Ok(vmm_outcome) => match *vmm_outcome {
            Ok(vmm_data) => Ok(vmm_data),
            Err(vmm_action_error) => Err(anyhow!("vmm action error: {:?}", vmm_action_error)),
        },
        Err(e) => Err(e),
    }
    .unwrap();
}

fn send_request(
    to_vmm: &Option<Sender<VmmRequest>>,
    from_vmm: &Option<Receiver<VmmResponse>>,
    to_vmm_fd: &EventFd,
    vmm_action: VmmAction,
) -> Result<VmmResponse> {
    if let Some(ref to_vmm) = to_vmm {
        to_vmm
            .send(Box::new(vmm_action.clone()))
            .with_context(|| format!("Failed to send  {:?} via channel ", vmm_action))?;
    } else {
        return Err(anyhow!("to_vmm is None"));
    }

    //notify vmm action
    if let Err(e) = to_vmm_fd.write(1) {
        return Err(anyhow!("failed to notify vmm: {}", e));
    }

    if let Some(from_vmm) = from_vmm.as_ref() {
        match from_vmm.recv() {
            Err(e) => Err(anyhow!("vmm recv err: {}", e)),
            Ok(vmm_outcome) => Ok(vmm_outcome),
        }
    } else {
        Err(anyhow!("from_vmm is None"))
    }
}

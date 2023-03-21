# kvm_io_bus
内核kvm结构体中包含kvm_io_bus字段
```
struct kvm {
    [2432] struct kvm_io_bus *buses[4];
}
```
编写bpftrace脚本查看运行./target/debug/dbs_load_kernel程序时kvm_io_bus_register_dev函数的调用情况
```
[root@shyi-centos8-1 rustvmm]# cat | BPFTRACE_STRLEN=144 bpftrace - <<EOF
kprobe:kvm_assign_ioeventfd_idx {
  printf("%d %s %s bus_idx:%d\n", pid, comm, func, (uint8)arg1);
}

kprobe:kvm_io_bus_register_dev {
  printf("%d %s %s bus_idx:%d addr:0x%lx len:%d\n", pid, comm, func, (uint8)arg1, (uint64)arg2, arg3);
}
EOF
Attaching 2 probes...
52483 dbs_load_kernel kvm_io_bus_register_dev bus_idx:1 addr:0x20 len:2
52483 dbs_load_kernel kvm_io_bus_register_dev bus_idx:1 addr:0xa0 len:2
52483 dbs_load_kernel kvm_io_bus_register_dev bus_idx:1 addr:0x4d0 len:2
52483 dbs_load_kernel kvm_io_bus_register_dev bus_idx:0 addr:0xfec00000 len:256
52483 dbs_load_kernel kvm_io_bus_register_dev bus_idx:1 addr:0x40 len:4
52483 dbs_load_kernel kvm_io_bus_register_dev bus_idx:1 addr:0x61 len:4
```
编写drgn程序查看kvm.buses
```python
from drgn.helpers.linux.list import list_for_each_entry

for kvm in list_for_each_entry("struct kvm", prog["vm_list"].address_of_(), "vm_list"):
    pid = kvm.userspace_pid
    print("=====>kvm userspace_pid:%d" % (pid.value_()))
    enum_bus = ["KVM_MMIO_BUS", "KVM_PIO_BUS", "KVM_VIRTIO_CCW_NOTIFY_BUS", "KVM_FAST_MMIO_BUS"]
    for i in range(4):
        print(f"===>kvm.buses[%d]: %s" % (i, enum_bus[i]))
        bus = kvm.buses[i]
        print(bus)
        for k in range(bus.dev_count.value_()):
            bus_range = bus.range[k]
            print(f"=>range[%d] addr:0x%x len:%d dev:" % (k, bus_range.addr.value_(), bus_range.len.value_()))
            print(bus_range.dev)
```
运行结果为
```
[root@shyi-centos8-1 rustvmm]# drgn drgn_vm_list.py
=====>kvm userspace_pid:52483
===>kvm.buses[0]: KVM_MMIO_BUS
*(struct kvm_io_bus *)0xffffa0488c7aa480 = {
        .dev_count = (int)1,
        .ioeventfd_count = (int)0,
        .range = (struct kvm_io_range []){},
}
=>range[0] addr:0xfec00000 len:256 dev:
*(struct kvm_io_device *)0xffffa048854cd998 = {
        .ops = (const struct kvm_io_device_ops *)ioapic_mmio_ops+0x0 = 0xffffffffc0bf37d0,
}
===>kvm.buses[1]: KVM_PIO_BUS
*(struct kvm_io_bus *)0xffffa04ab840d380 = {
        .dev_count = (int)5,
        .ioeventfd_count = (int)0,
        .range = (struct kvm_io_range []){},
}
=>range[0] addr:0x20 len:2 dev:
*(struct kvm_io_device *)0xffffa04ab763e760 = {
        .ops = (const struct kvm_io_device_ops *)picdev_master_ops+0x0 = 0xffffffffc0bf36a0,
}
=>range[1] addr:0x40 len:4 dev:
*(struct kvm_io_device *)0xffffa04aa8902000 = {
        .ops = (const struct kvm_io_device_ops *)pit_dev_ops+0x0 = 0xffffffffc0bf37b0,
}
=>range[2] addr:0x61 len:4 dev:
*(struct kvm_io_device *)0xffffa04aa8902008 = {
        .ops = (const struct kvm_io_device_ops *)speaker_dev_ops+0x0 = 0xffffffffc0bf3790,
}
=>range[3] addr:0xa0 len:2 dev:
*(struct kvm_io_device *)0xffffa04ab763e768 = {
        .ops = (const struct kvm_io_device_ops *)picdev_slave_ops+0x0 = 0xffffffffc0bf3680,
}
=>range[4] addr:0x4d0 len:2 dev:
*(struct kvm_io_device *)0xffffa04ab763e770 = {
        .ops = (const struct kvm_io_device_ops *)picdev_eclr_ops+0x0 = 0xffffffffc0bf3660,
}
===>kvm.buses[2]: KVM_VIRTIO_CCW_NOTIFY_BUS
*(struct kvm_io_bus *)0xffffa04aa6025d98 = {
        .dev_count = (int)0,
        .ioeventfd_count = (int)0,
        .range = (struct kvm_io_range []){},
}
===>kvm.buses[3]: KVM_FAST_MMIO_BUS
*(struct kvm_io_bus *)0xffffa04aa6025ef0 = {
        .dev_count = (int)0,
        .ioeventfd_count = (int)0,
        .range = (struct kvm_io_range []){},
}
```
+ 测试程序没有为serial的0x3f8端口注册ioeventfd

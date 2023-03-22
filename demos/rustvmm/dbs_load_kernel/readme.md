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
[root@shyi-centos8-1 rustvmm]# drgn drgn_vm_io_bus_list.py
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

# irq

## noapic
在cmd中配置"noapic"后，Guest中查看/proc/interrupts
```
:/# cat /proc/interrupts
           CPU0
  0:         50    XT-PIC      timer
  2:          0    XT-PIC      cascade
  4:        257    XT-PIC      ttyS0
NMI:          0   Non-maskable interrupts
LOC:       1813   Local timer interrupts
SPU:          0   Spurious interrupts
PMI:          0   Performance monitoring interrupts
IWI:          0   IRQ work interrupts
RTR:          0   APIC ICR read retries
RES:          0   Rescheduling interrupts
CAL:          0   Function call interrupts
TLB:          0   TLB shootdowns
TRM:          0   Thermal event interrupts
HYP:          0   Hypervisor callback interrupts
ERR:          0
MIS:          0
PIN:          0   Posted-interrupt notification event
NPI:          0   Nested posted-interrupt event
PIW:          0   Posted-interrupt wakeup event
```
编写drgn脚本
```python
from drgn.helpers.linux.list import list_for_each_entry, hlist_for_each_entry

for kvm in list_for_each_entry("struct kvm", prog["vm_list"].address_of_(), "vm_list"):
    pid = kvm.userspace_pid
    print("=====>kvm userspace_pid:%d" % (pid.value_()))
    print("==>irqfds:")
    for irqfd in list_for_each_entry("struct kvm_kernel_irqfd", kvm.irqfds.items.address_of_(), "list"):
        print("=>kvm_kernel_irqfd gsi:%d inject.func:%s" % (irqfd.gsi.value_(), irqfd.inject.func))
        # print(irqfd.inject)
    irq_routing = kvm.irq_routing
    print("==>irq_routing nr_rt_entries:%d" % (irq_routing.nr_rt_entries.value_()))
    for i in range(3):
        print(irq_routing.chip[i])
    # print(kvm.arch.vpic.pics[0])
    # print(kvm.arch.vpic.pics[1])
    # ttyS0的irq=4
    gsi = 4
    print("=>gsi:%d" % (gsi))
    for e in hlist_for_each_entry("struct kvm_kernel_irq_routing_entry", irq_routing.map[gsi].address_of_(), "link"):
        print("type:", e.type.value_(), "set:", e.set)
    # for i in range(irq_routing.nr_rt_entries.value_()):
    #     print("=>gsi:%d" % (i))
    #     for e in hlist_for_each_entry("struct kvm_kernel_irq_routing_entry", irq_routing.map[i].address_of_(), "link"):
    #         print("type:", e.type.value_(), "set:", e.set)
```
执行结果
```
=====>kvm userspace_pid:355196
==>irqfds:
=>kvm_kernel_irqfd gsi:4 inject.func:(work_func_t)irqfd_inject+0x0 = 0xffffffffc0b9d150
==>irq_routing nr_rt_entries:24
(int [24]){ 0, 1, 2, 3, 4, 5, 6, 7, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 }
(int [24]){ -1, -1, -1, -1, -1, -1, -1, -1, 8, 9, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1 }
(int [24]){ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23 }
=>gsi:4
type: 1 set: (int (*)(struct kvm_kernel_irq_routing_entry *, struct kvm *, int, int, bool))kvm_set_pic_irq+0x0 = 0xffffffffc0bcc430
type: 1 set: (int (*)(struct kvm_kernel_irq_routing_entry *, struct kvm *, int, int, bool))kvm_set_ioapic_irq+0x0 = 0xffffffffc0bcc410
```
对于Guest中禁用apic的场景，在host上通过perf查看kvm的irq注入事件
```
perf record -e kvm:kvm_set_irq -e kvm:kvm_pic_set_irq -e kvm:kvm_ioapic_set_irq -e kvm:kvm_apic_accept_irq -e kvm:kvm_inj_virq
```
通过perf script查看事件，其中vector 236为LOCAL_TIMER_VECTOR，定义为"#define LOCAL_TIMER_VECTOR             0xec"
```
[root@shyi-centos8-1 rustvmm]# perf script
 dbs_load_kernel 426566 [004] 108229.766087: kvm:kvm_apic_accept_irq: apicid 0 vec 236 (Fixed|edge)
 dbs_load_kernel 426566 [003] 108229.798142: kvm:kvm_apic_accept_irq: apicid 0 vec 236 (Fixed|edge)
 kworker/5:2-eve 429543 [005] 108229.924107:         kvm:kvm_set_irq: gsi 4 level 1 source 0
 kworker/5:2-eve 429543 [005] 108229.924116:  kvm:kvm_ioapic_set_irq: pin 4 dst 0 vec 0 (Fixed|physical|edge|masked)
 kworker/5:2-eve 429543 [005] 108229.924118:     kvm:kvm_pic_set_irq: chip 0 pin 4 (edge)
 kworker/5:2-eve 429543 [005] 108229.924136:         kvm:kvm_set_irq: gsi 4 level 0 source 0
 kworker/5:2-eve 429543 [005] 108229.924137:  kvm:kvm_ioapic_set_irq: pin 4 dst 0 vec 0 (Fixed|physical|edge|masked)
 kworker/5:2-eve 429543 [005] 108229.924138:     kvm:kvm_pic_set_irq: chip 0 pin 4 (edge)
 dbs_load_kernel 426566 [003] 108229.924216:        kvm:kvm_inj_virq: irq 52
 dbs_load_kernel 426566 [003] 108229.924258:        kvm:kvm_inj_virq: irq 52
 dbs_load_kernel 426566 [003] 108229.926039: kvm:kvm_apic_accept_irq: apicid 0 vec 236 (Fixed|edge)
 kworker/3:2-mm_ 420821 [003] 108229.926253:         kvm:kvm_set_irq: gsi 4 level 1 source 0
 kworker/3:2-mm_ 420821 [003] 108229.926257:  kvm:kvm_ioapic_set_irq: pin 4 dst 0 vec 0 (Fixed|physical|edge|masked)
 kworker/3:2-mm_ 420821 [003] 108229.926259:     kvm:kvm_pic_set_irq: chip 0 pin 4 (edge)
 kworker/3:2-mm_ 420821 [003] 108229.926265:         kvm:kvm_set_irq: gsi 4 level 0 source 0
 kworker/3:2-mm_ 420821 [003] 108229.926266:  kvm:kvm_ioapic_set_irq: pin 4 dst 0 vec 0 (Fixed|physical|edge|masked)
 kworker/3:2-mm_ 420821 [003] 108229.926267:     kvm:kvm_pic_set_irq: chip 0 pin 4 (edge)
 dbs_load_kernel 426566 [003] 108229.926281:        kvm:kvm_inj_virq: irq 52
 dbs_load_kernel 426566 [003] 108229.926289:        kvm:kvm_inj_virq: irq 52
 ...
```
+ gsi 4对应vector 52
对于pic设备，pin与vector的偏移记录在kvm_kpic_state.irq_base中，编写drgn脚本查看vpic中pic0和pic1的irq_base
```python
from drgn.helpers.linux.list import list_for_each_entry, hlist_for_each_entry

for kvm in list_for_each_entry("struct kvm", prog["vm_list"].address_of_(), "vm_list"):
    pid = kvm.userspace_pid
    print("=====>kvm userspace_pid:%d" % (pid.value_()))
    for i in range(2):
        print("pic[%d] irq_base:%d" % (i, kvm.arch.vpic.pics[i].irq_base.value_())) 
```
运行结果为
```
[root@shyi-centos8-1 rustvmm]# drgn drgn_vm_pic_state.py
=====>kvm userspace_pid:426561
pic[0] irq_base:48
pic[1] irq_base:56
```
+ pic0的vector偏移为48，gsi 4对应的vector=4+48=52

## apic
取消内核cmdline中的"noapic"参数，hypervisor启动后在Guest中查看/proc/interrupts内容为
```
:/# cat /proc/interrupts
           CPU0
  0:         55   IO-APIC   0-edge      timer
  2:          0    XT-PIC      cascade
  4:        166   IO-APIC   4-edge      ttyS0
NMI:          0   Non-maskable interrupts
LOC:       1669   Local timer interrupts
SPU:          0   Spurious interrupts
PMI:          0   Performance monitoring interrupts
IWI:          0   IRQ work interrupts
RTR:          0   APIC ICR read retries
RES:          0   Rescheduling interrupts
CAL:          0   Function call interrupts
TLB:          0   TLB shootdowns
TRM:          0   Thermal event interrupts
HYP:          0   Hypervisor callback interrupts
ERR:          0
MIS:          0
PIN:          0   Posted-interrupt notification event
NPI:          0   Nested posted-interrupt event
PIW:          0   Posted-interrupt wakeup event
```
在host中通过perf查看kvm的irq相关事件
```
perf record -e kvm:kvm_set_irq -e kvm:kvm_pic_set_irq -e kvm:kvm_ioapic_set_irq -e kvm:kvm_apic_accept_irq -e kvm:kvm_inj_virq
```
perf script查看结果为
```
 dbs_load_kernel 448058 [000] 113108.495865: kvm:kvm_apic_accept_irq: apicid 0 vec 236 (Fixed|edge)
 dbs_load_kernel 448058 [000] 113108.559888: kvm:kvm_apic_accept_irq: apicid 0 vec 236 (Fixed|edge)
 kworker/3:1-eve 443349 [003] 113108.708681:         kvm:kvm_set_irq: gsi 4 level 1 source 0
 kworker/3:1-eve 443349 [003] 113108.708721: kvm:kvm_apic_accept_irq: apicid 0 vec 33 (Fixed|edge)
 kworker/3:1-eve 443349 [003] 113108.708737:  kvm:kvm_ioapic_set_irq: pin 4 dst 0 vec 33 (Fixed|physical|edge)
 kworker/3:1-eve 443349 [003] 113108.708740:     kvm:kvm_pic_set_irq: chip 0 pin 4 (edge|masked)
 kworker/3:1-eve 443349 [003] 113108.708741:         kvm:kvm_set_irq: gsi 4 level 0 source 0
 kworker/3:1-eve 443349 [003] 113108.708743:  kvm:kvm_ioapic_set_irq: pin 4 dst 0 vec 33 (Fixed|physical|edge)
 kworker/3:1-eve 443349 [003] 113108.708743:     kvm:kvm_pic_set_irq: chip 0 pin 4 (edge|masked)
 kworker/0:2-eve 437357 [000] 113108.711751:         kvm:kvm_set_irq: gsi 4 level 1 source 0
 kworker/0:2-eve 437357 [000] 113108.711758: kvm:kvm_apic_accept_irq: apicid 0 vec 33 (Fixed|edge)
 kworker/0:2-eve 437357 [000] 113108.711765:  kvm:kvm_ioapic_set_irq: pin 4 dst 0 vec 33 (Fixed|physical|edge)
 kworker/0:2-eve 437357 [000] 113108.711767:     kvm:kvm_pic_set_irq: chip 0 pin 4 (edge|masked)
 kworker/0:2-eve 437357 [000] 113108.711768:         kvm:kvm_set_irq: gsi 4 level 0 source 0
 kworker/0:2-eve 437357 [000] 113108.711769:  kvm:kvm_ioapic_set_irq: pin 4 dst 0 vec 33 (Fixed|physical|edge)
 kworker/0:2-eve 437357 [000] 113108.711770:     kvm:kvm_pic_set_irq: chip 0 pin 4 (edge|masked)
 dbs_load_kernel 448058 [000] 113108.815849: kvm:kvm_apic_accept_irq: apicid 0 vec 236 (Fixed|edge)
 ...
```
+ gsi对应vector 33
查看 **__apic_accept_irq** 函数的调用栈
```
[root@shyi-centos8-1 rustvmm]# cat | BPFTRACE_STRLEN=144 bpftrace - <<EOF
kprobe:__apic_accept_irq /arg2 != 236/ {
  printf("%d %s %s vector:%d level:%d\n", pid, comm, func, arg2, arg3);
  printf("%s", kstack(perf));
}
EOF
Attaching 1 probe...
437357 kworker/0:2 __apic_accept_irq vector:33 level:1

        ffffffffc0bc6cd1 __apic_accept_irq+1
        ffffffffc0bc7480 kvm_irq_delivery_to_apic_fast+496
        ffffffffc0bcc594 kvm_irq_delivery_to_apic+52
        ffffffffc0bcb1fc ioapic_service+268
        ffffffffc0bcb5f3 ioapic_set_irq+195
        ffffffffc0bcbd51 kvm_ioapic_set_irq+97
        ffffffffc0b9e910 kvm_set_irq+160
        ffffffffc0b9d191 irqfd_inject+65
        ffffffffa00f256a process_one_work+426
        ffffffffa00f2c10 worker_thread+48
        ffffffffa00f8516 kthread+278
        ffffffffa000436f ret_from_fork+31
448998 kworker/3:2 __apic_accept_irq vector:33 level:1

        ffffffffc0bc6cd1 __apic_accept_irq+1
        ffffffffc0bc7480 kvm_irq_delivery_to_apic_fast+496
        ffffffffc0bcc594 kvm_irq_delivery_to_apic+52
        ffffffffc0bcb1fc ioapic_service+268
        ffffffffc0bcb5f3 ioapic_set_irq+195
        ffffffffc0bcbd51 kvm_ioapic_set_irq+97
        ffffffffc0b9e910 kvm_set_irq+160
        ffffffffc0b9d191 irqfd_inject+65
        ffffffffa00f256a process_one_work+426
        ffffffffa00f2c10 worker_thread+48
        ffffffffa00f8516 kthread+278
        ffffffffa000436f ret_from_fork+31
```
编写drgn脚本查看kvm.arch.vioapic的内容
```python
from drgn.helpers.linux.list import list_for_each_entry

for kvm in list_for_each_entry("struct kvm", prog["vm_list"].address_of_(), "vm_list"):
    pid = kvm.userspace_pid
    print("=====>kvm userspace_pid:%d" % (pid.value_()))
    vioapic = kvm.arch.vioapic
    print("vioapic base_address:0x%lx" % (vioapic.base_address.value_()))
    print(vioapic.dev)
    for i in range(24):
        entry = vioapic.redirtbl[i]
        print("===>gsi(%d) vector:%d dest_id:%d" % 
            (i, entry.fields.vector.value_(), entry.fields.dest_id.value_()))
```
drgn脚本输出为
```
[root@shyi-centos8-1 rustvmm]# drgn drgn_kvm_vioapic_list.py
=====>kvm userspace_pid:448058
(struct kvm_io_device){
        .ops = (const struct kvm_io_device_ops *)ioapic_mmio_ops+0x0 = 0xffffffffc0bf37d0,
}
===>gsi(0) vector:48 dest_id:0
===>gsi(1) vector:0 dest_id:0
===>gsi(2) vector:0 dest_id:0
===>gsi(3) vector:0 dest_id:0
===>gsi(4) vector:33 dest_id:0
===>gsi(5) vector:0 dest_id:0
===>gsi(6) vector:0 dest_id:0
===>gsi(7) vector:0 dest_id:0
===>gsi(8) vector:0 dest_id:0
===>gsi(9) vector:0 dest_id:0
===>gsi(10) vector:0 dest_id:0
===>gsi(11) vector:0 dest_id:0
===>gsi(12) vector:0 dest_id:0
===>gsi(13) vector:0 dest_id:0
===>gsi(14) vector:0 dest_id:0
===>gsi(15) vector:0 dest_id:0
===>gsi(16) vector:0 dest_id:0
===>gsi(17) vector:0 dest_id:0
===>gsi(18) vector:0 dest_id:0
===>gsi(19) vector:0 dest_id:0
===>gsi(20) vector:0 dest_id:0
===>gsi(21) vector:0 dest_id:0
===>gsi(22) vector:0 dest_id:0
===>gsi(23) vector:0 dest_id:0
```
+ 在kvm.arch.vioapic.redirtbl中记录了gsi对应的dest_id(目的cpu)和vector
+ Guest中通过mmio write配置ioapic的 IOREDTBL

## 1. virsh qemu-monitor-command
virsh qemu-monitor-command命令可向qemu-kvm进程发送monitor指令，以info pci命令为例，使用strace可查看libvirtd进程向qemu-kvm进程发送的qemu-monitor命令。
+ strace绑定到libvirtd进程
```
# strace -s 256 -f -p `pgrep libvirtd` -o strace_libvirtd_info_pci.txt
```
+ virsh qemu-monitor-command命令
```
# virsh qemu-monitor-command centos7 --hmp info pci
```
+ strace获取到的数据
```
write(26, "{\"execute\":\"human-monitor-command\",\"arguments\":{\"command-line\":\"info pci\"},\"id\":\"libvirt-19\"}\r\n", 95) = 95
```

## 2. qemu monitor代码分析
+ 在qmp-commands.hx可查看到human-monitor-command命令对应的函数为qmp_marshal_human_monitor_command。
+ 在qmp_human_monitor_command函数中调用handle_hmp_command函数，在handle_hmp_command中调用monitor_parse_command命令解析command，使用mon->cmd_table参数。
+ mon->cmd_table = mon_cmds;而mon_cmds的定义为
```c
static mon_cmd_t mon_cmds[] = {
#include "hmp-commands.h"
    { NULL, NULL, },
};
```
+ 在x86_64-softmmu/hmp-commands.h中info指令相关定义
```c
{
.name       = "info",
.args_type  = "item:s?",
.params     = "[subcommand]",
.help       = "show various information about the system state",
.mhandler.cmd = hmp_info_help,
.sub_table = info_cmds,
},
```
+ info_cmds定义
```
static mon_cmd_t info_cmds[] = {
#include "hmp-commands-info.h"
    { NULL, NULL, },
};
```
+ 在x86_64-softmmu/hmp-commands-info.h中info pci对应
```c
{
.name       = "pci",
.args_type  = "",
.params     = "",
.help       = "show PCI info",
.mhandler.cmd = hmp_info_pci,
},
```
+ monitor的info pci最终调用hmp_info_pci命令。

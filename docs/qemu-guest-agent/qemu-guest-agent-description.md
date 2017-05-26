## 1. qemu-guest-agent配置
+ 在虚拟机中安装qemu-guest-agent后，qemu-ga的配置文件为 **/etc/sysconfig/qemu-ga**，其中 **BLACKLIST_RPC** 指定了qemu-ga的 **--blacklist** 参数
+ qemu-ga输出debug进行调试，修改 **/lib/systemd/system/qemu-guest-agent.service** 文件，添加qemu-ga参数
```
   --logfile=/var/log/qemu-ga/qemu-ga.log \
   -v \
```
重启qemu-ga
```
# systemctl daemon-reload
# systemctl restart qemu-guest-agent.service
```

### 1.1 guest-exec
```
# virsh qemu-agent-command centos7 '{"execute":"guest-exec", "arguments": {"path":"ls", "arg": ["/root"], "capture-output": true}}'
{"return":{"pid":3184}}

# virsh qemu-agent-command centos7 '{"execute":"guest-exec-status", "arguments": {"pid":3184}}'
{"return":{"exitcode":0,"out-data":"YW5hY29uZGEta3MuY2ZnCg==","exited":true}}
```
+ 返回的out-data为base64数据
```
>>> import base64
>>> s = "YW5hY29uZGEta3MuY2ZnCg=="
>>> base64.b64decode(s)
'anaconda-ks.cfg\n'
```
+ guest-exec命令在qmp_guest_exec函数中调用g_spawn_async_with_pipes执行子程序。

## 2. qemu-guest-agent代码
qemu-guest-agent代码在qemu代码的qga目录中，在./configure时添加"--enable-guest-agent"编译qemu-guest-agent，qemu-guest-agent使用[qapi](https://github.com/qemu/qemu/blob/master/docs/qapi-code-gen.txt)生成代码，生成源码位于 **qga/qapi-generated/** 目录。

### 2.1 命令注册
在qga/qapi-generated/qga-qmp-marshal.c的qmp_init_marshal函数中调用 **qmp_register_command** 函数注册qemu-guest-aagent的命令，guest-info命令可查看QGA的信息
```
# virsh qemu-agent-command centos7 '{"execute":"guest-info"}'
```

### 2.2 struct QmpCommand
qga的命令对应静态全局变量 **static QTAILQ_HEAD(QmpCommandList, QmpCommand) qmp_commands** ，结构体QmpCommand的enabled参数表示该命令是否enable，有qemu-ga的blacklist参数控制。

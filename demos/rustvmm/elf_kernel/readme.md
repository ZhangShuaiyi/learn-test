# kernel和initrd
+ [vmlinux.bin](https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/kernels/vmlinux.bin)从网上下载
+ 也可使用kata带的vmlinux，部署kata带的vmlinux配置了pvh
+ initrd.img可通过[firecracker-initrd](https://github.com/marcov/firecracker-initrd.git)提供的脚本制作，如果下载慢的话可替换为国内源
```
diff --git a/container/build-initrd-in-ctr.sh b/container/build-initrd-in-ctr.sh
index 522eb60..e050c78 100755
--- a/container/build-initrd-in-ctr.sh
+++ b/container/build-initrd-in-ctr.sh
@@ -6,6 +6,8 @@

 set -euo pipefail

+sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories
+
 buildDir=/build
 rootfsDir=${buildDir}/rootfs
 keepRoot=
```
+ 也可通过dracut制作initramfs
```
dracut --no-compress --no-kernel --hostonly --install "/bin/lscpu /bin/free /bin/lsblk" /root/datas/centos-no-kernel-initramfs.img
```

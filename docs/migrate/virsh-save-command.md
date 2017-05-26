## 1. libvirtd流程
libvirtd从virsh接受传递过来的命令
```c
virNetServerProgramDispatch
-->remoteDispatchDomainSaveHelper
   -->virDomainSave
      -->qemuDomainSave <==>conn->driver->domainSave
         -->qemuDomainSaveFlags
            -->qemuDomainSaveInternal
               -->qemuDomainSaveMemory
                  -->virFileWrapperFdNew
                  -->qemuMigrationToFile
```
libvirtd打开要保存的文件，通过SCM_RIGHTS将fd通过monitor的getfd命令传递给qemu

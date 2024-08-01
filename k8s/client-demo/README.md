# 初始化

```shell
go get k8s.io/client-go@v0.28.6
go mod tidy
```

## 001-burstable-cpu-shares

+ 系统为cgroup v1
+ kubelet的/var/lib/kubelet/config.yaml中`cgroupDriver: systemd`
+ 查看node上burstable的总cpu.shares

```shell
[root@dev ~]# cat /sys/fs/cgroup/cpu/kubepods.slice/kubepods-burstable.slice/cpu.shares
481
[root@dev ~]# cat /sys/fs/cgroup/cpu/kubepods.slice/kubepods-burstable.slice/*/cpu.shares | awk '{ SUM += $1} END { print SUM }'
478
```

+ kubepods-burstable.slice/cpu.shares是根据该节点所有的burstable的cpu.shares计算的，为什么kubepods-burstable.slice/cpu.shares为481比下面的cpu.shares总和478大3？
+ 计算kubepods-burstable.slice/cpu.shares的代码为`setCPUCgroupConfig`

```go
func (m *qosContainerManagerImpl) setCPUCgroupConfig(configs map[v1.PodQOSClass]*CgroupConfig) error {
	pods := m.activePods()
	burstablePodCPURequest := int64(0)
	reuseReqs := make(v1.ResourceList, 4)
	for i := range pods {
		pod := pods[i]
		qosClass := v1qos.GetPodQOS(pod)
		if qosClass != v1.PodQOSBurstable {
			// we only care about the burstable qos tier
			continue
		}
		req := resource.PodRequests(pod, resource.PodResourcesOptions{Reuse: reuseReqs})
		if request, found := req[v1.ResourceCPU]; found {
			burstablePodCPURequest += request.MilliValue()
		}
	}

	// make sure best effort is always 2 shares
	bestEffortCPUShares := uint64(MinShares)
	configs[v1.PodQOSBestEffort].ResourceParameters.CPUShares = &bestEffortCPUShares

	// set burstable shares based on current observe state
	burstableCPUShares := MilliCPUToShares(burstablePodCPURequest)
	configs[v1.PodQOSBurstable].ResourceParameters.CPUShares = &burstableCPUShares
	return nil
}
```

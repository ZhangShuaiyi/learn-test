kubectl create -f 001-besteffort.yaml
sleep 600
kubectl create -f 002-burstable-500m.yaml
sleep 600
kubectl create -f 003-burstable-1c.yaml
sleep 600
kubectl create -f 004-guaranteed-5c.yaml

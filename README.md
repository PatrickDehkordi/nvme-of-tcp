# nvme-of-tcp

This provides a TCP transport for NVMe over fabrics. It is intended to offer performance close to RDMA without the complexity.

Configuration is similar to RDMA.

## Build

At present this is a fork of the v4.11 kernel. This adds two new kconfig options:

- `NVME_TCP` : enable initiator support
- `NVME_TARGET_TCP` : enable target support

The target requires the `nvmet` module to be loaded. Configuration is identical to RDMA, except `"tcp"` should be used for `addr_trtype`.

The host requires the `nvme`, `nvme_core` and `nvme_fabrics` modules to be loaded. Again, configuration is identical to RDMA, except `-t tcp` should be passed to the nvme command line utility instead of `-t rdma`. This requires a [patched version of nvme-cli](https://github.com/solarflarecommunications/nvme-cli/).

## Example

This is assuming a target IP of 10.0.0.1, a subsytem name of `ramdisk` and an underlying block device `/dev/ram0`.

### Target setup

Assuming modules are loaded
```
# Set up storage subsystem
mkdir /sys/kernel/config/nvmet/subsystems/ramdisk
echo 1 > /sys/kernel/config/nvmet/subsystems/ramdisk/attr_allow_any_host

mkdir /sys/kernel/config/nvmet/subsystems/ramdisk/namespaces/1
echo -n /dev/ram0 > /sys/kernel/config/nvmet/subsystems/ramdisk/namespaces/1/device_path
echo 1 > /sys/kernel/config/nvmet/subsystems/ramdisk/namespaces/1/enable

# Set up port
mkdir /sys/kernel/config/nvmet/ports/1
echo "ipv4" > /sys/kernel/config/nvmet/ports/1/addr_adrfam
echo "tcp" > /sys/kernel/config/nvmet/ports/1/addr_trtype
echo "11345" > /sys/kernel/config/nvmet/ports/1/addr_trsvcid
echo "10.0.0.1" > /sys/kernel/config/nvmet/ports/1/addr_traddr

# Associate subsystem with port
ln -s /sys/kernel/config/nvmet/subsystems/ramdisk /sys/kernel/config/nvmet/ports/1/subsystems/ramdisk
```

### Initiator setup
```
nvme connect -t tcp -a 10.0.0.1 -s 11345 -n ramdisk
```

`lsblk` should now show an NVMe device.


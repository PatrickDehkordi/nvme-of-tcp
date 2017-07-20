# nvme-of-tcp

This provides a TCP transport for NVMe over fabrics. It is intended to offer performance close to RDMA without the complexity.

Configuration is similar to RDMA.

### Notes

At present this is a fork of the v4.11 kernel. This adds two new kconfig options:

- `NVME_TCP` : enable initiator support
- `NVME_TARGET_TCP` : enable target support

The target requires the `nvmet` module to be loaded. Configuration is identical to RDMA, except `"tcp"` should be used for `addr_trtype`.

The host requires the `nvme`, `nvme_core` and `nvme_fabrics` modules to be loaded. Again, configuration is identical to RDMA, except `-t tcp` should be passed to the nvme command line utility instead of `-t rdma`. This requires a [patched version of nvme-cli](https://github.com/solarflarecommunications/nvme-cli/).

## Example

This is assuming a target IP of 10.0.0.1, a subsytem name of `ramdisk` and an underlying block device `/dev/ram0`.

## Building the Linux kernel

This is assuming an existing system with RedHat/Centos Distribution built on 3.x kernel. For more info refer to: https://kernelnewbies.org/KernelBuild

#### Install or confirm the following packages are installed:
yum install gcc make git ctags ncurses-devel openssl-devel

#### Download and unzip or clone the repo into a local directory:
git clone https://github.com/solarflarecommunications/nvme-of-tcp/tree/v4.11-nvme-of-tcp
cd nvme-of-tcp-4.11

#### Create a .config file or copy the existing .config file into the build direcotry:
scp /boot/config-3.10.0-327.el7.x86_64 .config

#### Modify the .config to include the relevant NVMe modules:
make menuconfig
Under "Block Devices" at a minimum select 
"NVM Express block device"
"NVMe over Fabrics TCP host support"
"NVMe over Fabrics TCP target support"
Save and Exit the text based kernel configuration utlity. 

#### Confirm the changes:
grep NVME_ .config

#### Compile and install the kernel. 
#### To save time you can utilize multiple cpus by including the j option:
make -j 16
make -j 16 modules_install install 

#### Confirm that the build is included in the boot menu entry.
#### This is depedent on the bootloader beign used, for GRUB2:
cat /boot/grub2/grub.cfg | grep menuentry

#### Set the build as the default boot option:
grub2-set-default 'Red Hat Enterprise Linux Server (4.11.0) 7.x (Maipo)’

### Reboot the system:
reboot

### Confirm that the kernel has been updated:
uname -a 
Linux host.name 4.11.0 #1 SMP date  x86_64 GNU/Linux

### Download the correct version of the NVMe cli utility that inlcudes TCP:
git clone https://github.com/solarflarecommunications/nvme-cli

### Update the NVMe cli utility:
cd nvme-cli
make
make install

## Target setup

#### Load the target driver, this should automatically load the dependencies "nvme", "nvme_core", and "nvme_fabrics"
```
modprobe nvmet_tcp
```
#### Set up storage subsystem
mkdir /sys/kernel/config/nvmet/subsystems/ramdisk
echo 1 > /sys/kernel/config/nvmet/subsystems/ramdisk/attr_allow_any_host

mkdir /sys/kernel/config/nvmet/subsystems/ramdisk/namespaces/1
echo -n /dev/ram0 > /sys/kernel/config/nvmet/subsystems/ramdisk/namespaces/1/device_path
echo 1 > /sys/kernel/config/nvmet/subsystems/ramdisk/namespaces/1/enable

#### Set up port
mkdir /sys/kernel/config/nvmet/ports/1
echo "ipv4" > /sys/kernel/config/nvmet/ports/1/addr_adrfam
echo "tcp" > /sys/kernel/config/nvmet/ports/1/addr_trtype
echo "11345" > /sys/kernel/config/nvmet/ports/1/addr_trsvcid
echo "10.0.0.1" > /sys/kernel/config/nvmet/ports/1/addr_traddr

#### Associate subsystem with port
```
ln -s /sys/kernel/config/nvmet/subsystems/ramdisk /sys/kernel/config/nvmet/ports/1/subsystems/ramdisk
```

## Initiator setup

#### Load the initiator driver, this should automatically load the dependencies "nvme", "nvme_core", and "nvme_fabrics":
```
modprobe nvme_tcp
```
#### Use the nvme cli utility to connect the initiator to the traget:
```
nvme connect -t tcp -a 10.0.0.1 -s 11345 -n ramdisk
```
`lsblk` should now show an NVMe device.


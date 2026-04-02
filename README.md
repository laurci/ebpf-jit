# ebpf-jit

A completely unhinged approach to eBPF packet filtering.

Instead of writing eBPF bytecode by hand or compiling a C program ahead of time like a normal person, this project JIT-compiles eBPF programs at runtime using LLVM (via inkwell). You give it a list of allowed IPs, it fires up an entire LLVM backend, emits a BPF ELF object into memory, and hot-loads it into the kernel as a TC classifier. It's a mass-produced industrial laser aimed at a paper target.

Could you just write a static eBPF filter? Yes. Could you use a BPF map? Obviously. Is dragging in LLVM to generate trivial packet filters at runtime justified in any universe? Absolutely not. But here we are.

## Prerequisites

1. stable rust toolchain: `rustup toolchain install stable`
1. LLVM 18.1 (for inkwell)

## Build & Run

```shell
cargo run --release
```

## Testing the filter

```shell
# Bridge
sudo ip link add test-br type bridge
sudo ip link set test-br up

# VM1 - the one we protect (filter on tap-test1 egress)
sudo ip netns add vm1
sudo ip link add tap-test1 type veth peer name eth0-vm1
sudo ip link set tap-test1 master test-br up
sudo ip link set eth0-vm1 netns vm1
sudo ip netns exec vm1 ip addr add 10.69.42.1/24 dev eth0-vm1
sudo ip netns exec vm1 ip link set eth0-vm1 up

# VM2 - allowed
sudo ip netns add vm2
sudo ip link add tap-test2 type veth peer name eth0-vm2
sudo ip link set tap-test2 master test-br up
sudo ip link set eth0-vm2 netns vm2
sudo ip netns exec vm2 ip addr add 10.69.42.2/24 dev eth0-vm2
sudo ip netns exec vm2 ip link set eth0-vm2 up

# VM3 - blocked
sudo ip netns add vm3
sudo ip link add tap-test3 type veth peer name eth0-vm3
sudo ip link set tap-test3 master test-br up
sudo ip link set eth0-vm3 netns vm3
sudo ip netns exec vm3 ip addr add 10.69.42.3/24 dev eth0-vm3
sudo ip netns exec vm3 ip link set eth0-vm3 up
```

```shell
# packets are accepted, minimal latency
sudo ip netns exec vm2 ping 10.69.42.1

# packets should be dropped
sudo ip netns exec vm3 ping 10.69.42.1
```

```shell
# remove tap device
sudo ip netns del vm1
sudo ip netns del vm2
sudo ip netns del vm3
sudo ip link del test-br
```

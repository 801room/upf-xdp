# upf-xdp
This program uses xdp to simply process gtpu packet.
<br>It is just a toy, but it shows the possibility of using xdp to implement 5g upf.
## Dependencies
[libbpf](https://github.com/libbpf/libbpf)
<br>[goebpf](https://github.com/dropbox/goebpf)

### Installation
```bash
sudo apt install libbpfcc-dev
go get github.com/dropbox/goebpf
```

## Component
![Component](./docs/Component.png)
## Usage
```
make
./main -h
   Usage of ./main:
     -elf string
        clang/llvm compiled binary file (default "upf.elf")
     -iface string
        Interface to bind XDP UPF N3/N6
     -n4addr string
        N4 server socket (default "127.0.0.1:8805")
     -test
        mock and testing (default true)
     -verbose
        Enable verbose mode with debug log messages
```
## Discuss
Message routing can be forwarded directly through the xdp encapsulation layer 2 Ethernet frame without going through the protocol stack. 
<br>What is the number of tables supported by xdp?

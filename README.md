## P4 reference tools

### P4 reference compiler

`p4c` is a reference compiler for the P4 programming language. The compiler is modular: it provides a standard front-end
and mid-end which can be combined with a target-specific back-end to create a complete P4 compiler. The goal is to make
adding new back-ends easy.

In our particular case, we are interested in the `p4c-bm2-ss` back-end, which can be used to target the
P4 `simple_switch`(`_grpc`) written using `bmv2`.

### P4Runtime

The P4Runtime API is a control plane specification, defined via protobuf (.proto) files, for controlling the data plane
elements of a device or program defined by a P4 program. With the protoc compiler, the P4Runtime protobuf files can be
compiled to generate the protobuf and gRPC bindings for C++, Python, and Go.

### PI (?)

P4 PI is an implementation framework for a P4Runtime server that includes all the core code.

### Software switch

BMv2, or `bmv2`, is the second version of the reference P4 software switch, nicknamed `bmv2` (for behavioral model
version 2). The software switch is written in C++11. It takes as input a JSON file generated from your P4 program by a
P4 compiler and interprets it to implement the packet-processing behavior specified by that P4 program.  
There are several variations of the behavioral model, but `simple_switch_grpc` is the one we will be using.

## Host

Download and install Ubuntu 20.04.2.0 LTS for desktop from [here](https://ubuntu.com/download/desktop). During the
installation process, when prompted, make sure to select `Normal installation` (under `Updates and other software`), and
let Ubuntu download and install the latest updates.

## Installation

### `p4c` and `bmv2`

For convenience, we use an install script that installs `p4c` and the `bmv2` `simple_switch`, plus
the `simple_switch_grpc`, that can use the P4Runtime API protocol to communicate with a controller (in addition to the
older Thrift API). It also installs Mininet and a few other small packages necessary to run network functions. It uses
the latest versions of the Protobuf, Thrift, and gRPC libraries that are supported by the open source P4 development
tools.

Install the following dependencies:

```bash
$ sudo apt install -y git \
    python3-pip
```

Clone `p4-guide`, the GitHub repository that contains the installation script:

```bash
$ git clone https://github.com/jafingerhut/p4-guide.git p4-guide
```

Run the installation script

```bash
$ cd p4-guide/bin
$ ./install-p4dev-v4.sh
```

**WARNING**: this process took me 2h+.

When it completes, follow the instructions suggested by the script.

### Clone the repository

Finally, clone this repository, checkout to the branch `improved-controller`, and head to the `example/` directory.

```bash
$ git clone https://github.com/machadoatz/p4-nfs.git p4-nfs
$ cd p4-nfs
```

Build the example following [these instructions](example/README.md).

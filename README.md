## Installation


## Host

Download and install Ubuntu 20.04.2.0 LTS for desktop from [here](https://ubuntu.com/download/desktop). During the
installation process, when prompted, make sure to select `Normal installation` (under `Updates and other software`), and
let Ubuntu download and install the latest updates.


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

Clone this repository, checkout to the branch ``, and head to the `bridge/` directory.

```bash
$ git clone https://github.com/machadoatz/p4-debug-nfs.git
$ cd p4-nfs
```

### Run the Bridge.
(It might be necessary to adapt the environment variables used by the Makefile)

- In the bridge directory, compile the P4 program with `make compile`.
- Start the mininet topology and the simple switch with `make switch`.
- Run `make controller` to run the controller defined in `controller.py`.

The controller creates table entries for new flows and deletes them after 10 minute timeouts.

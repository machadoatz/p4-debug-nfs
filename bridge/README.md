# Network Function Example

## Introduction

This example sets the standard approach to configure any P4-16 network function for evaluation.

## To Do
- acrescentar mcast group para 255 cpuport.
- hdr.ethernet.src e dst estavam iguais e pacote era reencaminhado para o mesmo host?? 

### `git` warning

During development, you need to change the file mode of helper scripts to be able to run them. Upon altering their
modes, `git` marks these files as changed, which is an undesired behaviour. To force `git` to discard such changes, run

```bash
$ git config core.fileMode false
```

## Instructions

### Compile the P4 program

```bash
$ make [compile]
```

### Start the switch

```bash
$ make switch
```

### Start the controller

```bash
$ make controller
```

### Clean the environment

```bash
$ make clean
```
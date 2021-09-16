# Usage

## Build
```bash
$ make
```

## Install

Install blkdev module
Arguments
 - servaddr: server address
 - servport: server port
 - name: device name
 - sz: device capacity

```bash
# insmod blk-mq/blkdev.ko servaddr="x.x.x.x" servport=4444 name="mysocketdev" sz="10G"
```

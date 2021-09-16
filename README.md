# Socket-blk-mq

Multi-queue block device driver using socket communication

## Usage

1. Install ksocket/ksocket.ko
2. Open the server/usocket_srv
3. Install blk-mq/blkdev.ko
4. Read/Write to /dev/socketdev0

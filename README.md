# Usage

## Build
```bash
# Build ksocket
cd ksocket
make
# Install ksocket module
sudo insmod ksocket.ko

# Build socket-blk-mq
cd ../blk-mq
make
```

## Run
```bash
# Install blkdev module
# Arguments
# - servaddr: server address
# - servport: server port
# - name: device name
# - sz: device capacity
sudo insmod blk-mq/blkdev.ko servaddr="x.x.x.x" servport=4444 name="mysocketdev" sz="10G"

# Create a file as a storage
truncate -s 10G ./mystore

# Run the server
# Argument
# - file_path: path of the file created as storage
./usocket_srv ./mystore

# Run the test program
# Argument
# - device_path: path of the device created by blkdev module
sudo ./test /dev/mysocketdev0 
```

## TODO
1. Improve blkdev module stability
2. Code refactoring
3. Documentation

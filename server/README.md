# Usage

## Build

Setting the server IP address and port for testing clinet (line 16 and 20 of usocket_cli.c)

Setting the port for server (line 17 of usocket_srv.c)

If you want logging, set the "SERV_DEBUG" macro to 1 (line 12 of usocket_srv.c)

```bash
$ make
```

## Run

Create a file as a storage

```bash
$ truncate -s 10G ./myfile
```

Run the Server
Argument
- file_path: path of the file created as storage

```bash
$ ./usocket_srv ./myfile
```

Run the Client for socket testing

```bash
# ./usocket_cli
```

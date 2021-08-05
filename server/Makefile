CC=gcc
SERVER_OBJS=usocket_srv.o
SERVER_TEST=usocket_srv
CLIENT_OBJS=usocket_cli.o
CLIENT_TEST=usocket_cli

all: server client

server: $(SERVER_OBJS)
	$(CC) -o $(SERVER_TEST) $^

client: $(CLIENT_OBJS)
	$(CC) -o $(CLIENT_TEST) $^

clean:
	rm -rf $(SERVER_OBJS) $(SERVER_TEST) $(CLIENT_OBJS) $(CLIENT_TEST)

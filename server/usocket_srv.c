#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/sysinfo.h>
#include <errno.h>
#include <unistd.h>

#define SERV_DEBUG	0

typedef unsigned long long u64;
typedef unsigned short u16;

#define PORT		4444
#define INIT		-1
#define READ		0
#define WRITE		1

typedef struct {
	unsigned int op;
	loff_t offset;
	u64 size;
	u16 tag;
	char data[0];
} packet_t;

int server_fd;
struct sockaddr_in addr_srv;
int addr_len = sizeof(addr_srv);

int recv_packet(int client_fd, packet_t *packet)
{
	int len;

	len = recv(client_fd, packet, sizeof(packet_t), 0);
	if (len < 0) {
		perror("recv failed");
		return -EFAULT;
	} else if (len == 0)
		return -ENOTCONN;

#if SERV_DEBUG
	printf("recv packet op(%d) offset(%lu) size(%llu) tag(%u)\n",
			packet->op, packet->offset, packet->size, packet->tag);
#endif

	if (packet->op == INIT)
		return 0;

	return 0;
}

int write_data(int client_fd, FILE *f, packet_t *packet)
{
	int len;

	len = recv(client_fd, packet->data, packet->size, MSG_WAITALL);
	if (len < 0) {
		perror("recv failed");
		return -EFAULT;
	} else if (len == 0)
		return -ENOTCONN;

#if SERV_DEBUG
	printf("write: offset(%ld) size(%llu)\n", packet->offset, packet->size);
	printf("  data: %s\n", packet->data);
#endif

	fseek(f, packet->offset, SEEK_SET);
	fwrite(packet->data, sizeof(char), packet->size, f);

	len = send(client_fd, packet, sizeof(packet_t), 0);
	if (len < 0) {
		perror("send failed");
		return -EFAULT;
	} else if (len == 0)
		return -ENOTCONN;

	return len;
}

int read_data(int client_fd, FILE *f, packet_t *packet)
{
	char *base;
	u64 len;

	fseek(f, packet->offset, SEEK_SET);
	fread(packet->data, sizeof(char), packet->size, f);

#if SERV_DEBUG
	printf("read: offset(%ld) size(%llu)\n", packet->offset, packet->size);
	printf("  data: %s\n", packet->data);
#endif

	len = send(client_fd, packet, sizeof(packet_t), 0);
	if (len < 0) {
		perror("send failed");
		return -EFAULT;
	} else if (len == 0)
		return -ENOTCONN;

	len = send(client_fd, packet->data, packet->size, 0);
	if (len < 0) {
		perror("send failed");
		return -EFAULT;
	} else if (len == 0) {
		return -ENOTCONN;
	} else if (len != packet->size) {
		printf("send: origin(%llu) real(%llu)\n", packet->size, len);
	}

	return len;
}

void send_serv_cores(int client_fd, int ncores)
{
	if (send(client_fd, &ncores, sizeof(int), 0) < 0) {
		perror("can't initialized");
		exit(EXIT_FAILURE);
	}

	printf("notify %d cores\n", ncores);
}

void handle_packet(char *file_path, int client_fd, int ncores)
{
	FILE *f = NULL;
	packet_t *packet;

	packet = malloc(sizeof(packet_t) + (2 * 1024 * 1024));
	if (!packet) {
		perror("no memory");
		return;
	}

	f = fopen(file_path, "r+");
	if (!f) {
		perror("open error");
		return;
	}

	while (1) {
		if (recv_packet(client_fd, packet))
			break;

		switch (packet->op) {
			case INIT:
				send_serv_cores(client_fd, ncores);
				goto out;
			case READ:
				read_data(client_fd, f, packet);
				break;
			case WRITE:
				write_data(client_fd, f, packet);
			default:
				break;
		}
	}
out:
	free(packet);
	fclose(f);
}

void run_server(char *file_path, int ncores)
{
	int client_fd;
	int pid;
	int cnt = 0;

	while (1) {
		if ((client_fd = accept(server_fd, (struct sockaddr *)&addr_srv,
						(socklen_t *)&addr_len)) < 0) {
			perror("accept failed");
		} else { 
			if ((pid = fork()) == 0) {
				close(server_fd);
				handle_packet(file_path, client_fd, ncores);
				close(client_fd);
				exit(0);
			} else if (pid < 0) {
				perror("fork failed");
			}
		}
	}
}

void init_server(int ncores)
{
	int opt;

	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket creation failed");
		exit(EXIT_FAILURE);
	}

	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
				&opt, sizeof(opt))) {
		perror("set socket failed");
		exit(EXIT_FAILURE);
	}

	addr_srv.sin_family = AF_INET;
	addr_srv.sin_addr.s_addr = INADDR_ANY;
	addr_srv.sin_port = htons(PORT);

	if (bind(server_fd, (struct sockaddr *)&addr_srv, sizeof(addr_srv))) {
		perror("bind failed");
		exit(EXIT_FAILURE);
	}

	if (listen(server_fd, ncores)) {
		perror("listen failed");
		exit(EXIT_FAILURE);
	}
}

int main(int argc, char *argv[])
{
	char file_path[4096];
	int ncores;

	if (argc < 2) {
		printf("Usage: ./usocket_srv file_path\n");
		return -EINVAL;
	}

	memcpy(file_path, argv[1], strlen(argv[1]));
	ncores = get_nprocs();
	ncores = 4;

	init_server(ncores);

	printf("cores: %d, port: %d, file: %s\nserver listen...\n",
			ncores, PORT, file_path);

	run_server(file_path, ncores);

	close(server_fd);

	return 0;
}

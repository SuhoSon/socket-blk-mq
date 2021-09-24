#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/sysinfo.h>
#include <signal.h>

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
} packet_t;

int ncores;
int server_fd;
int client_fd;
struct sockaddr_in addr_srv;
int addr_len = sizeof(addr_srv);

int recv_packet(int client_fd, packet_t *packet)
{
	int len;

	len = recv(client_fd, packet, sizeof(packet_t), 0);
	if (len <= 0)
		perror("recv failed");

#if SERV_DEBUG
	printf("recv packet op(%d) offset(%lu) size(%llu) tag(%u)\n",
			packet->op, packet->offset, packet->size, packet->tag);
#endif

	return len;
}

int write_data(int client_fd, int fd, packet_t *packet, char *buffer)
{
	int len;

	len = recv(client_fd, buffer, packet->size, MSG_WAITALL);
	if (len <= 0) {
		perror("recv failed");
		return len;
	}

#if SERV_DEBUG
	printf("write: offset(%ld) size(%llu)\n", packet->offset, packet->size);
	printf("  data: %s\n", buffer);
#endif

	pwrite(fd, buffer, packet->size, packet->offset);

	len = send(client_fd, packet, sizeof(packet_t), 0);
	if (len <= 0)
		perror("send failed");

	return len;
}

int read_data(int client_fd, int fd, packet_t *packet, char *buffer)
{
	u64 len;

	pread(fd, buffer, packet->size, packet->offset);

#if SERV_DEBUG
	printf("read: offset(%ld) size(%llu)\n", packet->offset, packet->size);
	printf("  data: %s\n", buffer);
#endif

	len = send(client_fd, packet, sizeof(packet_t), 0);
	if (len <= 0) {
		perror("send failed");
		return len;
	}

	len = send(client_fd, buffer, packet->size, 0);
	if (len <= 0)
		perror("send failed");

	return len;
}

void send_serv_cores(int client_fd, int ncores)
{
	if (send(client_fd, &ncores, sizeof(int), 0) <= 0) {
		perror("can't initialized");
		return;
	}

	printf("Connected.\n");
}

void handle_packet(char *file_path, int ncores)
{
	int fd;
	packet_t packet;
	char *buffer;

	buffer = aligned_alloc(512, 2 * 1024 * 1024);
	if (!buffer) {
		perror("no memory");
		return;
	}

	fd = open(file_path, O_RDWR | O_DIRECT);
	if (fd < 0) {
		perror("open error");
		free(buffer);
		return;
	}

	while (1) {
		if (recv_packet(client_fd, &packet) <= 0)
			break;

		switch (packet.op) {
			case INIT:
				send_serv_cores(client_fd, ncores);
				goto out;
			case READ:
				if (read_data(client_fd, fd, &packet, buffer) <= 0)
					goto out;
				break;
			case WRITE:
				if (write_data(client_fd, fd, &packet, buffer) <= 0)
					goto out;
			default:
				break;
		}
	}
out:
	free(buffer);
	close(fd);
}

void run_server(char *file_path, int ncores)
{
	int pid;

	while (1) {
		if ((client_fd = accept(server_fd, (struct sockaddr *)&addr_srv,
						(socklen_t *)&addr_len)) < 0) {
			perror("accept failed");
		} else { 
			if ((pid = fork()) == 0) {
				close(server_fd);
				server_fd = -1;
				handle_packet(file_path, ncores);
				close(client_fd);
				exit(0);
			} else if (pid < 0)
				perror("fork failed");
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

void sigint_handler(int sig)
{
	if (server_fd > 0)
		close(server_fd);
	if (client_fd > 0)
		close(client_fd);
	exit(0);
}

int main(int argc, char *argv[])
{
	char file_path[4096];

	if (argc < 2) {
		printf("Usage: ./usocket_srv file_path\n");
		return -EINVAL;
	}

	signal(SIGINT, sigint_handler);

	memcpy(file_path, argv[1], strlen(argv[1]));
	ncores = get_nprocs();
	ncores = 4;

	init_server(ncores);

	printf("cores: %d, port: %d, file: %s\nserver listen...\n",
			ncores, PORT, file_path);

	run_server(file_path, ncores);

	return 0;
}

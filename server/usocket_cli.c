#include <pthread.h>
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

typedef unsigned long long u64;
typedef unsigned short u16;

#define PORT		4444
#define READ		0
#define WRITE		1

char *servip = "127.0.0.1";

typedef struct {
	unsigned int op;
	loff_t offset;
	u64 size;
	u16 id;
	char data[0];
} packet_t;

struct sockaddr_in servaddr;
int client_len;

int read_test()
{
	packet_t *packet;

	int server_fd;

	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("error: ");
		return -ENOTCONN;
	}

	if (connect(server_fd, (struct sockaddr *)&servaddr, client_len) < 0) {
		perror("connect error:");
		return -ENOTCONN;
	}

	packet = malloc(sizeof(packet_t) + 4);
	if (!packet) {
		perror("malloc error:");
		return -ENOMEM;
	}
	packet->op = READ;
	packet->offset = 0;
	packet->size = 4;
	packet->id = 0;

	if (send(server_fd, packet, sizeof(packet_t), MSG_DONTWAIT) < 0) {
		perror("send error:");
		return -ENOTCONN;
	}

	if (recv(server_fd, packet, sizeof(packet_t), 0) < 0) {
		perror("send error:");
		return -ENOTCONN;
	}

	if (recv(server_fd, packet->data, packet->size, MSG_WAITALL) < 0) {
		perror("send error:");
		return -ENOTCONN;
	}

	packet->data[3] = '\0';

	printf("recv: op(%d) offset(%lu) size(%llu) id(%d)\ndata: %s\n",
			packet->op, packet->offset, packet->size, packet->id, packet->data);

	free(packet);

	return server_fd;
}

int write_test()
{
	packet_t *packet;

	int server_fd;

	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("error: ");
		return -ENOTCONN;
	}

	if (connect(server_fd, (struct sockaddr *)&servaddr, client_len) < 0) {
		perror("connect error:");
		return -ENOTCONN;
	}

	packet = malloc(sizeof(packet_t));
	if (!packet) {
		perror("malloc error:");
		return -ENOMEM;
	}
	packet->op = WRITE;
	packet->offset = 0;
	packet->size = 4;
	packet->id = 0;
	packet->data[0] = 'b';
	packet->data[1] = 'y';
	packet->data[2] = 'e';

	if (send(server_fd, packet, sizeof(packet_t), MSG_MORE) < 0) {
		perror("send error:");
		return -ENOTCONN;
	}

	if (send(server_fd, packet->data, packet->size, 0) < 0) {
		perror("send error:");
		return -ENOTCONN;
	}

	if (recv(server_fd, packet, sizeof(packet_t), 0) < 0) {
		perror("send error:");
		return -ENOTCONN;
	}

	printf("recv: op(%d) offset(%lu) size(%llu) id(%d)\n",
			packet->op, packet->offset, packet->size, packet->id);

	free(packet);

	return server_fd;
}

void init_serv_addr(char *addr, int port)
{
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = inet_addr(addr);
	servaddr.sin_port = htons(port);
	client_len = sizeof(servaddr);
}

int main(int argc, char *argv[])
{
	pthread_t thread_id;
	packet_t packet;
	int ncores;
	int server_fd;

	init_serv_addr(servip, 4444);

	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("error: ");
		return -ENOTCONN;
	}

	if (connect(server_fd, (struct sockaddr *)&servaddr, client_len) < 0) {
		perror("connect error:");
		return -ENOTCONN;
	}

	memset(&packet, 0, sizeof(packet_t));
	packet.op = -1;

	if (send(server_fd, &packet, sizeof(packet_t), 0) < 0) {
		perror("ncores send error:");
		return -ENOTCONN;
	}

	if (recv(server_fd, &ncores, sizeof(int), MSG_WAITALL) < 0) {
		perror("ncores recv error:");
		return -ENOTCONN;
	}

	close(server_fd);

	while (1) {
		int op;

		printf("read=0, write=1, exit=2: ");
		scanf("%d", &op);

		switch (op) {
			case READ:
				server_fd = read_test();
				if (server_fd < 0)
					printf("read error\n");
				break;
			case WRITE:
				server_fd = write_test();
				if (server_fd < 0)
					printf("write error\n");
				break;
			case 2:
				return 0;
			default:
				break;
		}

		if (server_fd > 0)
			close(server_fd);
	}

	return 0;
}

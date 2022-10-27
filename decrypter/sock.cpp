#include "sock.h"
#include "crypt.h"

bool init_sock(WSADATA* wsa, SOCKET& sock, char** argv) {
	int res;
	struct sockaddr_in server;
	int port;

	res = WSAStartup(MAKEWORD(2, 2), wsa);
	if (res != 0) {
		printf("WSAStartup failed with error: %d\n", res);
		return false;
	}

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == INVALID_SOCKET) {
		printf("socket failed with error: %ld\n", WSAGetLastError());
		WSACleanup();
		return false;
	}

	server.sin_addr.S_un.S_addr = inet_addr(argv[0]);
	server.sin_family = AF_INET;
	server.sin_port = htons(atoi(argv[1]));

	// Connect to server.
	res = connect(sock, (struct sockaddr*) & server, sizeof(server));
	if (res == SOCKET_ERROR) {
		printf("%s:%s - connect failed with code: %d\n", argv[0], argv[1], WSAGetLastError());
		closesocket(sock);
		sock = INVALID_SOCKET;
		return false;
	}
	return true;
}
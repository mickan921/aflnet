/*
   Minimal native Windows RTSP-like target for AFLNet smoke testing.

   This is not a real RTSP implementation. It exists so the Windows fuzzer can
   be built and exercised against a tiny Windows network process before moving
   on to larger applications.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32

#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>

#  define DEFAULT_PORT "8554"
#  define RECV_BUF_SIZE 8192

static unsigned char coverage_map[64];

static void write_env_marker(void) {
  const char *path = getenv("AFLNET_SMOKE_ENV_MARKER");
  FILE *fp;

  if (!path || !*path) return;

  fp = fopen(path, "wb");
  if (!fp) return;
  fputs("seen\n", fp);
  fclose(fp);
}

static void write_coverage(void) {
  const char *path = getenv("AFLNET_COVERAGE_FILE");
  FILE *fp;

  if (!path || !*path) return;

  fp = fopen(path, "wb");
  if (!fp) return;
  fwrite(coverage_map, 1, sizeof(coverage_map), fp);
  fclose(fp);
}

static int contains_token(const char *buf, int len, const char *token) {
  int token_len = (int)strlen(token);
  int i;

  if (token_len <= 0 || token_len > len) return 0;

  for (i = 0; i <= len - token_len; i++)
    if (!memcmp(buf + i, token, token_len)) return 1;

  return 0;
}

static void mark_coverage(const char *req, int len) {
  int i;

  for (i = 0; i < len; i++)
    coverage_map[((unsigned char)req[i]) % sizeof(coverage_map)]++;

  if (contains_token(req, len, "OPTIONS")) coverage_map[1]++;
  if (contains_token(req, len, "DESCRIBE")) coverage_map[2]++;
  if (contains_token(req, len, "SETUP")) coverage_map[3]++;
  if (contains_token(req, len, "PLAY")) coverage_map[4]++;
  if (contains_token(req, len, "TEARDOWN")) coverage_map[5]++;

  write_coverage();
}

static int find_request_end(const char *buf, int len) {
  int i;

  for (i = 3; i < len; i++)
    if (buf[i - 3] == '\r' && buf[i - 2] == '\n' &&
        buf[i - 1] == '\r' && buf[i] == '\n')
      return i + 1;

  return 0;
}

static void extract_cseq(const char *req, int len, char *out, size_t out_size) {
  int i;

  snprintf(out, out_size, "1");

  for (i = 0; i + 5 < len; i++) {
    size_t pos = 0;

    if (_strnicmp(req + i, "CSeq:", 5)) continue;

    i += 5;
    while (i < len && (req[i] == ' ' || req[i] == '\t')) i++;

    while (i < len && req[i] != '\r' && req[i] != '\n' && pos + 1 < out_size)
      out[pos++] = req[i++];

    out[pos] = '\0';
    return;
  }
}

static int response_code_for_request(const char *req, int len, const char **phrase) {
  if (contains_token(req, len, "AFLNET_HANG")) {
    Sleep(30000);
    *phrase = "Hang";
    return 599;
  }

  if (contains_token(req, len, "AFLNET_CRASH")) {
    volatile int *crash = NULL;
    *crash = 1;
  }

  if (contains_token(req, len, "AFLNET_EXIT")) {
    ExitProcess(42);
  }

  if (contains_token(req, len, "OPTIONS")) {
    *phrase = "Options";
    return 200;
  }
  if (contains_token(req, len, "DESCRIBE")) {
    *phrase = "Describe";
    return 210;
  }
  if (contains_token(req, len, "SETUP")) {
    *phrase = "Setup";
    return 220;
  }
  if (contains_token(req, len, "PLAY")) {
    *phrase = "Play";
    return 230;
  }
  if (contains_token(req, len, "TEARDOWN")) {
    *phrase = "Teardown";
    return 240;
  }

  *phrase = "Unknown";
  return 455;
}

static int build_response(const char *req, int req_len, char *resp,
                          size_t resp_size, int *resp_len) {
  char cseq[32];
  const char *phrase;
  int code = response_code_for_request(req, req_len, &phrase);
  int len;

  extract_cseq(req, req_len, cseq, sizeof(cseq));
  len = snprintf(resp, resp_size,
                 "RTSP/1.0 %03d %s\r\n"
                 "CSeq: %s\r\n"
                 "Server: aflnet-win-smoke\r\n"
                 "Content-Length: 0\r\n\r\n",
                 code, phrase, cseq);

  if (len <= 0 || len >= (int)resp_size) return 1;
  *resp_len = len;
  return 0;
}

static int send_response(SOCKET client, const char *req, int req_len) {
  char resp[256];
  int len;

  if (build_response(req, req_len, resp, sizeof(resp), &len)) return 1;
  return send(client, resp, len, 0) != len;
}

static int send_response_to(SOCKET server, const char *req, int req_len,
                            const struct sockaddr *client_addr,
                            int client_addr_len) {
  char resp[256];
  int len;

  if (build_response(req, req_len, resp, sizeof(resp), &len)) return 1;
  return sendto(server, resp, len, 0, client_addr, client_addr_len) != len;
}

static int run_server(const char *port) {
  struct addrinfo hints, *res = NULL;
  SOCKET listener = INVALID_SOCKET;
  SOCKET client = INVALID_SOCKET;
  char buf[RECV_BUF_SIZE];
  int buf_len = 0;
  int ret = 1;
  int reuse = 1;
  DWORD timeout_ms = 2000;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_PASSIVE;

  if (getaddrinfo("127.0.0.1", port, &hints, &res)) return 2;

  listener = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (listener == INVALID_SOCKET) goto out;

  setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse,
             sizeof(reuse));

  if (bind(listener, res->ai_addr, (int)res->ai_addrlen) == SOCKET_ERROR)
    goto out;

  if (listen(listener, 1) == SOCKET_ERROR) goto out;

  client = accept(listener, NULL, NULL);
  if (client == INVALID_SOCKET) goto out;

  setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout_ms,
             sizeof(timeout_ms));

  for (;;) {
    int n;
    int req_end;

    if (buf_len >= RECV_BUF_SIZE - 1) buf_len = 0;

    n = recv(client, buf + buf_len, (RECV_BUF_SIZE - 1) - buf_len, 0);
    if (n <= 0) break;

    buf_len += n;

    while ((req_end = find_request_end(buf, buf_len)) > 0) {
      mark_coverage(buf, req_end);
      if (send_response(client, buf, req_end)) goto out;

      memmove(buf, buf + req_end, buf_len - req_end);
      buf_len -= req_end;
    }
  }

  ret = 0;

out:
  if (client != INVALID_SOCKET) closesocket(client);
  if (listener != INVALID_SOCKET) closesocket(listener);
  if (res) freeaddrinfo(res);
  write_coverage();
  return ret;
}

static int run_udp_server(const char *port) {
  struct addrinfo hints, *res = NULL;
  SOCKET server = INVALID_SOCKET;
  char buf[RECV_BUF_SIZE];
  int ret = 1;
  int reuse = 1;
  int received_any = 0;
  DWORD timeout_ms = 2000;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  hints.ai_flags = AI_PASSIVE;

  if (getaddrinfo("127.0.0.1", port, &hints, &res)) return 2;

  server = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (server == INVALID_SOCKET) goto out;

  setsockopt(server, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse,
             sizeof(reuse));
  setsockopt(server, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout_ms,
             sizeof(timeout_ms));

  if (bind(server, res->ai_addr, (int)res->ai_addrlen) == SOCKET_ERROR)
    goto out;

  for (;;) {
    struct sockaddr_storage client_addr;
    int client_addr_len = sizeof(client_addr);
    int n = recvfrom(server, buf, sizeof(buf), 0,
                     (struct sockaddr *)&client_addr, &client_addr_len);

    if (n == SOCKET_ERROR) {
      int err = WSAGetLastError();
      if ((err == WSAETIMEDOUT || err == WSAEWOULDBLOCK) && received_any) {
        ret = 0;
        break;
      }
      goto out;
    }

    if (n <= 0) continue;

    received_any = 1;
    mark_coverage(buf, n);
    if (send_response_to(server, buf, n, (struct sockaddr *)&client_addr,
                         client_addr_len))
      goto out;
  }

out:
  if (server != INVALID_SOCKET) closesocket(server);
  if (res) freeaddrinfo(res);
  write_coverage();
  return ret;
}

int main(int argc, char **argv) {
  WSADATA wsa;
  const char *port = argc > 1 ? argv[1] : DEFAULT_PORT;
  const char *mode = argc > 2 ? argv[2] : "tcp";
  int ret;

  if (WSAStartup(MAKEWORD(2, 2), &wsa)) return 2;
  write_env_marker();
  if (!_stricmp(mode, "udp")) ret = run_udp_server(port);
  else if (!_stricmp(mode, "tcp")) ret = run_server(port);
  else {
    fprintf(stderr, "usage: %s [port] [tcp|udp]\n", argv[0]);
    ret = 2;
  }
  WSACleanup();

  return ret;
}

#else

int main(void) {
  fprintf(stderr, "rtsp_smoke_server is only supported on native Windows.\n");
  return 1;
}

#endif

/*
   AFLNet portability helpers.

   The full afl-fuzz engine still depends on Unix process and shared-memory
   primitives, but the AFLNet protocol/replay networking code can use this
   layer on both POSIX and Windows.
*/

#ifndef _HAVE_AFL_COMPAT_H
#define _HAVE_AFL_COMPAT_H

#include <errno.h>
#include <stdlib.h>

#ifdef _WIN32

#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif

#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#  include <fcntl.h>
#  include <io.h>
#  include <sys/stat.h>

typedef SOCKET aflnet_socket_t;

#  define AFLNET_INVALID_SOCKET INVALID_SOCKET
#  define AFLNET_SOCKET_ERROR   SOCKET_ERROR

#  ifndef MSG_NOSIGNAL
#    define MSG_NOSIGNAL 0
#  endif

#  define open    _open
#  define close   _close
#  define read    _read
#  define write   _write
#  define lseek   _lseeki64
#  define fileno  _fileno
#  define unlink  _unlink

#  ifndef O_BINARY
#    define O_BINARY _O_BINARY
#  endif

static inline void aflnet_sleep_us(unsigned int usec) {
  Sleep((usec + 999) / 1000);
}

static inline void aflnet_cleanup_sockets(void) {
  WSACleanup();
}

static inline int aflnet_init_sockets(void) {
  static int initialized;
  WSADATA wsa;

  if (initialized) return 0;
  if (WSAStartup(MAKEWORD(2, 2), &wsa)) return -1;

  initialized = 1;
  atexit(aflnet_cleanup_sockets);
  return 0;
}

static inline int aflnet_close_socket(aflnet_socket_t sockfd) {
  return closesocket(sockfd);
}

static inline int aflnet_socket_last_error(void) {
  return WSAGetLastError();
}

static inline int aflnet_socket_would_block(int err) {
  return err == WSAEWOULDBLOCK || err == WSAEINTR || err == WSAETIMEDOUT;
}

static inline int aflnet_set_socket_timeout(aflnet_socket_t sockfd,
                                            int optname,
                                            struct timeval timeout) {
  DWORD timeout_ms = (DWORD)(timeout.tv_sec * 1000 +
                            (timeout.tv_usec + 999) / 1000);

  return setsockopt(sockfd, SOL_SOCKET, optname, (const char *)&timeout_ms,
                    sizeof(timeout_ms));
}

static inline int aflnet_wait_socket(aflnet_socket_t sockfd, int for_write,
                                     int timeout_ms) {
  fd_set readfds, writefds;
  struct timeval timeout;

  FD_ZERO(&readfds);
  FD_ZERO(&writefds);

  if (for_write) FD_SET(sockfd, &writefds);
  else FD_SET(sockfd, &readfds);

  timeout.tv_sec = timeout_ms / 1000;
  timeout.tv_usec = (timeout_ms % 1000) * 1000;

  return select(0, for_write ? NULL : &readfds, for_write ? &writefds : NULL,
                NULL, &timeout);
}

#else

#  include <arpa/inet.h>
#  include <fcntl.h>
#  include <netdb.h>
#  include <netinet/in.h>
#  include <sys/select.h>
#  include <sys/socket.h>
#  include <unistd.h>

typedef int aflnet_socket_t;

#  define AFLNET_INVALID_SOCKET (-1)
#  define AFLNET_SOCKET_ERROR   (-1)

#  ifndef O_BINARY
#    define O_BINARY 0
#  endif

static inline void aflnet_sleep_us(unsigned int usec) {
  usleep(usec);
}

static inline int aflnet_init_sockets(void) {
  return 0;
}

static inline int aflnet_close_socket(aflnet_socket_t sockfd) {
  return close(sockfd);
}

static inline int aflnet_socket_last_error(void) {
  return errno;
}

static inline int aflnet_socket_would_block(int err) {
  return err == EAGAIN || err == EWOULDBLOCK || err == EINTR;
}

static inline int aflnet_set_socket_timeout(aflnet_socket_t sockfd,
                                            int optname,
                                            struct timeval timeout) {
  return setsockopt(sockfd, SOL_SOCKET, optname, (char *)&timeout,
                    sizeof(timeout));
}

static inline int aflnet_wait_socket(aflnet_socket_t sockfd, int for_write,
                                     int timeout_ms) {
  fd_set readfds, writefds;
  struct timeval timeout;

  FD_ZERO(&readfds);
  FD_ZERO(&writefds);

  if (for_write) FD_SET(sockfd, &writefds);
  else FD_SET(sockfd, &readfds);

  timeout.tv_sec = timeout_ms / 1000;
  timeout.tv_usec = (timeout_ms % 1000) * 1000;

  return select(sockfd + 1, for_write ? NULL : &readfds,
                for_write ? &writefds : NULL, NULL, &timeout);
}

#endif /* _WIN32 */

#endif /* !_HAVE_AFL_COMPAT_H */

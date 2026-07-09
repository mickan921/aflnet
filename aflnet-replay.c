#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "alloc-inl.h"
#include "aflnet.h"

#define server_wait_usecs 10000

unsigned int* (*extract_response_codes)(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref) = NULL;

static unsigned int parse_uint_arg(const char *value, const char *name)
{
  char *end = NULL;
  unsigned long parsed;

  if (!value || !*value || value[0] == '-') FATAL("Bad value for %s: %s", name, value ? value : "(null)");

  parsed = strtoul(value, &end, 10);
  if (!end || *end || parsed > 0xffffffffUL)
    FATAL("Bad value for %s: %s", name, value);

  return (unsigned int)parsed;
}

/* Expected arguments:
1. Path to the test case (e.g., crash-triggering input)
2. Application protocol (e.g., RTSP, FTP)
3. Server's network port
Optional:
4. First response timeout (ms), default 1
5. Follow-up responses timeout (us), default 1000
*/

int main(int argc, char* argv[])
{
  FILE *fp;
  int n;
  char* buf = NULL, *response_buf = NULL;
  unsigned int response_buf_size = 0;
  unsigned int size, i, state_count, packet_count = 0;
  unsigned int *state_sequence;
  unsigned int socket_timeout = 1000;
  unsigned int poll_timeout = 1;
  u8 net_protocol;
  u8 *net_host = NULL;
  u32 net_port;


  if (argc < 4) {
    PFATAL("Usage: ./aflnet-replay packet_file protocol port|netinfo [first_resp_timeout(ms) [follow-up_resp_timeout(us)]]");
  }

  fp = fopen(argv[1],"rb");
  if(fp == NULL){
    fprintf(stderr, "[AFLNet-replay] Error opening file %s\n", argv[1]);
    exit(1);
  }
  
  aflnet_extract_requests_fn unused_extract_requests = NULL;
  if (aflnet_select_protocol(argv[2], &unused_extract_requests, &extract_response_codes)) {
    fprintf(stderr, "[AFLNet-replay] Protocol %s has not been supported yet!\n", argv[2]);
    exit(1);
  }
  init_message_code_map();

  if (aflnet_parse_replay_target(argv[3], argv[2], &net_protocol, &net_host, &net_port)) {
    FATAL("Bad replay target '%s'. Use a port or [tcp/udp]://host/port", argv[3]);
  }

  if (argc > 4) {
    poll_timeout = parse_uint_arg(argv[4], "first_resp_timeout");
    if (argc > 5) {
      socket_timeout = parse_uint_arg(argv[5], "follow-up_resp_timeout");
    }
  }

  //Wait for the server to initialize
  aflnet_sleep_us(server_wait_usecs);

  if (response_buf) {
    ck_free(response_buf);
    response_buf = NULL;
    response_buf_size = 0;
  }

  aflnet_socket_t sockfd;

  //Set timeout for socket data sending/receiving -- otherwise it causes a big delay
  //if the server is still alive after processing all the requests
  struct timeval timeout;

  timeout.tv_sec = 0;
  timeout.tv_usec = socket_timeout;

  if (aflnet_connect(&sockfd, net_protocol, (char *)net_host, net_port, timeout)) {
    FATAL("Cannot connect to %s://%s/%u",
          net_protocol == PRO_UDP ? "udp" : "tcp", (char *)net_host, net_port);
  }

  //Send requests one by one
  //And save all the server responses
  while(!feof(fp)) {
    if (buf) {ck_free(buf); buf = NULL;}
    if (fread(&size, sizeof(unsigned int), 1, fp) > 0) {
      packet_count++;
      fprintf(stderr,"\nSize of the current packet %u is %u\n", packet_count, size);

      if (!size) FATAL("Malformed replay file '%s': packet %u has zero size", argv[1], packet_count);

      buf = (char *)ck_alloc(size);
      if (fread(buf, 1, size, fp) != size)
        FATAL("Malformed replay file '%s': short packet %u", argv[1], packet_count);

      if (net_recv(sockfd, timeout, poll_timeout, &response_buf, &response_buf_size)) break;
      n = net_send(sockfd, timeout, buf,size);
      if (n != size) break;

      if (net_recv(sockfd, timeout, poll_timeout, &response_buf, &response_buf_size)) break;
    }
  }

  fclose(fp);
  aflnet_close_socket(sockfd);

  //Extract response codes
  state_sequence = (*extract_response_codes)(response_buf, response_buf_size, &state_count);

  fprintf(stderr,"\n--------------------------------");
  fprintf(stderr,"\nResponses from server:");

  for (i = 0; i < state_count; i++) {
    fprintf(stderr,"%d-",state_sequence[i]);
  }

  fprintf(stderr,"\n++++++++++++++++++++++++++++++++\nResponses in details:\n");
  for (i=0; i < response_buf_size; i++) {
    fprintf(stderr,"%c",response_buf[i]);
  }
  fprintf(stderr,"\n--------------------------------");

  //Free memory
  ck_free(state_sequence);
  if (buf) ck_free(buf);
  ck_free(response_buf);
  ck_free(net_host);
  destroy_message_code_map();

  return 0;
}


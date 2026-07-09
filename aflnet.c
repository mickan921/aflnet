#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "alloc-inl.h"
#include "aflnet.h"

// Mapping from original state IDs to compact IDs starting from 1

static u32 message_code_counter = 0;
khash_t(32) *message_code_map = NULL;

static char *aflnet_strdup(const char *str) {
  size_t len = strlen(str) + 1;
  char *ret = (char *)malloc(len);

  if (!ret) return NULL;
  memcpy(ret, str, len);
  return ret;
}

static int aflnet_parse_port(const char *str, u32 *port) {
  char *end = NULL;
  unsigned long parsed;

  if (!str || !*str) return 1;

  errno = 0;
  parsed = strtoul(str, &end, 10);
  if (errno || !end || *end || parsed == 0 || parsed > 65535UL) return 1;

  *port = (u32)parsed;
  return 0;
}

static int parse_status_code3(const char *line, unsigned int line_len,
                              unsigned int offset,
                              unsigned int *code_ref) {
  const unsigned char *p;

  if (line_len < offset + 3) return 1;

  p = (const unsigned char *)line + offset;
  if (!isdigit(p[0]) || !isdigit(p[1]) || !isdigit(p[2])) return 1;

  *code_ref = (unsigned int)((p[0] - '0') * 100 +
                            (p[1] - '0') * 10 +
                            (p[2] - '0'));
  return *code_ref == 0;
}

int aflnet_region_span(const region_t *region, u32 buf_len,
                       u32 *start_ref, u32 *len_ref) {
  u32 start;
  u32 end;

  if (!region || !buf_len) return 1;
  if (region->start_byte < 0 || region->end_byte < region->start_byte)
    return 1;

  start = (u32)region->start_byte;
  end = (u32)region->end_byte;
  if (start >= buf_len || end >= buf_len) return 1;

  if (start_ref) *start_ref = start;
  if (len_ref) *len_ref = end - start + 1;
  return 0;
}

int aflnet_region_is_valid(const region_t *region, u32 buf_size) {
  return aflnet_region_span(region, buf_size, NULL, NULL) == 0;
}

int aflnet_regions_are_valid(const region_t *regions, u32 region_count, u32 buf_size) {
  u32 i;
  int prev_end = -1;

  if (!region_count) return 1;
  if (!regions || !buf_size) return 0;

  for (i = 0; i < region_count; i++) {
    if (!aflnet_region_is_valid(&regions[i], buf_size)) return 0;
    if (i && regions[i].start_byte <= prev_end) return 0;
    prev_end = regions[i].end_byte;
  }

  return 1;
}

static int mqtt_read_remaining_length(const unsigned char *buf, u32 buf_size,
                                      u32 offset, u32 *value_ref,
                                      u32 *encoded_len_ref) {
  u32 multiplier = 1;
  u32 value = 0;
  u32 i;

  for (i = 0; i < 4; i++) {
    unsigned char encoded;
    u32 digit;

    if (offset + i >= buf_size) return 1;

    encoded = buf[offset + i];
    digit = (u32)(encoded & 0x7f);
    if (digit && multiplier > UINT_MAX / digit) return 1;
    if (value > UINT_MAX - digit * multiplier) return 1;
    value += digit * multiplier;

    if ((encoded & 0x80) == 0) {
      *value_ref = value;
      *encoded_len_ref = i + 1;
      return 0;
    }

    if (i == 3 || multiplier > UINT_MAX / 128) return 1;
    multiplier *= 128;
  }

  return 1;
}

void init_message_code_map(){
  if (message_code_map) kh_destroy(32, message_code_map);
  message_code_map = kh_init(32);
  message_code_counter = 0;
}

void destroy_message_code_map(){
  if (message_code_map) kh_destroy(32, message_code_map);
  message_code_map = NULL;
  message_code_counter = 0;
}

u32 get_mapped_message_code (u32 ori_message_code){
  u32 mapped_message_code = 0;

  if (!message_code_map) init_message_code_map();

  khiter_t k = kh_get(32, message_code_map, ori_message_code);
  if (k == kh_end(message_code_map)) {
    int ret;
    k = kh_put(32, message_code_map, ori_message_code, &ret);
    message_code_counter++;
    kh_value(message_code_map, k) = message_code_counter;

    mapped_message_code = message_code_counter;
  }
  else {
    mapped_message_code = kh_value(message_code_map, k);
  }

  return mapped_message_code;
}

// Protocol-specific functions for extracting requests and responses

int aflnet_select_protocol(const char* protocol,
                           aflnet_extract_requests_fn *requests_fn,
                           aflnet_extract_response_codes_fn *responses_fn)
{
  if (!strcmp(protocol, "RTSP")) {
    *requests_fn = &extract_requests_rtsp;
    *responses_fn = &extract_response_codes_rtsp;
  } else if (!strcmp(protocol, "FTP")) {
    *requests_fn = &extract_requests_ftp;
    *responses_fn = &extract_response_codes_ftp;
  } else if (!strcmp(protocol, "MQTT")) {
    *requests_fn = &extract_requests_mqtt;
    *responses_fn = &extract_response_codes_mqtt;
  } else if (!strcmp(protocol, "DTLS12")) {
    *requests_fn = &extract_requests_dtls12;
    *responses_fn = &extract_response_codes_dtls12;
  } else if (!strcmp(protocol, "DNS")) {
    *requests_fn = &extract_requests_dns;
    *responses_fn = &extract_response_codes_dns;
  } else if (!strcmp(protocol, "DICOM")) {
    *requests_fn = &extract_requests_dicom;
    *responses_fn = &extract_response_codes_dicom;
  } else if (!strcmp(protocol, "SMTP")) {
    *requests_fn = &extract_requests_smtp;
    *responses_fn = &extract_response_codes_smtp;
  } else if (!strcmp(protocol, "SSH")) {
    *requests_fn = &extract_requests_ssh;
    *responses_fn = &extract_response_codes_ssh;
  } else if (!strcmp(protocol, "TLS")) {
    *requests_fn = &extract_requests_tls;
    *responses_fn = &extract_response_codes_tls;
  } else if (!strcmp(protocol, "SIP")) {
    *requests_fn = &extract_requests_sip;
    *responses_fn = &extract_response_codes_sip;
  } else if (!strcmp(protocol, "HTTP")) {
    *requests_fn = &extract_requests_http;
    *responses_fn = &extract_response_codes_http;
  } else if (!strcmp(protocol, "IPP")) {
    *requests_fn = &extract_requests_ipp;
    *responses_fn = &extract_response_codes_ipp;
  } else if (!strcmp(protocol, "TFTP")) {
    *requests_fn = &extract_requests_tftp;
    *responses_fn = &extract_response_codes_tftp;
  } else if (!strcmp(protocol, "DHCP")) {
    *requests_fn = &extract_requests_dhcp;
    *responses_fn = &extract_response_codes_dhcp;
  } else if (!strcmp(protocol, "SNTP")) {
    *requests_fn = &extract_requests_SNTP;
    *responses_fn = &extract_response_codes_SNTP;
  } else if (!strcmp(protocol, "NTP")) {
    *requests_fn = &extract_requests_NTP;
    *responses_fn = &extract_response_codes_NTP;
  } else if (!strcmp(protocol, "SNMP")) {
    *requests_fn = &extract_requests_SNMP;
    *responses_fn = &extract_response_codes_SNMP;
  } else {
    *requests_fn = NULL;
    *responses_fn = NULL;
    return 1;
  }

  return 0;
}

region_t* extract_requests_tftp(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref)
{
  char *mem;
  unsigned int mem_count = 0;
  unsigned int mem_size = 1024;
  unsigned int region_count = 0;
  region_t *regions = NULL;
  char terminator[2] = {0x00, 0x00};
  //char* terminator = '\0';
  mem = (char *)ck_alloc(mem_size);

  unsigned int cur_start = 0;
  unsigned int cur_end = 0;
  for (unsigned int byte_count = 0; byte_count < buf_size; byte_count++) {
    memcpy(&mem[mem_count], buf + byte_count, 1);
    if ((mem_count > 1) && (memcmp(&mem[mem_count - 1], terminator, 1) == 0)){
        region_count++;
        regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
        regions[region_count - 1].start_byte = cur_start;
        regions[region_count - 1].end_byte = cur_end;
        regions[region_count - 1].state_sequence = NULL;
        regions[region_count - 1].state_count = 0;

        mem_count = 0;
        cur_start = cur_end + 1;
        cur_end = cur_start;

    }
    else {
      mem_count++;
      cur_end++;
      //Check if the last byte has been reached
      if (cur_end == buf_size - 1) {
        region_count++;
        regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
        regions[region_count - 1].start_byte = cur_start;
        regions[region_count - 1].end_byte = cur_end;
        regions[region_count - 1].state_sequence = NULL;
        regions[region_count - 1].state_count = 0;
        break;
      }
      if (mem_count == mem_size) {

        //enlarge the mem buffer
        mem_size = mem_size * 2;
        mem=(char *)ck_realloc(mem, mem_size);
      }
    }
    //ACTF("End of iteration");
  }
  if (mem) ck_free(mem);
  //in case region_count equals zero, it means that the structure of the buffer is broken
  //hence we create one region for the whole buffer
  if ((region_count == 0) && (buf_size > 0)) {
    regions = (region_t *)ck_realloc(regions, sizeof(region_t));
    regions[0].start_byte = 0;
    regions[0].end_byte = buf_size - 1;
    regions[0].state_sequence = NULL;
    regions[0].state_count = 0;

    region_count = 1;
  }

  *region_count_ref = region_count;
  return regions;
}



region_t* extract_requests_dhcp(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref)
{
  char *mem;
  unsigned int mem_count = 0;
  unsigned int mem_size = 1024;
  unsigned int region_count = 0;
  region_t *regions = NULL;
  char terminator[2] = {0xff, 0xff};
  //char* terminator = '\0';
  mem = (char *)ck_alloc(mem_size);

  unsigned int cur_start = 0;
  unsigned int cur_end = 0;
  for (unsigned int byte_count = 0; byte_count < buf_size; byte_count++) {
    memcpy(&mem[mem_count], buf + byte_count, 1);
    if ((mem_count > 1) && (memcmp(&mem[mem_count - 1], terminator, 2) == 0)){
        region_count++;
        regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
        regions[region_count - 1].start_byte = cur_start;
        regions[region_count - 1].end_byte = cur_end;
        regions[region_count - 1].state_sequence = NULL;
        regions[region_count - 1].state_count = 0;

        mem_count = 0;
        cur_start = cur_end + 1;
        cur_end = cur_start;

    }
    else {
      mem_count++;
      cur_end++;
      //Check if the last byte has been reached
      if (cur_end == buf_size - 1) {
        region_count++;
        regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
        regions[region_count - 1].start_byte = cur_start;
        regions[region_count - 1].end_byte = cur_end;
        regions[region_count - 1].state_sequence = NULL;
        regions[region_count - 1].state_count = 0;
        break;
      }
      if (mem_count == mem_size) {

        //enlarge the mem buffer
        mem_size = mem_size * 2;
        mem=(char *)ck_realloc(mem, mem_size);
      }
    }
    //ACTF("End of iteration");
  }
  if (mem) ck_free(mem);
  //in case region_count equals zero, it means that the structure of the buffer is broken
  //hence we create one region for the whole buffer
  if ((region_count == 0) && (buf_size > 0)) {
    regions = (region_t *)ck_realloc(regions, sizeof(region_t));
    regions[0].start_byte = 0;
    regions[0].end_byte = buf_size - 1;
    regions[0].state_sequence = NULL;
    regions[0].state_count = 0;

    region_count = 1;
  }

  *region_count_ref = region_count;
  return regions;
}


region_t* extract_requests_SNTP(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref)
{
  char *mem;
  unsigned int mem_count = 0;
  unsigned int mem_size = 1024;
  unsigned int region_count = 0;
  region_t *regions = NULL;
  char terminator[1] = {0x0};
  //char* terminator = '\0';
  mem = (char *)ck_alloc(mem_size);

  unsigned int cur_start = 0;
  unsigned int cur_end = 0;
  for (unsigned int byte_count = 0; byte_count < buf_size; byte_count++) {
    memcpy(&mem[mem_count], buf + byte_count, 1);
    if ((mem_count > 1) && (memcmp(&mem[mem_count - 1], terminator, 1) == 0)){
        region_count++;
        regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
        regions[region_count - 1].start_byte = cur_start;
        regions[region_count - 1].end_byte = cur_end;
        regions[region_count - 1].state_sequence = NULL;
        regions[region_count - 1].state_count = 0;

        mem_count = 0;
        cur_start = cur_end + 1;
        cur_end = cur_start;

    }
    else {
      mem_count++;
      cur_end++;
      //Check if the last byte has been reached
      if (cur_end == buf_size - 1) {
        region_count++;
        regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
        regions[region_count - 1].start_byte = cur_start;
        regions[region_count - 1].end_byte = cur_end;
        regions[region_count - 1].state_sequence = NULL;
        regions[region_count - 1].state_count = 0;
        break;
      }
      if (mem_count == mem_size) {

        //enlarge the mem buffer
        mem_size = mem_size * 2;
        mem=(char *)ck_realloc(mem, mem_size);
      }
    }
    //ACTF("End of iteration");
  }
  if (mem) ck_free(mem);
  //in case region_count equals zero, it means that the structure of the buffer is broken
  //hence we create one region for the whole buffer
  if ((region_count == 0) && (buf_size > 0)) {
    regions = (region_t *)ck_realloc(regions, sizeof(region_t));
    regions[0].start_byte = 0;
    regions[0].end_byte = buf_size - 1;
    regions[0].state_sequence = NULL;
    regions[0].state_count = 0;

    region_count = 1;
  }

  *region_count_ref = region_count;
  return regions;
}

region_t* extract_requests_NTP(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref)
{
  char *mem;
  unsigned int mem_count = 0;
  unsigned int mem_size = 1024;
  unsigned int region_count = 0;
  region_t *regions = NULL;
  char terminator[1] = {0x0};
  //char* terminator = '\0';
  mem = (char *)ck_alloc(mem_size);

  unsigned int cur_start = 0;
  unsigned int cur_end = 0;
  if(buf_size==48){

    for (unsigned int byte_count = 0; byte_count < buf_size; byte_count++) {
    memcpy(&mem[mem_count], buf + byte_count, 1);
 
    if (mem_count==47){

        region_count++;
        regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
        regions[region_count - 1].start_byte = cur_start;
        regions[region_count - 1].end_byte = cur_end;
        regions[region_count - 1].state_sequence = NULL;
        regions[region_count - 1].state_count = 0;

        mem_count = 0;
        cur_start = cur_end + 1;
        cur_end = cur_start;

    }
    else {
      mem_count++;
      cur_end++;
      //Check if the last byte has been reached
      if (cur_end == buf_size - 1) {
        region_count++;
        regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
        regions[region_count - 1].start_byte = cur_start;
        regions[region_count - 1].end_byte = cur_end;
        regions[region_count - 1].state_sequence = NULL;
        regions[region_count - 1].state_count = 0;
        break;
      }
      if (mem_count == mem_size) {

        //enlarge the mem buffer
        mem_size = mem_size * 2;
        mem=(char *)ck_realloc(mem, mem_size);
      }
    }
    //ACTF("End of iteration");
    }
  }
  else{
    for (unsigned int byte_count = 0; byte_count < buf_size; byte_count++) {
      memcpy(&mem[mem_count], buf + byte_count, 1);
      if (((mem_count > 48) && (memcmp(&mem[mem_count - 1], terminator, 1) == 0) && (mem_count ==68 || mem_count==120))){
          region_count++;
          regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
          regions[region_count - 1].start_byte = cur_start;
          regions[region_count - 1].end_byte = cur_end;
          regions[region_count - 1].state_sequence = NULL;
          regions[region_count - 1].state_count = 0;

          mem_count = 0;
          cur_start = cur_end + 1;
          cur_end = cur_start;

      }
      else {
        mem_count++;
        cur_end++;
        //Check if the last byte has been reached
        if (cur_end == buf_size - 1) {
          region_count++;
          regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
          regions[region_count - 1].start_byte = cur_start;
          regions[region_count - 1].end_byte = cur_end;
          regions[region_count - 1].state_sequence = NULL;
          regions[region_count - 1].state_count = 0;
          break;
        }
        if (mem_count == mem_size) {

          //enlarge the mem buffer
          mem_size = mem_size * 2;
          mem=(char *)ck_realloc(mem, mem_size);
        }
      }
      //ACTF("End of iteration");
    }
  }
  if (mem) ck_free(mem);
  //in case region_count equals zero, it means that the structure of the buffer is broken
  //hence we create one region for the whole buffer
  if ((region_count == 0) && (buf_size > 0)) {
    regions = (region_t *)ck_realloc(regions, sizeof(region_t));
    regions[0].start_byte = 0;
    regions[0].end_byte = buf_size - 1;
    regions[0].state_sequence = NULL;
    regions[0].state_count = 0;

    region_count = 1;
  }

  *region_count_ref = region_count;
  return regions;
}

region_t* extract_requests_SNMP(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref)
{
  char *mem;
  unsigned int mem_count = 0;
  unsigned int mem_size = 1024;
  unsigned int region_count = 0;
  region_t *regions = NULL;
  char terminator[1] = {0x0};
  //char* terminator = '\0';
  mem = (char *)ck_alloc(mem_size);

  unsigned int cur_start = 0;
  unsigned int cur_end = 0;
  for (unsigned int byte_count = 0; byte_count < buf_size; byte_count++) {
    memcpy(&mem[mem_count], buf + byte_count, 1);
    if ((mem_count > 1) && (memcmp(&mem[mem_count - 1], terminator, 1) == 0)){
        region_count++;
        regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
        regions[region_count - 1].start_byte = cur_start;
        regions[region_count - 1].end_byte = cur_end;
        regions[region_count - 1].state_sequence = NULL;
        regions[region_count - 1].state_count = 0;

        mem_count = 0;
        cur_start = cur_end + 1;
        cur_end = cur_start;

    }
    else {
      mem_count++;
      cur_end++;
      //Check if the last byte has been reached
      if (cur_end == buf_size - 1) {
        region_count++;
        regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
        regions[region_count - 1].start_byte = cur_start;
        regions[region_count - 1].end_byte = cur_end;
        regions[region_count - 1].state_sequence = NULL;
        regions[region_count - 1].state_count = 0;
        break;
      }
      if (mem_count == mem_size) {

        //enlarge the mem buffer
        mem_size = mem_size * 2;
        mem=(char *)ck_realloc(mem, mem_size);
      }
    }
    //ACTF("End of iteration");
  }
  if (mem) ck_free(mem);
  //in case region_count equals zero, it means that the structure of the buffer is broken
  //hence we create one region for the whole buffer
  if ((region_count == 0) && (buf_size > 0)) {
    regions = (region_t *)ck_realloc(regions, sizeof(region_t));
    regions[0].start_byte = 0;
    regions[0].end_byte = buf_size - 1;
    regions[0].state_sequence = NULL;
    regions[0].state_count = 0;

    region_count = 1;
  }

  *region_count_ref = region_count;
  return regions;
}


region_t* extract_requests_smtp(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref)
{
   char *mem;
  unsigned int byte_count = 0;
  unsigned int mem_count = 0;
  unsigned int mem_size = 1024;
  unsigned int region_count = 0;
  region_t *regions = NULL;
  char terminator[2] = {0x0D, 0x0A};

  mem=(char *)ck_alloc(mem_size);

  unsigned int cur_start = 0;
  unsigned int cur_end = 0;
  while (byte_count < buf_size) {

    memcpy(&mem[mem_count], buf + byte_count++, 1);

    //Check if the last two bytes are 0x0D0A
    if ((mem_count > 1) && (memcmp(&mem[mem_count - 1], terminator, 2) == 0)) {
      region_count++;
      regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
      regions[region_count - 1].start_byte = cur_start;
      regions[region_count - 1].end_byte = cur_end;
      regions[region_count - 1].state_sequence = NULL;
      regions[region_count - 1].state_count = 0;

      mem_count = 0;
      cur_start = cur_end + 1;
      cur_end = cur_start;
    } else {
      mem_count++;
      cur_end++;

      //Check if the last byte has been reached
      if (cur_end == buf_size - 1) {
        region_count++;
        regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
        regions[region_count - 1].start_byte = cur_start;
        regions[region_count - 1].end_byte = cur_end;
        regions[region_count - 1].state_sequence = NULL;
        regions[region_count - 1].state_count = 0;
        break;
      }

      if (mem_count == mem_size) {
        //enlarge the mem buffer
        mem_size = mem_size * 2;
        mem=(char *)ck_realloc(mem, mem_size);
      }
    }
  }
  if (mem) ck_free(mem);

  //in case region_count equals zero, it means that the structure of the buffer is broken
  //hence we create one region for the whole buffer
  if ((region_count == 0) && (buf_size > 0)) {
    regions = (region_t *)ck_realloc(regions, sizeof(region_t));
    regions[0].start_byte = 0;
    regions[0].end_byte = buf_size - 1;
    regions[0].state_sequence = NULL;
    regions[0].state_count = 0;

    region_count = 1;
  }

  *region_count_ref = region_count;
  return regions;
}

region_t* extract_requests_ssh(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref)
{
  char *mem;
  unsigned int byte_count = 0;
  unsigned int mem_count = 0;
  unsigned int mem_size = 1024;
  unsigned int region_count = 0;
  region_t *regions = NULL;
  char terminator[2] = {0x0D, 0x0A};

  mem=(char *)ck_alloc(mem_size);

  unsigned int cur_start = 0;
  unsigned int cur_end = 0;
  while (byte_count < buf_size) {

    memcpy(&mem[mem_count], buf + byte_count++, 1);

    //Check if the region buffer length is at least 6 bytes
    //Why 6 bytes? It is because both the SSH identification and the normal message are longer than 6 bytes
    //For normal message, it starts with message size (4 bytes), #padding_bytes (1 byte) and message code (1 byte)
    if (mem_count >= 6) {
      if (!strncmp(mem, "SSH-", 4)) {
        //It could be an identification message
        //Find terminator (0x0D 0x0A)
        while ((byte_count < buf_size) && (memcmp(&mem[mem_count - 1], terminator, 2))) {
          if (mem_count == mem_size - 1) {
            //enlarge the mem buffer
            mem_size = mem_size * 2;
            mem=(char *)ck_realloc(mem, mem_size);
          }
          memcpy(&mem[++mem_count], buf + byte_count++, 1);
          cur_end++;
        }

        //Create one region
        region_count++;
        regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
        regions[region_count - 1].start_byte = cur_start;
        regions[region_count - 1].end_byte = cur_end;
        regions[region_count - 1].state_sequence = NULL;
        regions[region_count - 1].state_count = 0;

        //Check if the last byte has been reached
        if (cur_end < buf_size - 1) {
          mem_count = 0;
          cur_start = cur_end + 1;
          cur_end = cur_start;
        }
      } else {
        //It could be a normal message
        //Extract the message size stored in the first 4 bytes
        unsigned int message_size = read_bytes_to_uint32((unsigned char *)mem, 0, 4);
        unsigned char message_code = (unsigned char)mem[5];
        //and skip the payload and the MAC
        unsigned int bytes_to_skip = message_size > 2 ? message_size - 2 : 0;
        if ((message_code >= 20) && (message_code <= 49)) {
          //Do nothing
        } else {
          if (bytes_to_skip <= UINT_MAX - 8) bytes_to_skip += 8;
        }

        unsigned int temp_count = 0;
        while ((byte_count < buf_size) && (temp_count < bytes_to_skip)) {
          byte_count++;
          cur_end++;
          temp_count++;
        }

        if (byte_count < buf_size) {
          byte_count--;
          cur_end--;
        }

        //Create one region
        region_count++;
        regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
        regions[region_count - 1].start_byte = cur_start;
        regions[region_count - 1].end_byte = cur_end;
        regions[region_count - 1].state_sequence = NULL;
        regions[region_count - 1].state_count = 0;

        //Check if the last byte has been reached
        if (cur_end < buf_size - 1) {
          mem_count = 0;
          cur_start = cur_end + 1;
          cur_end = cur_start;
        }
      }
    } else {
      mem_count++;
      cur_end++;

      //Check if the last byte has been reached
      if (cur_end == buf_size - 1) {
        region_count++;
        regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
        regions[region_count - 1].start_byte = cur_start;
        regions[region_count - 1].end_byte = cur_end;
        regions[region_count - 1].state_sequence = NULL;
        regions[region_count - 1].state_count = 0;
        break;
      }

      if (mem_count == mem_size) {
        //enlarge the mem buffer
        mem_size = mem_size * 2;
        mem=(char *)ck_realloc(mem, mem_size);
      }
    }
  }
  if (mem) ck_free(mem);

  //in case region_count equals zero, it means that the structure of the buffer is broken
  //hence we create one region for the whole buffer
  if ((region_count == 0) && (buf_size > 0)) {
    regions = (region_t *)ck_realloc(regions, sizeof(region_t));
    regions[0].start_byte = 0;
    regions[0].end_byte = buf_size - 1;
    regions[0].state_sequence = NULL;
    regions[0].state_count = 0;

    region_count = 1;
  }

  *region_count_ref = region_count;
  return regions;
}

region_t* extract_requests_tls(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref)
{
  char *mem;
  unsigned int byte_count = 0;
  unsigned int mem_count = 0;
  unsigned int mem_size = 1024;
  unsigned int region_count = 0;
  region_t *regions = NULL;

  mem=(char *)ck_alloc(mem_size);

  unsigned int cur_start = 0;
  unsigned int cur_end = 0;
  while (byte_count < buf_size) {

    memcpy(&mem[mem_count], buf + byte_count++, 1);

    //Check if the region buffer length is at least 5 bytes (record header size)
    if (mem_count >= 5) {
      //1st byte: content type
      //2nd and 3rd byte: TLS version
      //Extract the message size stored in the 4th and 5th bytes
      u16 message_size = (u16)read_bytes_to_uint32((unsigned char *)mem, 3, 2);

      //and skip the payload
      unsigned int bytes_to_skip = message_size;

      unsigned int temp_count = 0;
      while ((byte_count < buf_size) && (temp_count < bytes_to_skip)) {
        byte_count++;
        cur_end++;
        temp_count++;
      }

      if (byte_count < buf_size) {
          byte_count--;
          cur_end--;
      }

      //Create one region
      region_count++;
      regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
      regions[region_count - 1].start_byte = cur_start;
      regions[region_count - 1].end_byte = cur_end;
      regions[region_count - 1].state_sequence = NULL;
      regions[region_count - 1].state_count = 0;

      //Check if the last byte has been reached
      if (cur_end < buf_size - 1) {
        mem_count = 0;
        cur_start = cur_end + 1;
        cur_end = cur_start;
      }
    } else {
      mem_count++;
      cur_end++;

      //Check if the last byte has been reached
      if (cur_end == buf_size - 1) {
        region_count++;
        regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
        regions[region_count - 1].start_byte = cur_start;
        regions[region_count - 1].end_byte = cur_end;
        regions[region_count - 1].state_sequence = NULL;
        regions[region_count - 1].state_count = 0;
        break;
      }

      if (mem_count == mem_size) {
        //enlarge the mem buffer
        mem_size = mem_size * 2;
        mem=(char *)ck_realloc(mem, mem_size);
      }
    }
  }
  if (mem) ck_free(mem);

  //in case region_count equals zero, it means that the structure of the buffer is broken
  //hence we create one region for the whole buffer
  if ((region_count == 0) && (buf_size > 0)) {
    regions = (region_t *)ck_realloc(regions, sizeof(region_t));
    regions[0].start_byte = 0;
    regions[0].end_byte = buf_size - 1;
    regions[0].state_sequence = NULL;
    regions[0].state_count = 0;

    region_count = 1;
  }

  *region_count_ref = region_count;
  return regions;
}


region_t* extract_requests_dicom(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref)
{
  unsigned int pdu_length = 0;
  unsigned int packet_length = 0;
  unsigned int region_count = 0;
  unsigned int end = 0;
  unsigned int start = 0;

  region_t *regions = NULL;

  unsigned int byte_count = 0;
  while (byte_count < buf_size) {

    if ((byte_count + 2 >= buf_size) || (byte_count + 5 >= buf_size)) break;

    // Bytes from third to sixth encode the PDU length.
    pdu_length =
      (buf[byte_count + 5]) |
      (buf[byte_count + 4] << 8)  |
      (buf[byte_count + 3] << 16) |
      (buf[byte_count + 2] << 24);

    // DICOM Header(6 bytes) includes PDU type and PDU length.
    packet_length = pdu_length + 6;

    start = byte_count;
    end = byte_count + packet_length - 1;

    if (end < start) break; // it means that int overflow has happened -_0_0_-
    if (end >= buf_size) break; // checking boundaries

    region_count++;
    regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
    regions[region_count - 1].start_byte = start;
    regions[region_count - 1].end_byte = end;
    regions[region_count - 1].state_sequence = NULL;
    regions[region_count - 1].state_count = 0;

    if ( (byte_count + packet_length) < byte_count ) break; // checking int overflow
    if ( (byte_count + packet_length) < packet_length ) break; // checking int overflow
    byte_count += packet_length;
  }

  // if bytes is left
  if ((byte_count < buf_size) && (buf_size > 0)) {
    region_count++;
    regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
    regions[region_count - 1].start_byte = byte_count;
    regions[region_count - 1].end_byte = buf_size - 1;
    regions[region_count - 1].state_sequence = NULL;
    regions[region_count - 1].state_count = 0;
  }

  *region_count_ref = region_count;
  return regions;
}

region_t* extract_requests_dns(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref)
{
  char *mem;
  unsigned int mem_count = 0;
  unsigned int mem_size = 1024;
  unsigned int region_count = 0;
  region_t *regions = NULL;

  mem = (char *)ck_alloc(mem_size);

  unsigned int cur_start = 0;
  unsigned int cur_end = 0;
  for (unsigned int byte_count = 0; byte_count < buf_size; byte_count++) {
    memcpy(&mem[mem_count], buf + byte_count, 1);

    // A DNS header is 12 bytes long & the 1st null byte after that indicates the end of the query.
    if ((mem_count >= 12) && (*(mem+mem_count) == 0)) {
      // 4 bytes left of the tail.
      if (byte_count + 4 >= buf_size) {
        cur_end = buf_size - 1;
        byte_count = buf_size - 1;
      } else {
        cur_end += 4;
        byte_count += 4;
      }
      region_count++;
      regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
      regions[region_count - 1].start_byte = cur_start;
      regions[region_count - 1].end_byte = cur_end;
      regions[region_count - 1].state_sequence = NULL;
      regions[region_count - 1].state_count = 0;

      if (cur_end == buf_size - 1) break;

      mem_count = 0;
      cur_start = cur_end + 1;
      cur_end = cur_start;
    } else {
      mem_count++;
      cur_end++;

      // Check if the last byte has been reached
      if (cur_end == buf_size - 1) {
        region_count++;
        regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
        regions[region_count - 1].start_byte = cur_start;
        regions[region_count - 1].end_byte = cur_end;
        regions[region_count - 1].state_sequence = NULL;
        regions[region_count - 1].state_count = 0;
        break;
      }

      if (mem_count == mem_size) {
        // Enlarge the mem buffer
        mem_size *= 2;
        mem = (char *)ck_realloc(mem, mem_size);
      }
    }
  }
  if (mem) ck_free(mem);

  // In case region_count equals zero, it means that the structure of the buffer is broken
  // hence we create one region for the whole buffer
  if ((region_count == 0) && (buf_size > 0)) {
    regions = (region_t *)ck_realloc(regions, sizeof(region_t));
    regions[0].start_byte = 0;
    regions[0].end_byte = buf_size - 1;
    regions[0].state_sequence = NULL;
    regions[0].state_count = 0;

    region_count = 1;
  }

  *region_count_ref = region_count;
  return regions;
}

region_t* extract_requests_rtsp(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref)
{
  char *mem;
  unsigned int byte_count = 0;
  unsigned int mem_count = 0;
  unsigned int mem_size = 1024;
  unsigned int region_count = 0;
  region_t *regions = NULL;
  char terminator[4] = {0x0D, 0x0A, 0x0D, 0x0A};

  mem=(char *)ck_alloc(mem_size);

  unsigned int cur_start = 0;
  unsigned int cur_end = 0;
  while (byte_count < buf_size) {

    memcpy(&mem[mem_count], buf + byte_count++, 1);

    //Check if the last four bytes are 0x0D0A0D0A
    if ((mem_count > 3) && (memcmp(&mem[mem_count - 3], terminator, 4) == 0)) {
      region_count++;
      regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
      regions[region_count - 1].start_byte = cur_start;
      regions[region_count - 1].end_byte = cur_end;
      regions[region_count - 1].state_sequence = NULL;
      regions[region_count - 1].state_count = 0;

      mem_count = 0;
      cur_start = cur_end + 1;
      cur_end = cur_start;
    } else {
      mem_count++;
      cur_end++;

      //Check if the last byte has been reached
      if (cur_end == buf_size - 1) {
        region_count++;
        regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
        regions[region_count - 1].start_byte = cur_start;
        regions[region_count - 1].end_byte = cur_end;
        regions[region_count - 1].state_sequence = NULL;
        regions[region_count - 1].state_count = 0;
        break;
      }

      if (mem_count == mem_size) {
        //enlarge the mem buffer
        mem_size = mem_size * 2;
        mem=(char *)ck_realloc(mem, mem_size);
      }
    }
  }
  if (mem) ck_free(mem);

  //in case region_count equals zero, it means that the structure of the buffer is broken
  //hence we create one region for the whole buffer
  if ((region_count == 0) && (buf_size > 0)) {
    regions = (region_t *)ck_realloc(regions, sizeof(region_t));
    regions[0].start_byte = 0;
    regions[0].end_byte = buf_size - 1;
    regions[0].state_sequence = NULL;
    regions[0].state_count = 0;

    region_count = 1;
  }

  *region_count_ref = region_count;
  return regions;
}

region_t* extract_requests_ftp(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref)
{
  char *mem;
  unsigned int byte_count = 0;
  unsigned int mem_count = 0;
  unsigned int mem_size = 1024;
  unsigned int region_count = 0;
  region_t *regions = NULL;
  char terminator[2] = {0x0D, 0x0A};

  mem=(char *)ck_alloc(mem_size);

  unsigned int cur_start = 0;
  unsigned int cur_end = 0;
  while (byte_count < buf_size) {

    memcpy(&mem[mem_count], buf + byte_count++, 1);

    //Check if the last two bytes are 0x0D0A
    if ((mem_count > 1) && (memcmp(&mem[mem_count - 1], terminator, 2) == 0)) {
      region_count++;
      regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
      regions[region_count - 1].start_byte = cur_start;
      regions[region_count - 1].end_byte = cur_end;
      regions[region_count - 1].state_sequence = NULL;
      regions[region_count - 1].state_count = 0;

      mem_count = 0;
      cur_start = cur_end + 1;
      cur_end = cur_start;
    } else {
      mem_count++;
      cur_end++;

      //Check if the last byte has been reached
      if (cur_end == buf_size - 1) {
        region_count++;
        regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
        regions[region_count - 1].start_byte = cur_start;
        regions[region_count - 1].end_byte = cur_end;
        regions[region_count - 1].state_sequence = NULL;
        regions[region_count - 1].state_count = 0;
        break;
      }

      if (mem_count == mem_size) {
        //enlarge the mem buffer
        mem_size = mem_size * 2;
        mem=(char *)ck_realloc(mem, mem_size);
      }
    }
  }
  if (mem) ck_free(mem);

  //in case region_count equals zero, it means that the structure of the buffer is broken
  //hence we create one region for the whole buffer
  if ((region_count == 0) && (buf_size > 0)) {
    regions = (region_t *)ck_realloc(regions, sizeof(region_t));
    regions[0].start_byte = 0;
    regions[0].end_byte = buf_size - 1;
    regions[0].state_sequence = NULL;
    regions[0].state_count = 0;

    region_count = 1;
  }

  *region_count_ref = region_count;
  return regions;
}

region_t* extract_requests_mqtt(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref)
{
  unsigned int region_count = 0;
  unsigned int cur_start = 0;
  region_t *regions = NULL;

  while(cur_start < buf_size)
  {
    unsigned int packet_start = cur_start;
    u32 remaining_len = 0;
    u32 encoded_len = 0;
    u32 header_len;
    u32 payload_start;
    u32 cur_end;

    if (mqtt_read_remaining_length(buf, buf_size, cur_start + 1,
                                   &remaining_len, &encoded_len)) {
      cur_end = buf_size - 1;
    } else {
      header_len = 1 + encoded_len;
      payload_start = cur_start + header_len;
      if (remaining_len > buf_size - payload_start)
        cur_end = buf_size - 1;
      else if (remaining_len == 0)
        cur_end = payload_start - 1;
      else
        cur_end = payload_start + remaining_len - 1;
    }

    // Create a region for every request
		region_count++;
		regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
		regions[region_count - 1].start_byte = packet_start;
		regions[region_count - 1].end_byte = cur_end;
		regions[region_count - 1].state_sequence = NULL;
		regions[region_count - 1].state_count = 0;
    // Update the indices
    cur_start = cur_end + 1;
  }

  //in case region_count equals zero, it means that the structure of the buffer is broken
  //hence we create one region for the whole buffer
	if ((region_count == 0) && (buf_size > 0)) {
		regions = (region_t *)ck_realloc(regions, sizeof(region_t));
		regions[0].start_byte = 0;
		regions[0].end_byte = buf_size - 1;
		regions[0].state_sequence = NULL;
		regions[0].state_count = 0;
		region_count = 1;
	}
	*region_count_ref = region_count;
	return regions;
}

region_t* extract_requests_sip(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref)
{
  char *mem;
  unsigned int byte_count = 0;
  unsigned int mem_count = 0;
  unsigned int mem_size = 1024;
  unsigned int region_count = 0;
  region_t *regions = NULL;
  char terminator[2] = {0x0D, 0x0A};

  mem=(char *)ck_alloc(mem_size);

  unsigned int cur_start = 0;
  unsigned int cur_end = 0;
  while (byte_count < buf_size) {

    memcpy(&mem[mem_count], buf + byte_count++, 1);

    //Check if the last bytes match the terminator, and the next ones are a SIP command
    if ((mem_count > 1) && (memcmp(&mem[mem_count - 1], terminator, 1) == 0) &&
	  (((buf_size - byte_count >= 8) && (memcmp(buf + byte_count, "REGISTER", 8)==0) ) ||
	  ((buf_size - byte_count >= 6) && (memcmp(buf + byte_count, "INVITE", 6)==0) ) ||
	  ((buf_size - byte_count >= 3) && (memcmp(buf + byte_count, "ACK", 3)==0) ) ||
	  ((buf_size - byte_count >= 3) && (memcmp(buf + byte_count, "BYE", 3)==0) ) )
	  ) {
      region_count++;
      regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
      regions[region_count - 1].start_byte = cur_start;
      regions[region_count - 1].end_byte = cur_end;
      regions[region_count - 1].state_sequence = NULL;
      regions[region_count - 1].state_count = 0;

      mem_count = 0;
      cur_start = cur_end + 1;
      cur_end = cur_start;
    } else {
      mem_count++;
      cur_end++;

      //Check if the last byte has been reached
      if (cur_end == buf_size - 1) {
        region_count++;
        regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
        regions[region_count - 1].start_byte = cur_start;
        regions[region_count - 1].end_byte = cur_end;
        regions[region_count - 1].state_sequence = NULL;
        regions[region_count - 1].state_count = 0;
        break;
      }

      if (mem_count == mem_size) {
        //enlarge the mem buffer
        mem_size = mem_size * 2;
        mem=(char *)ck_realloc(mem, mem_size);
      }
    }
  }
  if (mem) ck_free(mem);

  //in case region_count equals zero, it means that the structure of the buffer is broken
  //hence we create one region for the whole buffer
  if ((region_count == 0) && (buf_size > 0)) {
    regions = (region_t *)ck_realloc(regions, sizeof(region_t));
    regions[0].start_byte = 0;
    regions[0].end_byte = buf_size - 1;
    regions[0].state_sequence = NULL;
    regions[0].state_count = 0;

    region_count = 1;
  }

  *region_count_ref = region_count;
  return regions;
}

region_t* extract_requests_http(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref)
{
  char *mem;
  unsigned int byte_count = 0;
  unsigned int mem_count = 0;
  unsigned int mem_size = 1024;
  unsigned int region_count = 0;
  region_t *regions = NULL;
  char terminator[4] = {0x0D, 0x0A, 0x0D, 0x0A};

  mem=(char *)ck_alloc(mem_size);

  unsigned int cur_start = 0;
  unsigned int cur_end = 0;
  while (byte_count < buf_size) {

    memcpy(&mem[mem_count], buf + byte_count++, 1);

    //Check if the last four bytes are 0x0D0A0D0A
    if ((mem_count >=4) && (memcmp(&mem[mem_count - 3], terminator, 4) == 0)) {
      region_count++;
      regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
      regions[region_count - 1].start_byte = cur_start;
      regions[region_count - 1].end_byte = cur_end;
      regions[region_count - 1].state_sequence = NULL;
      regions[region_count - 1].state_count = 0;

      mem_count = 0;
      cur_start = cur_end + 1;
      cur_end = cur_start;
    } else {
      mem_count++;
      cur_end++;

      //Check if the last byte has been reached
      if (cur_end == buf_size - 1) {
        region_count++;
        regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
        regions[region_count - 1].start_byte = cur_start;
        regions[region_count - 1].end_byte = cur_end;
        regions[region_count - 1].state_sequence = NULL;
        regions[region_count - 1].state_count = 0;
        break;
      }

      if (mem_count == mem_size) {
        //enlarge the mem buffer
        mem_size = mem_size * 2;
        mem=(char *)ck_realloc(mem, mem_size);
      }
    }
  }
  if (mem) ck_free(mem);

  //in case region_count equals zero, it means that the structure of the buffer is broken
  //hence we create one region for the whole buffer
  if ((region_count == 0) && (buf_size > 0)) {
    regions = (region_t *)ck_realloc(regions, sizeof(region_t));
    regions[0].start_byte = 0;
    regions[0].end_byte = buf_size - 1;
    regions[0].state_sequence = NULL;
    regions[0].state_count = 0;

    region_count = 1;
  }

  *region_count_ref = region_count;
  return regions;
}

region_t* extract_requests_ipp(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref)
{
  char *mem;
  unsigned int byte_count = 0;
  unsigned int mem_count = 0;
  unsigned int mem_size = 1024;
  unsigned int region_count = 0;
  region_t *regions = NULL;
  char terminator[4] = {0x0D, 0x0A, 0x0D, 0x0A};
  char ipp[1] = {0x03};

  mem=(char *)ck_alloc(mem_size);

  unsigned int cur_start = 0;
  unsigned int cur_end = 0;
  while (byte_count < buf_size) {

    memcpy(&mem[mem_count], buf + byte_count++, 1);

    //Check if the last bytes match the HTTP terminator (if data is sent) OR end-of-attributes-tag IPP command (if no data is sent)
    if ((mem_count > 3) && 
    ((memcmp(&mem[mem_count - 3], terminator, 4) == 0) || (memcmp(&mem[mem_count], ipp, 1) == 0)) &&
    ((buf_size - byte_count >= 4) && (memcmp(buf + byte_count, "POST", 4) == 0))
    ) {
      region_count++;
      regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
      regions[region_count - 1].start_byte = cur_start;
      regions[region_count - 1].end_byte = cur_end;
      regions[region_count - 1].state_sequence = NULL;
      regions[region_count - 1].state_count = 0;

      mem_count = 0;
      cur_start = cur_end + 1;
      cur_end = cur_start;
    } else {
      mem_count++;
      cur_end++;

      //Check if the last byte has been reached
      if (cur_end == buf_size - 1) {
        region_count++;
        regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
        regions[region_count - 1].start_byte = cur_start;
        regions[region_count - 1].end_byte = cur_end;
        regions[region_count - 1].state_sequence = NULL;
        regions[region_count - 1].state_count = 0;
        break;
      }

      if (mem_count == mem_size) {
        //enlarge the mem buffer
        mem_size = mem_size * 2;
        mem=(char *)ck_realloc(mem, mem_size);
      }
    }
  }
  if (mem) ck_free(mem);

  //in case region_count equals zero, it means that the structure of the buffer is broken
  //hence we create one region for the whole buffer
  if ((region_count == 0) && (buf_size > 0)) {
    regions = (region_t *)ck_realloc(regions, sizeof(region_t));
    regions[0].start_byte = 0;
    regions[0].end_byte = buf_size - 1;
    regions[0].state_sequence = NULL;
    regions[0].state_count = 0;

    region_count = 1;
  }

  *region_count_ref = region_count;
  return regions;
}
unsigned int* extract_response_codes_tftp(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref)
{
  char *mem;
  unsigned int byte_count = 0;
  unsigned int mem_count = 0;
  unsigned int mem_size = 1024;
  unsigned int *state_sequence = NULL;
  unsigned int state_count = 0;
  char terminator_one[1] = {0x00};
  char terminator_two[1] = {0x03};

  mem=(char *)ck_alloc(mem_size);

  state_count++;
  state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
  state_sequence[state_count - 1] = 0;

  while (byte_count < buf_size) {
    memcpy(&mem[mem_count], buf + byte_count++, 1);

    if ((mem_count > 0) && ((memcmp(&mem[mem_count - 1], terminator_one, 1) == 0) || (memcmp(&mem[mem_count - 1], terminator_two, 1) == 0))) {
      //Extract the response code which is the first 4 bytes
      char temp[5];
      memcpy(temp, mem, 5);
      temp[4] = 0x0;
      unsigned int message_code = (unsigned int) atoi(temp);

      if (message_code == 0) break;

      message_code = get_mapped_message_code(message_code);

      state_count++;
      state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
      state_sequence[state_count - 1] = message_code;
      mem_count = 0;
    } else if (byte_count == buf_size){
      char temp[5];
      memcpy(temp, mem, 5);
      temp[4] = 0x0;
      unsigned int message_code = (unsigned int) atoi(temp);
      if (message_code == 0) break;

      message_code = get_mapped_message_code(message_code);

      state_count++;
      state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
      state_sequence[state_count - 1] = message_code;
      //mem_count = 0;
      break;
    }else{
      mem_count++;
      if (mem_count == mem_size) {
        //enlarge the mem buffer
        mem_size = mem_size * 2;
        mem=(char *)ck_realloc(mem, mem_size);
      }
    }
  }
  if (mem) ck_free(mem);
  *state_count_ref = state_count;
  return state_sequence;
}

unsigned int* extract_response_codes_dhcp(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref)
{
  char *mem;
  unsigned int byte_count = 0;
  unsigned int mem_count = 0;
  unsigned int mem_size = 1024;
  unsigned int *state_sequence = NULL;
  unsigned int state_count = 0;
  char terminator_one[1] = {0x02};
  char terminator_two[1] = {0x04};
  char terminator_three[1] = {0x05};
  char terminator_four[1] = {0x06};

  mem=(char *)ck_alloc(mem_size);

  state_count++;
  state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
  state_sequence[state_count - 1] = 0;

  while (byte_count < buf_size) {
    memcpy(&mem[mem_count], buf + byte_count++, 1);

    if ((mem_count > 240) && (((memcmp(&mem[mem_count - 1], terminator_one, 1) == 0) || (memcmp(&mem[mem_count - 1], terminator_two, 1) == 0))||
     (memcmp(&mem[mem_count - 1], terminator_three, 1) == 0) || (memcmp(&mem[mem_count - 1], terminator_four, 1) == 0))) {
      //Extract the response code which is the at the offset 240, which indicates the option field
      char temp[5];
      memcpy(temp, mem, 5);
      temp[4] = 0x0;
      unsigned int message_code = (unsigned int) atoi(temp);

      if (message_code == 0) break;

      message_code = get_mapped_message_code(message_code);

      state_count++;
      state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
      state_sequence[state_count - 1] = message_code;
      mem_count = 0;
    } else if (byte_count == buf_size){
      char temp[5];
      memcpy(temp, mem, 5);
      temp[4] = 0x0;
      unsigned int message_code = (unsigned int) atoi(temp);
      if (message_code == 0) break;

      message_code = get_mapped_message_code(message_code);

      state_count++;
      state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
      state_sequence[state_count - 1] = message_code;
      //mem_count = 0;
      break;
    }else{
      mem_count++;
      if (mem_count == mem_size) {
        //enlarge the mem buffer
        mem_size = mem_size * 2;
        mem=(char *)ck_realloc(mem, mem_size);
      }
    }
  }
  if (mem) ck_free(mem);
  *state_count_ref = state_count;
  return state_sequence;
}

unsigned int* extract_response_codes_SNTP(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref)
{
  char *mem;
  unsigned int byte_count = 0;
  unsigned int mem_count = 0;
  unsigned int mem_size = 1024;
  unsigned int *state_sequence = NULL;
  unsigned int state_count = 0;
  char terminator_one[1] = {0x24};
  char terminator_two[1] = {0x35};
  char terminator_three[1] = {0x01};
  

  mem=(char *)ck_alloc(mem_size);

  state_count++;
  state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
  state_sequence[state_count - 1] = 0;

  while (byte_count < buf_size) {
    memcpy(&mem[mem_count], buf + byte_count++, 1);

    if ((mem_count > 0) && ((memcmp(&mem[mem_count - 1], terminator_one, 1) == 0) || (memcmp(&mem[mem_count - 1], terminator_two, 1) == 0)
    ||(memcmp(&mem[mem_count - 1], terminator_three, 1) == 0))) {
      //Extract the response code which is the first 4 bytes
     
      unsigned int message_code = read_bytes_to_uint32(
          (unsigned char *)mem, 0, MIN(4, mem_count + 1));
      if (message_code == 0)
      {
        break;

      } 

      message_code = get_mapped_message_code(message_code);

      state_count++;
      state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
      state_sequence[state_count - 1] = message_code;
      mem_count = 0;
    } else if (byte_count == buf_size){
      char temp[5];
      memcpy(temp, mem, 5);
      temp[4] = 0x0;
      unsigned int message_code = (unsigned int) atoi(temp);
      if (message_code == 0) {
        break;
      }

      message_code = get_mapped_message_code(message_code);

      state_count++;
      state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
      state_sequence[state_count - 1] = message_code;
      //mem_count = 0;
      break;
    }else{
      mem_count++;
      if (mem_count == mem_size) {
        //enlarge the mem buffer
        mem_size = mem_size * 2;
        mem=(char *)ck_realloc(mem, mem_size);
      }
    }
  }
  if (mem) ck_free(mem);
  *state_count_ref = state_count;
  return state_sequence;
}

unsigned int* extract_response_codes_NTP(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref)
{
  char *mem;
  unsigned int byte_count = 0;
  unsigned int mem_count = 0;
  unsigned int mem_size = 1024;
  unsigned int *state_sequence = NULL;
  unsigned int state_count = 0;
  char terminator_one[1] = {0x24};
  char terminator_two[1] = {0x35};
  char terminator_three[1] = {0x01};
  

  mem=(char *)ck_alloc(mem_size);

  state_count++;
  state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
  state_sequence[state_count - 1] = 0;

  while (byte_count < buf_size) {
    memcpy(&mem[mem_count], buf + byte_count++, 1);

    if ((mem_count > 0) && ((memcmp(&mem[mem_count - 1], terminator_one, 1) == 0) || (memcmp(&mem[mem_count - 1], terminator_two, 1) == 0)
    ||(memcmp(&mem[mem_count - 1], terminator_three, 1) == 0))) {
      //Extract the response code which is the first 4 bytes
      unsigned int message_code = read_bytes_to_uint32(
          (unsigned char *)mem, 0, MIN(4, mem_count + 1));
      if (message_code == 0)
      {
        break;

      }
      
      message_code = get_mapped_message_code(message_code);

      state_count++;
      state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
      state_sequence[state_count - 1] = message_code;
      mem_count = 0;
    } else if (byte_count == buf_size){
      char temp[5];
      memcpy(temp, mem, 5);
      temp[4] = 0x0;
      unsigned int message_code = (unsigned int) atoi(temp);
      if (message_code == 0) {
        break;
      }

      message_code = get_mapped_message_code(message_code);

      state_count++;
      state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
      state_sequence[state_count - 1] = message_code;
      //mem_count = 0;
      break;
    }else{
      mem_count++;
      if (mem_count == mem_size) {
        //enlarge the mem buffer
        mem_size = mem_size * 2;
        mem=(char *)ck_realloc(mem, mem_size);
      }
    }
  }
  if (mem) ck_free(mem);
  *state_count_ref = state_count;
  return state_sequence;
}


unsigned int* extract_response_codes_SNMP(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref)
{
  char *mem;
  unsigned int byte_count = 0;
  unsigned int mem_count = 0;
  unsigned int mem_size = 1024;
  unsigned int *state_sequence = NULL;
  unsigned int state_count = 0;
  char terminator_one[1] = {0x0A};
  char terminator_two[1] = {0x01};
  char terminator_three[1] = {0x02};
  char terminator_four[1] = {0x03};
  char terminator_five[1] = {0x04};
  char terminator_six[1] = {0x05};
  

  mem=(char *)ck_alloc(mem_size);

  state_count++;
  state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
  state_sequence[state_count - 1] = 0;

  while (byte_count < buf_size) {
    memcpy(&mem[mem_count], buf + byte_count++, 1);
    

    if ((mem_count>7) && ((memcmp(&mem[mem_count - 1], terminator_one, 1) == 0) || (memcmp(&mem[mem_count - 1], terminator_two, 1) == 0)
    ||(memcmp(&mem[mem_count - 1], terminator_three, 1) == 0)||(memcmp(&mem[mem_count-1],terminator_four,1)==0) || (memcmp(&mem[mem_count-1],terminator_five,1)==0)
    ||(memcmp(&mem[mem_count-1],terminator_six,1)==0))) {
      //Extract the response code which is the first 4 bytes
      unsigned int message_code = (unsigned char)mem[byte_count - 1];
      if (message_code == 0)
      {
        break;

      } 

      message_code = get_mapped_message_code(message_code);

      state_count++;
      state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
      state_sequence[state_count - 1] = message_code;
      mem_count = 0;
    } else if (byte_count == buf_size){
      unsigned int message_code = (unsigned char)mem[byte_count - 1];
      if (message_code == 0) {
        break;
      }

      message_code = get_mapped_message_code(message_code);

      state_count++;
      state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
      state_sequence[state_count - 1] = message_code;
      //mem_count = 0;
      break;
    }else{
      mem_count++;
      if (mem_count == mem_size) {
        //enlarge the mem buffer
        mem_size = mem_size * 2;
        mem=(char *)ck_realloc(mem, mem_size);
      }
    }
  }
  if (mem) ck_free(mem);
  *state_count_ref = state_count;
  return state_sequence;
}
unsigned int* extract_response_codes_smtp(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref)
{
  char *mem;
  unsigned int byte_count = 0;
  unsigned int mem_count = 0;
  unsigned int mem_size = 1024;
  unsigned int *state_sequence = NULL;
  unsigned int state_count = 0;
  char terminator[2] = {0x0D, 0x0A};

  mem=(char *)ck_alloc(mem_size);

  state_count++;
  state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
  state_sequence[state_count - 1] = 0;

  while (byte_count < buf_size) {
    memcpy(&mem[mem_count], buf + byte_count++, 1);

    if ((mem_count > 0) && (memcmp(&mem[mem_count - 1], terminator, 2) == 0)) {
      unsigned int message_code;

      if (parse_status_code3(mem, mem_count + 1, 0, &message_code)) {
        mem_count = 0;
        continue;
      }

      message_code = get_mapped_message_code(message_code);

      state_count++;
      state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
      state_sequence[state_count - 1] = message_code;
      mem_count = 0;
    } else {
      mem_count++;
      if (mem_count == mem_size) {
        //enlarge the mem buffer
        mem_size = mem_size * 2;
        mem=(char *)ck_realloc(mem, mem_size);
      }
    }
  }
  if (mem) ck_free(mem);
  *state_count_ref = state_count;
  return state_sequence;
}

unsigned int* extract_response_codes_ssh(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref)
{
   char mem[7];
   unsigned int byte_count = 0;
   unsigned int *state_sequence = NULL;
   unsigned int state_count = 0;

   //Initial state
   state_count++;
   state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
   if (state_sequence == NULL) PFATAL("Unable realloc a memory region to store state sequence");
   state_sequence[state_count - 1] = 0;

   while (byte_count + 6 <= buf_size) {
      memcpy(mem, buf + byte_count, 6);
      byte_count += 6;

      /* If this is the identification message */
      if (!memcmp(mem, "SSH", 3)) {
        //Read until \x0D\x0A
        char tmp = 0x00;
        while (byte_count < buf_size && tmp != 0x0A) {
          memcpy(&tmp, buf + byte_count, 1);
          byte_count += 1;
        }
        if (tmp != 0x0A) break;
        state_count++;
        state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
        if (state_sequence == NULL) PFATAL("Unable realloc a memory region to store state sequence");
        state_sequence[state_count - 1] = 256; //Identification
      } else {
        //Extract the message type and skip the payload and the MAC
        unsigned int message_size = read_bytes_to_uint32((unsigned char *)mem, 0, 4);
        unsigned int bytes_to_skip;

        //Break if the response does not adhere to the known format(s)
        //Normally, it only happens in the last response
        if (message_size < 2) break;

        unsigned char message_code = (unsigned char)mem[5];
        bytes_to_skip = message_size - 2;
        
        /* If this is a KEY exchange related message */
        if ((message_code >= 20) && (message_code <= 49)) {
          //Do nothing
        } else {
          if (bytes_to_skip > UINT_MAX - 8) break;
          bytes_to_skip += 8;
        }
        if (bytes_to_skip > buf_size - byte_count) break;

        message_code = get_mapped_message_code(message_code);

        state_count++;
        state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
        if (state_sequence == NULL) PFATAL("Unable realloc a memory region to store state sequence");
        state_sequence[state_count - 1] = message_code;

        byte_count += bytes_to_skip;
      }
   }
   *state_count_ref = state_count;
   return state_sequence;
}

unsigned int* extract_response_codes_tls(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref)
{
  char *mem;
  unsigned int byte_count = 0;
  unsigned int mem_count = 0;
  unsigned int mem_size = 1024;
  unsigned char content_type, message_type;
  unsigned int *state_sequence = NULL;
  unsigned int state_count = 0;

  mem=(char *)ck_alloc(mem_size);

  //Add initial state
  state_count++;
  state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
  state_sequence[state_count - 1] = 0;

  while (byte_count < buf_size) {

    memcpy(&mem[mem_count], buf + byte_count++, 1);

    //Check if the region buffer length is at least 6 bytes (5 bytes for record header size)
    //the 6th byte could be message type
    if (mem_count >= 6) {
      //1st byte: content type
      //2nd and 3rd byte: TLS version
      //Extract the message size stored in the 4th and 5th bytes
      content_type = mem[0];

      //Check if this is an application data record
      if (content_type != 0x17) {
        message_type = mem[5];
      } else {
        message_type = 0xFF;
      }

      u16 message_size = (u16)read_bytes_to_uint32((unsigned char *)mem, 3, 2);

      //and skip the payload
      unsigned int bytes_to_skip = message_size ? message_size - 1 : 0;
      unsigned int temp_count = 0;
      while ((byte_count < buf_size) && (temp_count < bytes_to_skip)) {
        byte_count++;
        temp_count++;
      }

      if (byte_count < buf_size) {
          byte_count--;
      }

      //add a new response code
      unsigned int message_code = (content_type << 8) + message_type;
      message_code = get_mapped_message_code(message_code);
      state_count++;
      state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
      state_sequence[state_count - 1] = message_code;
      mem_count = 0;
    } else {
      mem_count++;

      if (mem_count == mem_size) {
        //enlarge the mem buffer
        mem_size = mem_size * 2;
        mem=(char *)ck_realloc(mem, mem_size);
      }
    }
  }
  if (mem) ck_free(mem);

  *state_count_ref = state_count;
  return state_sequence;
}

unsigned int* extract_response_codes_dicom(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref)
{
  if (buf_size == 0) {
    *state_count_ref = 0;
    return NULL;
  }

  unsigned int *state_sequence = NULL;
  unsigned int state_count = 0;

  state_count++;
  state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
  state_sequence[state_count - 1] = 0; // initial status code is 0

  state_count++;
  unsigned int message_code = buf[0]; // return PDU type as status code
  message_code = get_mapped_message_code(message_code);
  state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
  state_sequence[state_count - 1] = message_code;

  *state_count_ref = state_count;
  return state_sequence;
};

unsigned int* extract_response_codes_dns(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref)
{
  char *mem;
  unsigned int mem_count = 0;
  unsigned int mem_size = 1024;
  unsigned int *state_sequence = NULL;
  unsigned int state_count = 0;

  mem=(char *)ck_alloc(mem_size);

  state_count++;
  state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
  state_sequence[state_count - 1] = 0;

  for (unsigned int byte_count = 0; byte_count < buf_size; byte_count++) {
    memcpy(&mem[mem_count], buf + byte_count, 1);

    // The original query will be included with the response.
    if ((mem_count >= 12) && (*(mem+mem_count) == 0)) {
      // 4 bytes left of the query. Jump to the answer.
      byte_count += 5;
      mem_count += 5;

      // Save the 3rd & 4th bytes as the response code
      unsigned int message_code = (unsigned int) ((mem[2] << 8) + mem[3]);
      message_code = get_mapped_message_code(message_code);

      state_count++;
      state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
      state_sequence[state_count - 1] = message_code;
      mem_count = 0;
    } else {
      mem_count++;
      if (mem_count == mem_size) {
        //enlarge the mem buffer
        mem_size = mem_size * 2;
        mem=(char *)ck_realloc(mem, mem_size);
      }
    }
  }
  if (mem) ck_free(mem);
  *state_count_ref = state_count;
  return state_sequence;
}

static unsigned char dtls12_version[2] = {0xFE, 0xFD};

// (D)TLS known and custom constants

// the known 1-byte (D)TLS content types
#define CCS_CONTENT_TYPE 0x14
#define ALERT_CONTENT_TYPE 0x15
#define HS_CONTENT_TYPE 0x16
#define APPLICATION_CONTENT_TYPE 0x17
#define HEARTBEAT_CONTENT_TYPE 0x18

// custom content types
#define UNKNOWN_CONTENT_TYPE 0xFF // the content type is unrecognized

// custom handshake types (for handshake content)
#define UNKNOWN_MESSAGE_TYPE 0xFF // when the message type cannot be determined because the message is likely encrypted
#define MALFORMED_MESSAGE_TYPE 0xFE // when message type cannot be determined because the message appears to be malformed

region_t *extract_requests_dtls12(unsigned char* buf, unsigned int buf_size, unsigned int* region_count_ref) {
  unsigned int byte_count = 0;
  unsigned int region_count = 0;
  region_t *regions = NULL;

  unsigned int cur_start = 0;

   while (byte_count < buf_size) {

     //Check if the first three bytes are <valid_content_type><dtls-1.2>
     if ((byte_count > 3 && buf_size - byte_count > 1) &&
     (buf[byte_count] >= CCS_CONTENT_TYPE && buf[byte_count] <= HEARTBEAT_CONTENT_TYPE)  &&
     (memcmp(&buf[byte_count+1], dtls12_version, 2) == 0)) {
       region_count++;
       regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
       regions[region_count - 1].start_byte = cur_start;
       regions[region_count - 1].end_byte = byte_count-1;
       regions[region_count - 1].state_sequence = NULL;
       regions[region_count - 1].state_count = 0;
       cur_start = byte_count;
     } else {

      //Check if the last byte has been reached
      if (byte_count == buf_size - 1) {
        region_count++;
        regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
        regions[region_count - 1].start_byte = cur_start;
        regions[region_count - 1].end_byte = byte_count;
        regions[region_count - 1].state_sequence = NULL;
        regions[region_count - 1].state_count = 0;
        break;
      }
     }

     byte_count ++;
  }

  //in case region_count equals zero, it means that the structure of the buffer is broken
  //hence we create one region for the whole buffer
  if ((region_count == 0) && (buf_size > 0)) {
    regions = (region_t *)ck_realloc(regions, sizeof(region_t));
    regions[0].start_byte = 0;
    regions[0].end_byte = buf_size - 1;
    regions[0].state_sequence = NULL;
    regions[0].state_count = 0;

    region_count = 1;
  }

  *region_count_ref = region_count;
  return regions;
}

// a status code comprises <content_type, message_type> tuples
// message_type varies depending on content_type (e.g. for handshake content, message_type is the handshake message type...)
//
unsigned int* extract_response_codes_dtls12(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref)
{
  unsigned int byte_count = 0;
  unsigned int *state_sequence = NULL;
  unsigned int state_count = 0;
  unsigned int status_code = 0;

  state_count++;
  state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
  state_sequence[state_count - 1] = 0; // initial status code is 0

  while (byte_count < buf_size) {
    // a DTLS 1.2 record has a 13 bytes header, followed by the contained message
    if ( (buf_size - byte_count >= 13) &&
    (buf[byte_count] >= CCS_CONTENT_TYPE && buf[byte_count] <= HEARTBEAT_CONTENT_TYPE)  &&
    (memcmp(&buf[byte_count+1], dtls12_version, 2) == 0)) {
      unsigned char content_type = buf[byte_count];
      unsigned char message_type;
      u32 available = buf_size - byte_count;
      u32 record_length = read_bytes_to_uint32(buf, byte_count+11, 2);
      u32 record_total;

      // the record length exceeds buffer boundaries (not expected)
      if (record_length > available - 13) {
        message_type = MALFORMED_MESSAGE_TYPE;
        record_total = available;
      }
      else {
        record_total = 13 + record_length;
        switch(content_type) {
          case HS_CONTENT_TYPE: ;
            // the minimum size of a correct DTLS 1.2 handshake message is 12 bytes comprising fragment header fields
            if (record_length >= 12) {
              unsigned char hs_msg_type = buf[byte_count+13];
              u32 frag_length = read_bytes_to_uint32(buf, byte_count+22, 3);
              // we can check if the handshake record is encrypted by subtracting fragment length from record length
              // which should yield 12 if the fragment is not encrypted
              // the likelyhood for an encrypted fragment to satisfy this condition is very small
              if (record_length - frag_length == 12) {
                // not encrypted
                message_type = hs_msg_type;
              } else {
                // encrypted handshake message
                message_type = UNKNOWN_MESSAGE_TYPE;
              }
            } else {
                // malformed handshake message
                message_type = MALFORMED_MESSAGE_TYPE;
            }
          break;
          case CCS_CONTENT_TYPE:
            if (record_length == 1) {
              // unencrypted CCS
              unsigned char ccs_msg_type = buf[byte_count+13];
              message_type = ccs_msg_type;
            } else {
              if (record_length > 1) {
                // encrypted CCS
                message_type = UNKNOWN_MESSAGE_TYPE;
              } else {
                // malformed CCS
                message_type = MALFORMED_MESSAGE_TYPE;
              }
            }
          break;
          case ALERT_CONTENT_TYPE:
            if (record_length == 2) {
              // unencrypted alert, the type is sufficient for determining which alert occurred
              // unsigned char level = buf[byte_count+13];
              unsigned char type = buf[byte_count+14];
              message_type = type;
            } else {
              if (record_length > 2) {
                // encrypted alert
                message_type = UNKNOWN_MESSAGE_TYPE;
              } else {
                // malformed alert
                message_type = MALFORMED_MESSAGE_TYPE;
              }
            }
          break;
          case APPLICATION_CONTENT_TYPE:
            // for application messages we cannot determine whether they are encrypted or not
            message_type = UNKNOWN_MESSAGE_TYPE;
          break;
          case HEARTBEAT_CONTENT_TYPE:
            // a heartbeat message is at least 3 bytes long (1 byte type, 2 bytes payload length)
            // unfortunately, telling an encrypted message from an unencrypted message cannot be done reliably due to the variable length of padding
            // hence we just use unknown for either case
            if (record_length >= 3) {
              // unsigned char hb_msg_type = buf[byte_count+13];
              // u32 hb_length = read_bytes_to_uint32(buf, byte_count+14, 2);
              // unkown heartbeat message
              message_type = UNKNOWN_MESSAGE_TYPE;
            } else {
              // malformed heartbeat
              message_type = MALFORMED_MESSAGE_TYPE;
            }
          break;
          default:
            // unknown content and message type, should not be hit
            content_type = UNKNOWN_CONTENT_TYPE;
            message_type = UNKNOWN_MESSAGE_TYPE;
          break;
        }
      }

      status_code = (content_type << 8) + message_type;

      status_code = get_mapped_message_code(status_code);
      state_count++;
      state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
      state_sequence[state_count - 1] = status_code;
      byte_count += record_total;
    } else {
      // we shouldn't really be reaching this code
      byte_count ++;
    }
  }

  *state_count_ref = state_count;
  return state_sequence;
}

unsigned int* extract_response_codes_rtsp(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref)
{
  char *mem;
  unsigned int byte_count = 0;
  unsigned int mem_count = 0;
  unsigned int mem_size = 1024;
  unsigned int *state_sequence = NULL;
  unsigned int state_count = 0;
  char terminator[2] = {0x0D, 0x0A};
  char rtsp[5] = {0x52, 0x54, 0x53, 0x50, 0x2f};

  mem=(char *)ck_alloc(mem_size);

  state_count++;
  state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
  state_sequence[state_count - 1] = 0;

  while (byte_count < buf_size) {
    memcpy(&mem[mem_count], buf + byte_count++, 1);

    //Check if the last two bytes are 0x0D0A
    if ((mem_count > 0) && (memcmp(&mem[mem_count - 1], terminator, 2) == 0)) {
      unsigned int line_len = mem_count + 1;

      if ((line_len >= sizeof(rtsp)) && (memcmp(mem, rtsp, sizeof(rtsp)) == 0)) {
        unsigned int message_code;

        if (parse_status_code3(mem, line_len, 9, &message_code)) {
          mem_count = 0;
          continue;
        }

        message_code = get_mapped_message_code(message_code);

        state_count++;
        state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
        state_sequence[state_count - 1] = message_code;
        mem_count = 0;
      } else {
        mem_count = 0;
      }
    } else {
      mem_count++;
      if (mem_count == mem_size) {
        //enlarge the mem buffer
        mem_size = mem_size * 2;
        mem=(char *)ck_realloc(mem, mem_size);
      }
    }
  }
  if (mem) ck_free(mem);
  *state_count_ref = state_count;
  return state_sequence;
}

unsigned int* extract_response_codes_ftp(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref)
{
  char *mem;
  unsigned int byte_count = 0;
  unsigned int mem_count = 0;
  unsigned int mem_size = 1024;
  unsigned int *state_sequence = NULL;
  unsigned int state_count = 0;
  char terminator[2] = {0x0D, 0x0A};

  mem=(char *)ck_alloc(mem_size);

  state_count++;
  state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
  state_sequence[state_count - 1] = 0;

  while (byte_count < buf_size) {
    memcpy(&mem[mem_count], buf + byte_count++, 1);
    if ((mem_count > 0) && (memcmp(&mem[mem_count - 1], terminator, 2) == 0)) {
      unsigned int line_len = mem_count + 1;
      unsigned int message_code;
      int final_line = 0;

      if (line_len >= 4 && mem[3] == ' ') {
        final_line = 1;
      } else if (byte_count >= buf_size) {
        final_line = 1;
      } else if (line_len >= 3 && byte_count + 2 < buf_size &&
                 isdigit((unsigned char)buf[byte_count]) &&
                 memcmp(&mem[0], &buf[byte_count], 3) != 0) {
        final_line = 1;
      }

      if (!final_line ||
          parse_status_code3(mem, line_len, 0, &message_code)) {
        mem_count = 0;
        continue;
      }

      message_code = get_mapped_message_code(message_code);

      state_count++;
      state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
      state_sequence[state_count - 1] = message_code;
      mem_count = 0;
    } else {
      mem_count++;
      if (mem_count == mem_size) {
        //enlarge the mem buffer
        mem_size = mem_size * 2;
        mem=(char *)ck_realloc(mem, mem_size);
      }
    }
  }
  if (mem) ck_free(mem);
  *state_count_ref = state_count;
  return state_sequence;
}

unsigned int* extract_response_codes_mqtt(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref)
{
	unsigned int byte_count = 0;
	unsigned int *state_sequence = NULL;
	unsigned int state_count = 0;
	// Initial state of the response state machine
	state_count++;
	state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
	state_sequence[state_count - 1] = 0;
  while(byte_count < buf_size)
  {
    unsigned char message_code = buf[byte_count];
    u32 remaining_len = 0;
    u32 encoded_len = 0;
    u32 header_len;
    u32 payload_start;

    if (mqtt_read_remaining_length(buf, buf_size, byte_count + 1,
                                   &remaining_len, &encoded_len))
      break;

    header_len = 1 + encoded_len;
    payload_start = byte_count + header_len;

    // Determine whether it's a response packet
    if (message_code == 0x20 || message_code == 0x40 ||
        message_code == 0x50 || message_code == 0x62 ||
        message_code == 0x70 || message_code == 0x90 ||
        message_code == 0xB0 || message_code == 0xD0 ||
        message_code == 0xE0 || message_code == 0xF0)
    {
      // Get the response code(message type) from the packet
      message_code = get_mapped_message_code(message_code);

      // Create a new state 
			state_count++;
			state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
			state_sequence[state_count - 1] = message_code;
    }

    if (remaining_len > buf_size - payload_start) break;
    byte_count = payload_start + remaining_len;
  }
	*state_count_ref = state_count;
	return state_sequence;
}

unsigned int* extract_response_codes_sip(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref)
{
  char *mem;
  unsigned int byte_count = 0;
  unsigned int mem_count = 0;
  unsigned int mem_size = 1024;
  unsigned int *state_sequence = NULL;
  unsigned int state_count = 0;
  char terminator[2] = {0x0D, 0x0A};
  char sip[4] = {0x53, 0x49, 0x50, 0x2f};

  mem=(char *)ck_alloc(mem_size);

  state_count++;
  state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
  state_sequence[state_count - 1] = 0;

  while (byte_count < buf_size) {
    memcpy(&mem[mem_count], buf + byte_count++, 1);

    //Check if the last two bytes are 0x0D0A
    if ((mem_count > 0) && (memcmp(&mem[mem_count - 1], terminator, 2) == 0)) {
      unsigned int line_len = mem_count + 1;

      if ((line_len >= sizeof(sip)) && (memcmp(mem, sip, sizeof(sip)) == 0)) {
        unsigned int message_code;

        if (parse_status_code3(mem, line_len, 8, &message_code)) {
          mem_count = 0;
          continue;
        }

        message_code = get_mapped_message_code(message_code);

        state_count++;
        state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
        state_sequence[state_count - 1] = message_code;
        mem_count = 0;
      } else {
        mem_count = 0;
      }
    } else {
      mem_count++;
      if (mem_count == mem_size) {
        //enlarge the mem buffer
        mem_size = mem_size * 2;
        mem=(char *)ck_realloc(mem, mem_size);
      }
    }
  }
  if (mem) ck_free(mem);
  *state_count_ref = state_count;
  return state_sequence;
}

unsigned int* extract_response_codes_http(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref)
{
  char *mem;
  unsigned int byte_count = 0;
  unsigned int mem_count = 0;
  unsigned int mem_size = 1024;
  unsigned int *state_sequence = NULL;
  unsigned int state_count = 0;
  char terminator[2] = {0x0D, 0x0A};
  char http[5] = {0x48, 0x54, 0x54, 0x50, 0x2f};

  mem=(char *)ck_alloc(mem_size);

  state_count++;
  state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
  state_sequence[state_count - 1] = 0;

  while (byte_count < buf_size) {
    memcpy(&mem[mem_count], buf + byte_count++, 1);

    //Check if the last two bytes are 0x0D0A
    if ((mem_count > 0) && (memcmp(&mem[mem_count - 1], terminator, 2) == 0)) {
      unsigned int line_len = mem_count + 1;

      if ((line_len >= sizeof(http)) && (memcmp(mem, http, sizeof(http)) == 0)) {
        unsigned int message_code;

        if (parse_status_code3(mem, line_len, 9, &message_code)) {
          mem_count = 0;
          continue;
        }

        message_code = get_mapped_message_code(message_code);

        state_count++;
        state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
        state_sequence[state_count - 1] = message_code;
        mem_count = 0;
      } else {
        mem_count = 0;
      }
    } else {
      mem_count++;
      if (mem_count == mem_size) {
        //enlarge the mem buffer
        mem_size = mem_size * 2;
        mem=(char *)ck_realloc(mem, mem_size);
      }
    }
  }
  if (mem) ck_free(mem);
  *state_count_ref = state_count;
  return state_sequence;
}

unsigned int* extract_response_codes_ipp(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref)
{
  char *mem;
  unsigned int byte_count = 0;
  unsigned int mem_count = 0;
  unsigned int mem_size = 1024;
  unsigned int *state_sequence = NULL;
  unsigned int state_count = 0;
  char terminatorHTTP[4] = {0x0D, 0x0A, 0x0D, 0x0A};
  char http[5] = {0x48, 0x54, 0x54, 0x50, 0x2F};
  unsigned int message_code = 0;

  mem = (char *)ck_alloc(mem_size);

  //Initial state
  state_count++;
  state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));
  if (state_sequence == NULL) PFATAL("Unable realloc a memory region to store state sequence");
  state_sequence[state_count - 1] = 0;

  while (byte_count < buf_size) {
    memcpy(&mem[mem_count], buf + byte_count++, 1);
    //Check if the last two bytes are 0x0D0A0D0A
    if ((mem_count > 3) && (memcmp(&mem[mem_count - 3], terminatorHTTP, 4) == 0)) {
      unsigned int line_len = mem_count + 1;

      if ((line_len >= sizeof(http)) && (memcmp(mem, http, sizeof(http)) == 0)) {

        if (parse_status_code3(mem, line_len, 9, &message_code)) {
          mem_count = 0;
          continue;
        }

        if (message_code == 200) {
          if (byte_count + 3 >= buf_size) {
            mem_count = 0;
            continue;
          }

          //Extract IPP response code (bytes 3 and 4)
          unsigned int third = (unsigned int) buf[byte_count + 2];
          unsigned int fourth = (unsigned int) buf[byte_count + 3];

          //200 + IPP code to not confuse initial 0 state with successful-ok 0 state
          message_code += (unsigned int) (10 * third + fourth);
        }

        message_code = get_mapped_message_code(message_code);

        state_count++;
        state_sequence = (unsigned int *)ck_realloc(state_sequence, state_count * sizeof(unsigned int));

        if (state_sequence == NULL) PFATAL("Unable realloc a memory region to store state sequence");

        state_sequence[state_count - 1] = message_code;

        mem_count = 0;
      } else {
        mem_count = 0;
      }

    } else {

      mem_count++;
      if (mem_count == mem_size) {
        //enlarge the mem buffer
        mem_size = mem_size * 2;
        mem=(char *)ck_realloc(mem, mem_size);
      }
    }
  }

  if (mem) ck_free(mem);
  *state_count_ref = state_count;
  return state_sequence;
}

// kl_messages manipulating functions

klist_t(lms) *construct_kl_messages(u8* fname, region_t *regions, u32 region_count)
{
  FILE *fseed = NULL;
  long file_size;
  fseed = fopen(fname, "rb");
  if (fseed == NULL) PFATAL("Cannot open seed file %s", fname);

  if (fseek(fseed, 0, SEEK_END)) PFATAL("Cannot seek seed file %s", fname);
  file_size = ftell(fseed);
  if (file_size < 0) PFATAL("Cannot get seed file size %s", fname);
  if ((unsigned long)file_size > UINT_MAX)
    FATAL("Seed file %s is too large", fname);
  if (!aflnet_regions_are_valid(regions, region_count, (u32)file_size))
    PFATAL("Invalid AFLNet request regions for %s", fname);

  klist_t(lms) *kl_messages = kl_init(lms);
  u32 i;

  for (i = 0; i < region_count; i++) {
    u32 start;
    u32 len;

    if (aflnet_region_span(&regions[i], (u32)file_size, &start, &len))
      PFATAL("Invalid AFLNet request region in %s", fname);
    if (fseek(fseed, start, SEEK_SET))
      PFATAL("Cannot seek seed file %s", fname);

    //Create a new message
    message_t *m = (message_t *) ck_alloc(sizeof(message_t));
    m->mdata = (char *) ck_alloc(len);
    m->msize = len;
    if (m->mdata == NULL) PFATAL("Unable to allocate memory region to store new message");
    if (fread(m->mdata, 1, len, fseed) != len)
      PFATAL("Unable to read seed region from %s", fname);

    //Insert the message to the linked list
    *kl_pushp(lms, kl_messages) = m;
  }

  if (fseed != NULL) fclose(fseed);
  return kl_messages;
}

void delete_kl_messages(klist_t(lms) *kl_messages)
{
  /* Free all messages in the list before destroying the list itself */
  message_t *m;

  int ret = kl_shift(lms, kl_messages, &m);
  while (ret == 0) {
    if (m) {
      ck_free(m->mdata);
      ck_free(m);
    }
    ret = kl_shift(lms, kl_messages, &m);
  }

  /* Finally, destroy the list */
	kl_destroy(lms, kl_messages);
}

kliter_t(lms) *get_last_message(klist_t(lms) *kl_messages)
{
  kliter_t(lms) *it;
  it = kl_begin(kl_messages);
  while (kl_next(it) != kl_end(kl_messages)) {
    it = kl_next(it);
  }
  return it;
}


u32 save_kl_messages_to_file(klist_t(lms) *kl_messages, u8 *fname, u8 replay_enabled, u32 max_count)
{
  u8 *mem = NULL;
  u32 len = 0, message_size = 0;
  kliter_t(lms) *it;

  s32 fd = open(fname, O_WRONLY | O_CREAT | O_BINARY, 0600);
  if (fd < 0) PFATAL("Unable to create file '%s'", fname);

  u32 message_count = 0;
  //Iterate through all messages in the linked list
  for (it = kl_begin(kl_messages); it != kl_end(kl_messages) && message_count < max_count; it = kl_next(it)) {
    message_size = kl_val(it)->msize;
    if (replay_enabled) {
		  mem = (u8 *)ck_realloc(mem, 4 + len + message_size);

      //Save packet size first
      u32 *psize = (u32*)&mem[len];
      *psize = message_size;

      //Save packet content
      memcpy(&mem[len + 4], kl_val(it)->mdata, message_size);
      len = 4 + len + message_size;
    } else {
      mem = (u8 *)ck_realloc(mem, len + message_size);

      //Save packet content
      memcpy(&mem[len], kl_val(it)->mdata, message_size);
      len = len + message_size;
    }
    message_count++;
  }

  //Write everything to file & close the file
  ck_write(fd, mem, len, fname);
  close(fd);

  //Free the temporary buffer
  ck_free(mem);

  return len;
}

region_t* convert_kl_messages_to_regions(klist_t(lms) *kl_messages, u32* region_count_ref, u32 max_count)
{
  region_t *regions = NULL;
  kliter_t(lms) *it;

  u32 region_count = 1;
  s32 cur_start = 0, cur_end = 0;
  //Iterate through all messages in the linked list
  for (it = kl_begin(kl_messages); it != kl_end(kl_messages) && region_count <= max_count ; it = kl_next(it)) {
    regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));

    cur_end = cur_start + kl_val(it)->msize - 1;
    if (cur_end < 0) PFATAL("End_byte cannot be negative");

    regions[region_count - 1].start_byte = cur_start;
    regions[region_count - 1].end_byte = cur_end;
    regions[region_count - 1].state_sequence = NULL;
    regions[region_count - 1].state_count = 0;

    cur_start = cur_end + 1;
    region_count++;
  }

  *region_count_ref = region_count - 1;
  return regions;
}

// Network communication functions

int net_send(aflnet_socket_t sockfd, struct timeval timeout, char *mem, unsigned int len) {
  unsigned int byte_count = 0;
  int n;
  int rv = aflnet_wait_socket(sockfd, 1, 1);

  aflnet_set_socket_timeout(sockfd, SO_SNDTIMEO, timeout);
  if (rv > 0) {
    while (byte_count < len) {
      aflnet_sleep_us(10);
      n = send(sockfd, &mem[byte_count], len - byte_count, MSG_NOSIGNAL);
      if (n == 0) return byte_count;
      if (n == AFLNET_SOCKET_ERROR) return -1;
      byte_count += n;
    }
  }
  return byte_count;
}

int net_recv(aflnet_socket_t sockfd, struct timeval timeout, int poll_w, char **response_buf, unsigned int *len) {
  char temp_buf[1000];
  int n;
  int rv = aflnet_wait_socket(sockfd, 0, poll_w);

  aflnet_set_socket_timeout(sockfd, SO_RCVTIMEO, timeout);
  // data received
  if (rv > 0) {
    n = recv(sockfd, temp_buf, sizeof(temp_buf), 0);
    if ((n < 0) && !aflnet_socket_would_block(aflnet_socket_last_error())) {
      return 1;
    }
    while (n > 0) {
      aflnet_sleep_us(10);
      if (*len > UINT_MAX - (unsigned int)n - 1) return 1;
      *response_buf = (char *)ck_realloc(*response_buf, *len + n + 1);
      memcpy(&(*response_buf)[*len], temp_buf, n);
      (*response_buf)[(*len) + n] = '\0';
      *len = *len + n;
      n = recv(sockfd, temp_buf, sizeof(temp_buf), 0);
      if ((n < 0) && !aflnet_socket_would_block(aflnet_socket_last_error())) {
        return 1;
      }
    }
  } else
    if (rv < 0) // an error was returned
      return 1;

  // rv == 0 poll timeout or all data pending after poll has been received successfully
  return 0;
}

// Utility function

void save_regions_to_file(region_t *regions, unsigned int region_count, unsigned char *fname)
{
  int fd;
  FILE* fp;

  fd = open(fname, O_WRONLY | O_CREAT | O_EXCL, 0600);

  if (fd < 0) return;

  fp = fdopen(fd, "w");

  if (!fp) {
    close(fd);
    return;
  }

  int i;

  for(i=0; i < region_count; i++) {
     fprintf(fp, "Region %d - Start: %d, End: %d\n", i, regions[i].start_byte, regions[i].end_byte);
  }

  fclose(fp);
}

int str_split(char* a_str, const char* a_delim, char **result, int a_count)
{
	char *token;
	int count = 0;

	/* count number of tokens */
	/* get the first token */
	char* tmp1 = aflnet_strdup(a_str);
	if (!tmp1) return 1;
	token = strtok(tmp1, a_delim);

	/* walk through other tokens */
	while (token != NULL)
	{
		count++;
		token = strtok(NULL, a_delim);
	}

	if (count != a_count)
	{
		free(tmp1);
		return 1;
	}

	/* split input string, store tokens into result */
	count = 0;
	/* get the first token */
	token = strtok(a_str, a_delim);

	/* walk through other tokens */

	while (token != NULL)
	{
		result[count] = token;
		count++;
		token = strtok(NULL, a_delim);
	}

	free(tmp1);
	return 0;
}

void str_rtrim(char* a_str)
{
	char* ptr = a_str;
	int count = 0;
	while ((*ptr != '\n') && (*ptr != '\t') && (*ptr != ' ') && (count < strlen(a_str))) {
		ptr++;
		count++;
	}
	if (count < strlen(a_str)) {
		*ptr = '\0';
	}
}

int parse_net_config(u8* net_config, u8* protocol, u8** ip_address, u32* port)
{
  char  buf[256];
  char **tokens;
  int tokenCount = 3;

  if (strlen((char *)net_config) >= sizeof(buf)) return 1;

  tokens = (char**)malloc(sizeof(char*) * (tokenCount));
  if (!tokens) return 1;

  snprintf(buf, sizeof(buf), "%s", (char *)net_config);
  str_rtrim(buf);

  if (!str_split(buf, "/", tokens, tokenCount))
  {
      if (!strcmp(tokens[0], "tcp:")) {
        *protocol = PRO_TCP;
      } else if (!strcmp(tokens[0], "udp:")) {
        *protocol = PRO_UDP;
      } else {
        free(tokens);
        return 1;
      }

      /* Host names are resolved later by getaddrinfo(). */
      *ip_address = (u8 *)aflnet_strdup(tokens[1]);
      if (!*ip_address) {
        free(tokens);
        return 1;
      }

      if (aflnet_parse_port(tokens[2], port)) {
        free(*ip_address);
        free(tokens);
        return 1;
      }
  } else {
    free(tokens);
    return 1;
  }
  free(tokens);
  return 0;
}

int aflnet_protocol_uses_udp(const char *protocol)
{
  return !strcmp(protocol, "DTLS12") || !strcmp(protocol, "DNS") ||
         !strcmp(protocol, "SIP");
}

int aflnet_connect(aflnet_socket_t *sockfd_ref, u8 net_protocol,
                   const char *host, u32 port, struct timeval timeout)
{
  struct addrinfo hints, *res = NULL, *it;
  char service[16];
  int socktype;

  *sockfd_ref = AFLNET_INVALID_SOCKET;

  if (aflnet_init_sockets()) return 1;

  if (net_protocol == PRO_TCP) socktype = SOCK_STREAM;
  else if (net_protocol == PRO_UDP) socktype = SOCK_DGRAM;
  else return 1;

  snprintf(service, sizeof(service), "%u", port);
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = socktype;

  if (getaddrinfo(host, service, &hints, &res)) return 1;

  for (it = res; it; it = it->ai_next) {
    int n;

    for (n = 0; n < 1000; n++) {
      *sockfd_ref = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
      if (*sockfd_ref == AFLNET_INVALID_SOCKET) {
        aflnet_sleep_us(1000);
        continue;
      }

      aflnet_set_socket_timeout(*sockfd_ref, SO_SNDTIMEO, timeout);

      if (connect(*sockfd_ref, it->ai_addr, (int)it->ai_addrlen) == 0) break;
      aflnet_close_socket(*sockfd_ref);
      *sockfd_ref = AFLNET_INVALID_SOCKET;
      aflnet_sleep_us(1000);
    }

    if (n < 1000) break;
  }

  freeaddrinfo(res);
  return *sockfd_ref == AFLNET_INVALID_SOCKET;
}

int aflnet_parse_replay_target(const char *target_arg, const char *protocol,
                               u8 *net_protocol, u8 **host, u32 *port)
{
  if (strstr(target_arg, "://")) {
    return parse_net_config((u8 *)target_arg, net_protocol, host, port);
  }

  *net_protocol = aflnet_protocol_uses_udp(protocol) ? PRO_UDP : PRO_TCP;
  *host = (u8 *)aflnet_strdup("127.0.0.1");
  if (!*host) return 1;

  if (aflnet_parse_port(target_arg, port)) {
    free(*host);
    *host = NULL;
    return 1;
  }

  return 0;
}

u8* state_sequence_to_string(unsigned int *stateSequence, unsigned int stateCount) {
  u32 i = 0;

  u8 *out = NULL;

  char strState[STATE_STR_LEN];
  size_t len = 0;
  for (i = 0; i < stateCount; i++) {
    //Limit the loop to shorten the output string
    if ((i >= 2) && (stateSequence[i] == stateSequence[i - 1]) && (stateSequence[i] == stateSequence[i - 2])) continue;
    unsigned int stateID = stateSequence[i];
    if (i == stateCount - 1) {
      snprintf(strState, STATE_STR_LEN, "%d", (int) stateID);
    } else {
      snprintf(strState, STATE_STR_LEN, "%d-", (int) stateID);
    }
    out = (u8 *)ck_realloc(out, len + strlen(strState) + 1);
    memcpy(&out[len], strState, strlen(strState) + 1);
    len=strlen(out);
    //As Linux limit the size of the file name
    //we set a fixed upper bound here
    if (len > 150 && (i + 1 < stateCount)) {
      snprintf(strState, STATE_STR_LEN, "%s", "end-at-");
      out = (u8 *)ck_realloc(out, len + strlen(strState) + 1);
      memcpy(&out[len], strState, strlen(strState) + 1);
      len=strlen(out);

      snprintf(strState, STATE_STR_LEN, "%d", (int) stateSequence[stateCount - 1]);
      out = (u8 *)ck_realloc(out, len + strlen(strState) + 1);
      memcpy(&out[len], strState, strlen(strState) + 1);
      len=strlen(out);
      break;
    }
  }
  return out;
}


void hexdump(unsigned char *msg, unsigned char * buf, int start, int end) {
  printf("%s : ", msg);
  for (int i=start; i<=end; i++) {
    printf("%02x", buf[i]);
  }
  printf("\n");
}


u32 read_bytes_to_uint32(unsigned char* buf, unsigned int offset, int num_bytes) {
  u32 val = 0;
  for (int i=0; i<num_bytes; i++) {
    val = (val << 8) + buf[i+offset];
  }
  return val;
}

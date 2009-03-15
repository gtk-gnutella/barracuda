/*
 * Copyright (c) 2006 Christian Biere <christianbiere@gmx.de>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "lib/common.h"

#include <poll.h>

#include "lib/append.h"
#include "lib/base32.h"
#include "lib/compat.h"
#include "lib/ggep.h"
#include "lib/net_addr.h"
#include "lib/nettools.h"
#include "lib/utf8.h"

#define GNUTELLA_MAX_PAYLOAD (64 * 1024) /* 64 KiB */

#define GGEP_MAGIC   ((unsigned char) 0xC3)

static int verbosity;

static void
usage(int status)
{
  fprintf(stderr, "Usage: barracuda [-DH] [FILE]\n");
  fprintf(stderr, "   -D: There are dump headers.\n");
  fprintf(stderr, "   -H: Skip a Gnutella or HTTP-like handshake.\n");
  fprintf(stderr, " FILE: A network dump or browse host data.\n");
  fprintf(stderr, "       If not specified input is read from stdin.\n\n");
  exit(status);
}

enum dump_header_flags {
  DH_F_UDP  = (1 << 0),
  DH_F_TCP  = (1 << 1),
  DH_F_IPV4 = (1 << 2),
  DH_F_IPV6 = (1 << 3),
  DH_F_TO   = (1 << 4),
  DH_F_CTRL = (1 << 5),

  NUM_DH_F
};

struct dump_header {
  uint8_t flags;
  uint8_t addr[16];
  uint8_t port[2];
};

struct gnutella_guid {
  uint8_t data[16];
};

struct gnutella_header {
  struct gnutella_guid guid;
  uint8_t type;
  uint8_t ttl;
  uint8_t hops;
  uint8_t size[4];  /* little-endian */
};

struct gnutella_qhit_header {
  uint8_t hits;
  uint8_t port[2]; /* little-endian */
  uint8_t addr[4]; /* network byte-order */
  uint8_t speed[4]; /* speed + flags */
};

struct gnutella_qhit_item {
  uint8_t index[4]; /* little-endian */
  uint8_t size[4];  /* little-endian */
};

enum gnutella_packet_type {
  GPT_PING      = 0x00,
  GPT_PONG      = 0x01,
  GPT_QRP       = 0x30,
  GPT_VMSG_PRIV = 0x31,
  GPT_VMSG_STD  = 0x32,
  GPT_PUSH      = 0x40,
  GPT_QUERY     = 0x80,
  GPT_QHIT      = 0x81,
  GPT_HSEP      = 0xCD
};

static const char *
escape_buffer(const char *src, size_t src_len)
{
  static char *buf;
  static size_t buf_size;

  if (src_len < (size_t) -1 / 4) {
    char *p;
    size_t n;

    n = src_len * 4 + 1;
    if (buf_size < n) {
      buf_size = n;
      DO_FREE(buf);
      buf = malloc(buf_size);
    }
    p = append_escaped_chars(buf, &buf_size, src, src_len);
    *p = '\0';
    return buf;
  } else {
    return NULL;
  }
}

static const char *
dump_header_addr_to_string(const struct dump_header *dh)
{
  in_port_t port = peek_be16(dh->port);

  if (DH_F_IPV4 & dh->flags) {
    return net_addr_port_to_string(net_addr_peek_ipv4(&dh->addr[0]), port);
  } else if (DH_F_IPV6 & dh->flags) {
    return net_addr_port_to_string(net_addr_peek_ipv6(&dh->addr[0]), port);
  } else {
    return "<unknown>";
  }
}

static const char *
dump_header_ctrl_to_string(const struct dump_header *dh)
{
  if (DH_F_CTRL & dh->flags) {
    return ", prioritary";
  } else {
    return "";
  }
}

static const char *
dump_header_protocol_to_string(const struct dump_header *dh)
{
  if (DH_F_UDP & dh->flags) {
    return "UDP";
  } else if (DH_F_TCP & dh->flags) {
    return "TCP";
  } else {
    return "<unknown>";
  }
}

static void
print_dump_from_header(const struct dump_header *dh)
{
  printf("From: %s (%s)\n",
    dump_header_addr_to_string(dh),
    dump_header_protocol_to_string(dh));
}

static void
print_dump_to_header(const struct dump_header *dh)
{
  printf("To: %s (%s%s)\n",
    dump_header_addr_to_string(dh),
    dump_header_protocol_to_string(dh),
    dump_header_ctrl_to_string(dh));
}

static int
wait_for_fd(const int fd)
{
  static const struct pollfd zero_fds;
  struct pollfd fds;
  int ret;

  fds = zero_fds;
  fds.fd = fd;
  fds.events = POLLIN;
  do {
    ret = poll(&fds, 1, -1);
  } while (0 == ret || (-1 == ret && is_temporary_error(errno)));
  return ret;
}

static size_t
fill_buffer_from_fd(const int fd, void * const dst, const size_t buf_size)
{
  char *buf = dst;
  size_t pos = 0;

  RUNTIME_ASSERT(buf);
  RUNTIME_ASSERT(buf_size > 0);
  RUNTIME_ASSERT((size_t) -1 != buf_size);

  while (pos < buf_size) {
    ssize_t ret;
    size_t size;

    size = buf_size - pos;
    ret = read(fd, &buf[pos], size);
    if ((ssize_t) -1 == ret) {
      if (!is_temporary_error(errno) || wait_for_fd(fd) < 0) {
        return -1;
      }
    } else if (0 == ret) {
      if (pos != 0) {
        errno = EIO;
        return -1;
      }
      return 0; /* EOF */
    } else {
      RUNTIME_ASSERT((size_t) ret <= size);
      pos += (size_t) ret;
    }
  }

  return 1;
}

static size_t
buffer_inflate(void *dst, size_t dst_size, const void *src, size_t src_size)
{
    static z_stream zs_inflate;
    static z_streamp zsp_inflate;
    size_t dlen;
    int ret;

    zs_inflate.next_in = (void *) src;
    zs_inflate.avail_in = src_size;
    zs_inflate.next_out = dst;
    zs_inflate.avail_out = dst_size;
    if (!zsp_inflate) {
      zs_inflate.zalloc = NULL;
      zs_inflate.zfree = NULL;
      zs_inflate.opaque = NULL;
      zsp_inflate = &zs_inflate;
      ret = inflateInit(zsp_inflate);
    } else {
      ret = inflateReset(zsp_inflate);
    }
    switch (ret) {
    case Z_OK:
      break;
    case Z_MEM_ERROR:
    case Z_VERSION_ERROR:
    default:
      fprintf(stderr, "inflateInit() failed: %s", 
        zs_inflate.msg ? zs_inflate.msg : "Unknown error");
      return -1;
    }
         
    do {
      ret = inflate(zsp_inflate, Z_FINISH);
      if (Z_OK == ret && 0 == zs_inflate.avail_out) {
          ret = Z_BUF_ERROR;
          break;
      }
    } while (Z_OK == ret);
      
    switch (ret) {
    case Z_STREAM_END:
      dlen = zs_inflate.total_out;
      break;
    case Z_OK:
      RUNTIME_ASSERT(0);
    case Z_BUF_ERROR:
    case Z_DATA_ERROR:
    case Z_MEM_ERROR:
    case Z_NEED_DICT:
    case Z_STREAM_ERROR:
    default:
      fprintf(stderr, "inflate() failed: %s", 
        zs_inflate.msg ? zs_inflate.msg : "Unknown error");
      dlen = (size_t) -1;
    }
  
    ret = inflateReset(zsp_inflate);
    switch (ret) {
    case Z_OK:
      break;
    case Z_STREAM_ERROR:
    default:
      fprintf(stderr, "inflateReset() failed: %s", 
        zs_inflate.msg ? zs_inflate.msg : "Unknown error");
      break;
    }

    return dlen;
}

static const char *
packet_type_to_string(uint8_t type)
{
  static char buf[] = "0x00";
  static const char hexa[] = "0123456789abcdef";

  switch ((enum gnutella_packet_type) type) {
  case GPT_PING:      return "PING";
  case GPT_PONG:      return "PONG";
  case GPT_QRP:       return "QRP";
  case GPT_VMSG_PRIV: return "VMSG.PRIV";
  case GPT_VMSG_STD:  return "VMSG.STD";
  case GPT_PUSH:      return "PUSH";
  case GPT_QUERY:     return "QUERY";
  case GPT_QHIT:      return "QHIT";
  case GPT_HSEP:      return "HSEP";
  }

  buf[2] = hexa[(type >> 4) & 0xf];
  buf[3] = hexa[type & 0xf];
  return buf;
}

static void 
handle_peer_array(const char *data, size_t size)
{
  size_t pos;
  
  if (0 == size) {
    printf(" <No payload>");
    return;
  }
  if (0 != (size % 6)) {
    printf(" <Invalid length (%lu); not a multiple of 6>",
        (unsigned long) size);
    return;
  }
  for (pos = 0; pos < size; pos += 6) {
    if (pos > 0) {
      printf(",");
    }
    printf(" %s",
        net_addr_port_to_string(net_addr_peek_ipv4(&data[pos]),
          peek_le16(&data[pos + 4])));
  }
}

static uint64_t
peek_variable_integer(const char *data, size_t size)
{
  uint64_t v;
  unsigned i, n;
  
  v = 0;
  n = MIN(8, size);
  for (i = 0; i < n; i++) {
    v |= (data[i] & 0xff) << (8 * i);
  }
  return v;
}

static void 
handle_variable_integer(const char *data, size_t size)
{
  char buf[UINT64_DEC_BUFLEN];

  print_uint64(buf, sizeof buf, peek_variable_integer(data, size));
  printf(": %s", buf);
}
 
static void 
handle_ggep_alt(const char *data, size_t size)
{
  handle_peer_array(data, size);
}

static void 
handle_ggep_push(const char *data, size_t size)
{
  handle_peer_array(data, size);
}

static void 
handle_ggep_ip(const char *data, size_t size)
{
  handle_peer_array(data, size);
}

static void 
handle_ggep_udpnfw(const char *data, size_t size)
{
  handle_peer_array(data, size);
}

static void 
handle_ggep_ipp(const char *data, size_t size)
{
  handle_peer_array(data, size);
}

static void 
handle_ggep_du(const char *data, size_t size)
{
  handle_variable_integer(data, size);
}
 
static void 
handle_ggep_h(const char *data, size_t size)
{
  static const struct {
    const char * const prefix;
    const uint8_t base;
  } hashes[] = {
    { NULL, 0 },
    { "urn:sha1:", 32 },
    { "urn:bitprint:", 32 },
    { "urn:md5:", 64 },
    { "urn:uuid:", 16 },
    { "urn:md4:", 64 },
  };
  unsigned char h;
  const char *prefix;
  uint8_t base;

  if (size < 1) {
    printf(" <No payload>");
    return;
  }
  
  h = data[0];
  if (h < ARRAY_LEN(hashes)) {
    prefix = hashes[h].prefix;
    base = hashes[h].base;
  } else {
    prefix = NULL;
    base = 0;
  }

  if (prefix && base) {
    printf(": %s", prefix);

    if (32 == base) {
      char base32[256];
      size_t base32_len;

      base32_len = base32_encode(base32, sizeof base32, &data[1], size - 1);
      base32[base32_len] = '\0';
      printf("%s", base32);
    }
  } else {
    printf(": <%u> \"%s\"", h, escape_buffer(&data[1], size - 1));
  }
}

static void 
handle_ggep_ct(const char *data, size_t size)
{
  if (size < 1) {
    printf(" <No payload>");
  } else {
    uint64_t v;
    
    v = peek_variable_integer(data, size);
    if (v > (uint32_t) -1) {
      handle_variable_integer(data, size);
    } else {
      char buf[64], *p = buf;
      
      p = print_iso8601_date(p, sizeof buf, v);
      *p = '\0';
      printf(": %s", buf);
    }
  }
}

static void 
handle_ggep_m(const char *data, size_t size)
{
  if (size < 1) {
    printf(" <No payload>");
  } else {
    uint64_t mask = peek_variable_integer(data, size);

    if (mask & 0x04) {
      printf(" audio");
    }
    if (mask & 0x08) {
      printf(" video");
    }
    if (mask & 0x10) {
      printf(" text");
    }
    if (mask & 0x20) {
      printf(" image");
    }
    if (mask & 0x40) {
      printf(" win");
    }
    if (mask & 0x80) {
      printf(" non-win");
    }
  }
}

static int
handle_ggep(const char *data, size_t size)
{
  char ggep_buf[4096];
  ggep_t gtx;

  if (!ggep_decode(&gtx, data, size)) {
    return -1;
  }
  
  for (;;) {
    char id_name[GGEP_ID_BUFLEN];
    const char *data_ptr;
    size_t data_len;
    ggep_id_t id;
    int ret;

    ret = ggep_next(&gtx, id_name);
    if (0 == ret)
      break;

    if (-1 == ret) {
      /* Could not get next GGEP block */
      break;
    }

    printf("GGEP \"%s\"", id_name);
    id = ggep_map_id_name(id_name, NULL);
    if (GGEP_ID_INVALID == id) {
      printf(" <Unknown GGEP ID>\n");
    }

    data_len = ggep_data(&gtx, &data_ptr, ggep_buf, sizeof ggep_buf);
    if ((size_t) -1 == data_len) {
      if (verbosity > 0) {
        fprintf(stderr, "Decoding of GGEP block failed\n");
      }
      printf("<GGEP decoding failure>\n");
      continue;
    }

    switch (id) {
    case GGEP_ID_ALT:     handle_ggep_alt(data_ptr, data_len); break;
    case GGEP_ID_CT:      handle_ggep_ct(data_ptr, data_len); break;
    case GGEP_ID_DU:      handle_ggep_du(data_ptr, data_len); break;
    case GGEP_ID_H:       handle_ggep_h(data_ptr, data_len); break;
    case GGEP_ID_IPP:     handle_ggep_ipp(data_ptr, data_len); break;
    case GGEP_ID_IP:      handle_ggep_ip(data_ptr, data_len); break;
    case GGEP_ID_UDPNFW:  handle_ggep_udpnfw(data_ptr, data_len); break;
    case GGEP_ID_M:       handle_ggep_m(data_ptr, data_len); break;
    case GGEP_ID_PUSH:    handle_ggep_push(data_ptr, data_len); break;
    default:
      if (data_len > 0) {
        printf(" raw data (%lu bytes): \"%s\"",
          (unsigned long) data_len, escape_buffer(data_ptr, data_len));
      } else {
        printf(" <No payload>");
      }
    }

    printf("\n");
  }

  return 0;
}

static void
handle_extension(const char * const data, const size_t size)
{
  if (size > 0) {
    const char *g_ptr;

    g_ptr = memchr(data, GGEP_MAGIC, size);
    if (g_ptr) {
      size_t g_len = &data[size] - g_ptr;
      handle_ggep(g_ptr, g_len);
    }
    printf("Raw data: \"%s\"\n", escape_buffer(data, size));
  }
}

static void
handle_qhit(const char *data, size_t size)
{
  const struct gnutella_qhit_header *header;
  const struct gnutella_guid *guid;
  const struct gnutella_qhit_item *item;
  size_t guid_offset = size - sizeof *guid;
  unsigned hits;
  size_t pos;
  
  RUNTIME_ASSERT(size <= GNUTELLA_MAX_PAYLOAD);
  
  if (size < sizeof *header) {
    fprintf(stderr, "handle_qhit(): Too little payload for header.\n");
    return;
  }
  header = cast_to_const_void_ptr(data);
  
  hits = (unsigned char) header->hits;
  printf("Hits: %u\n", hits);
  printf("Address: %s\n",
    net_addr_port_to_string(net_addr_peek_ipv4(cast_to_const_char_ptr(header->addr)),
      peek_le16(header->port)));
  printf("Speed: %lu\n", (unsigned long) peek_le32(header->speed));

  if (size < sizeof *header + sizeof *guid) {
    fprintf(stderr, "handle_qhit(): Insufficient payload for query hit.\n");
    return;
  }
  if (size >= sizeof *header + sizeof *guid) {
    
    guid = cast_to_const_void_ptr(&data[guid_offset]);
    printf("Servent ID: %08lx-%08lx-%08lx-%08lx\n",
        (unsigned long) peek_be32(&guid->data[0]),
        (unsigned long) peek_be32(&guid->data[4]),
        (unsigned long) peek_be32(&guid->data[8]),
        (unsigned long) peek_be32(&guid->data[12]));
  }
  printf("----\n");

  pos = sizeof *header;
  for (/* NOTHING */; hits > 0; hits--) {
    const char *nul_ptr;
   
    if (pos >= guid_offset || guid_offset - pos < sizeof *item + 2)
      break;

    item = cast_to_const_void_ptr(&data[pos]);
    printf("Index: %lu\n", (unsigned long) peek_le32(item->index));
    printf("Size:  %lu\n", (unsigned long) peek_le32(item->size));

    pos += sizeof *item; 

    nul_ptr = memchr(&data[pos], 0, guid_offset - pos);
    if (!nul_ptr) {
      fprintf(stderr, "handle_qhit(): Non-terminated filename.\n");
      return;
    } else {
      size_t len;

      len = (nul_ptr - &data[pos]);
      if (len > (((size_t) -1) / 4 - 1)) {
        fprintf(stderr, "handle_qhit(): Filename is too long.\n");
        /* Ignore */
      } else {
        const char *p;
        size_t avail;
        
        printf("Filename: ");

        avail = len;
        p = &data[pos];
        while (avail > 0) {
          uint32_t cp;
          cp = utf8_decode(p, avail);
          if ((uint32_t) -1 != cp) {
            uint8_t u_len, i;

            u_len = utf8_first_byte_length_hint((unsigned char) *p);
            RUNTIME_ASSERT(u_len > 0);
            RUNTIME_ASSERT(avail >= u_len);
            avail -= u_len;

            if (cp >= 0x20 && cp != 0x7f) {
              for (i = 0; i < u_len; i++) {
                putchar((unsigned char) p[i]);
              }
            } else {
              char ch = cp & 0xff;
              printf("%s", escape_buffer(&ch, 1)); 
            }
            
            p += u_len;
          } else {
            if (verbosity > 0) {
              fprintf(stderr, "handle_qhit(): Invalid UTF-8.\n");
            }
            break;
          }
        }
      }
      printf("\n");

      pos += len;
    }

    RUNTIME_ASSERT(nul_ptr);
    RUNTIME_ASSERT(&data[pos] == nul_ptr);
    RUNTIME_ASSERT('\0' == *nul_ptr);

    pos++;
    RUNTIME_ASSERT(pos <= guid_offset);

    nul_ptr = memchr(&data[pos], 0, guid_offset - pos);
    if (!nul_ptr) {
      fprintf(stderr, "handle_qhit(): Non-terminated extension block.\n");
      return;
    } else if (nul_ptr != &data[pos]) {
      size_t len = nul_ptr - &data[pos];
      
      printf("Extension size:  %lu\n", (unsigned long) len);
     
      handle_extension(&data[pos], len);
      pos += len;
    }

    RUNTIME_ASSERT(nul_ptr);
    RUNTIME_ASSERT(&data[pos] == nul_ptr);
    RUNTIME_ASSERT('\0' == *nul_ptr);

    pos++;
    RUNTIME_ASSERT(pos <= guid_offset);

    printf("------\n");
  }

  if (hits > 0) {
    fprintf(stderr, "handle_qhit(): Expected %u more hits.\n", hits);
  }

  if (pos < guid_offset) {
      static const unsigned vendor_id_len = 4;
      
      printf("Extended QHD size:  %lu\n", (unsigned long) guid_offset - pos);
      if (guid_offset - pos >= vendor_id_len) {

        printf("Vendor ID: %s\n", escape_buffer(&data[pos], vendor_id_len));

        pos += vendor_id_len;
        if (pos < guid_offset) {
          uint8_t open_data_size = data[pos];
          bool has_ggep = false;
          
          printf("Open data size:  %u\n", open_data_size);
          pos++;

          if (open_data_size > guid_offset - pos) {
            printf("Open data size is too large.\n");
            return;
          }

          if (open_data_size >= 2) {
            uint8_t mask = data[pos];
            uint8_t value = data[pos + 1];
          
            printf("mask:  0x%02x\n", mask);
            printf("value: 0x%02x\n", value);
            
            if (0x20 & mask) {
              has_ggep = 0x20 & value;
              printf("Has GGEP: %s\n", has_ggep ? "yes" : "no");
            }
            if (0x10 & mask) {
              printf("Has speed: %s\n", (0x10 & value) ? "yes" : "no");
            }
            if (0x08 & mask) {
              printf("Has uploaded: %s\n", (0x08 & value) ? "yes" : "no");
            }
            if (0x04 & mask) {
              printf("Busy: %s\n", (0x04 & value) ? "yes" : "no");
            }
            /* mask and value are swapped */
            if (0x01 & value) {
              printf("Must push: %s\n", (0x01 & mask) ? "yes" : "no");
            }
          }

          pos += open_data_size;

          if (pos < guid_offset) {
            size_t priv_data_size = guid_offset - pos;
            static const char id_deflate[] = "{deflate}";
            const char *priv_data, *x;
            
            priv_data = &data[pos];
            priv_data_size = guid_offset - pos;
            
            printf("Private data area size:  %lu\n",
              (unsigned long) priv_data_size);

            handle_extension(priv_data, priv_data_size);

            x = compat_memmem(priv_data, priv_data_size,
                    id_deflate, STATIC_STRLEN(id_deflate));
            if (x) {
              char buf[64 * 1024];
              const char *src;
              size_t n, src_len;

              src = &x[STATIC_STRLEN(id_deflate)];
              src_len = priv_data_size - STATIC_STRLEN(id_deflate);
              n = buffer_inflate(buf, sizeof buf, src, src_len);
              if ((size_t) -1 != n) {
                printf("Inflated:  %s\n", escape_buffer(buf, n));
              }
            }

            pos += priv_data_size;
          }

          RUNTIME_ASSERT(pos == guid_offset);
        }
      }
  }
  
  printf("----\n");
}

static void
handle_query(const struct gnutella_header *header,
  const char * const data, const size_t size)
{
  const char *end;

  if (size < 2) {
    printf("Too short:  %s\n", escape_buffer(data, size));
  } else {
    uint16_t flags;

    flags = peek_be16(data);
    if (flags & (1 << 15)) {
      int is_firewalled = flags & (1 << 14);
      int want_xml = flags & (1 << 13);
      int leaf_guided = flags & (1 << 12);
      int ggep_h = flags & (1 << 11);
      int is_oob = flags & (1 << 10);
      int rudp_supp = flags & (1 << 9);
      int bit8 = flags & (1 << 8);
      
      printf("Flags:  %s%s%s%s%s%s%s\n"
        , is_firewalled ? "firewalled " : ""
        , want_xml ? "XML " : ""
        , leaf_guided ? "leaf-guided " : ""
        , ggep_h ? "GGEP/H " : ""
        , is_oob ? "OOB " : ""
        , rudp_supp ? "RUDP " : ""
        , bit8 ? "bit8 " : ""
      );
      if (is_oob) {
        printf("OOB address:  %s\n",
          net_addr_port_to_string(net_addr_peek_ipv4(&header->guid.data[0]),
            peek_le16(&header->guid.data[13]))
        );
      }
    } else {
      printf("Flags:  0x%04X\n", flags);
    }

    end = memchr(&data[2], '\0', size - 2);
    if (end) {
      end++;
    } else {
      end = &data[size];
    }
    printf("Query:  \"%s\"\n", escape_buffer(&data[2], (end - &data[2]) - 1));

    if (&data[size] != end) {
      size_t ext_len;
      
      ext_len = &data[size] - end;
      if ('\0' == data[size - 1]) {
        ext_len--;
      }
      handle_extension(end, ext_len);
    }
  }
}

static void
handle_ping(const char * const data, const size_t size)
{
  handle_extension(data, size);
}

static void
handle_pong(const char * const data, const size_t size)
{
  if (size < 14) {
    printf("Too short:  %s\n", escape_buffer(data, size));
  } else {
    printf("Source: %s\n",
      net_addr_port_to_string(net_addr_peek_ipv4(&data[2]), peek_le16(data)));
    printf("Files:  %lu\n", (unsigned long) peek_le32(&data[6]));
    printf("Volume: %lu KiB\n", (unsigned long) peek_le32(&data[10]));

    if (size > 14) {
      handle_extension(&data[14], size - 14);
    }
  }
}

static void
handle_qrp(const char *data, size_t size)
{
  (void) data;
  (void) size;
}

#define VC(a,b,c,d) ((uint32_t) ((a) << 24 | (b) << 16 | (c) << 8 | (d)))

enum vendor_code {
  VC_BEAR = VC('B','E','A','R'),
  VC_GNUC = VC('G','N','U','C'),
  VC_GTKG = VC('G','T','K','G'),
  VC_LIME = VC('L','I','M','E'),
  VC_NULL = VC(0,0,0,0)
};


static void
handle_vmsg_oob_reply_ack(const struct gnutella_header *header,
  const char *data, size_t size)
{
  (void) header;

  if (size < 9) {
    printf("Too short:  %s\n", escape_buffer(data, size));
  } else {
    printf("Requested: %u\n", (uint8_t) data[8]);
    if (size > 9) {
      handle_extension(&data[9], size - 9);
    }
  }
}

static void
handle_vmsg_oob_reply(const struct gnutella_header *header,
  const char *data, size_t size)
{
  (void) header;

  if (size < 9) {
    printf("Too short:  %s\n", escape_buffer(data, size));
  } else {
    printf("Hits: %u\n", (uint8_t) data[8]);
    if (size > 9) {
      handle_extension(&data[9], size - 9);
    }
  }
}

static void
handle_vmsg_time_sync_request(const struct gnutella_header *header,
  const char *data, size_t size)
{
  (void) header;

  if (size < 9) {
    printf("Too short:  %s\n", escape_buffer(data, size));
  } else {
    bool used_ntp = data[8] & 0x1;

    printf("NTP: %s\n", used_ntp ? "yes" : "no");

    if (size > 9) {
      handle_extension(&data[9], size - 9);
    }
  }
}

static void
handle_vmsg_time_sync_reply(const struct gnutella_header *header,
    const char *data, size_t size)
{
  if (size < 17) {
    printf("Too short:  %s\n", escape_buffer(data, size));
  } else {
    bool used_ntp = data[8] & 0x1;
    char buf[32], *p;

    printf("NTP: %s\n", used_ntp ? "yes" : "no");

    p = print_iso8601_date(buf, sizeof buf, peek_be32(&header->guid.data[0]));
    *p = '\0';
    printf("T1: %s (%lu us)\n",
      buf, (unsigned long) peek_be32(&header->guid.data[4]));

    p = print_iso8601_date(buf, sizeof buf, peek_be32(&data[9]));
    *p = '\0';
    printf("T2: %s (%lu us)\n",
      buf, (unsigned long) peek_be32(&data[13]));

    p = print_iso8601_date(buf, sizeof buf, peek_be32(&header->guid.data[8]));
    *p = '\0';
    printf("T3: %s (%lu us)\n",
      buf, (unsigned long) peek_be32(&header->guid.data[12]));

    if (size > 17) {
      handle_extension(&data[17], size - 17);
    }
  }
}

static void
handle_vmsg_port(const struct gnutella_header *header,
  const char *data, size_t size)
{
  const char *base = &data[8];
  const size_t len = size - 8;
  (void) header;
  if (len == 2) {
    printf("Port: %u\n", peek_le16(base));
  } else {
    handle_extension(base, len);
  }
}

static void
handle_vmsg_addr_port(const struct gnutella_header *header,
  const char *data, size_t size)
{
  const char *base = &data[8];
  const size_t len = size - 8;
  (void) header;
  if (len == 6) {
    printf("Address: %s\n", net_addr_port_to_string(
            net_addr_peek_ipv4(&base[0]), peek_le16(&base[4])));
  } else {
    handle_extension(base, len);
  }
}

static void
handle_vmsg_dummy(const struct gnutella_header *header,
  const char *data, size_t size)
{
  (void) header;
  handle_extension(&data[8], size - 8);
}

static const struct vmsg_head {
  enum vendor_code vendor;
  uint16_t selector;
  uint16_t version;
  const char *name;
  void (*handler)(const struct gnutella_header *header,
                    const char *data, size_t size);
} vmsg_table[] = {
  { VC_NULL,  0, 0, "Messages Supported",     handle_vmsg_dummy },
  { VC_NULL, 10, 0, "Features Supported",     handle_vmsg_dummy },
  { VC_BEAR,  4, 1, "Hops Flow",              handle_vmsg_dummy },
  { VC_BEAR,  7, 1, "TCP Connect Back",       handle_vmsg_dummy },
  { VC_BEAR, 11, 1, "Query Status Request",   handle_vmsg_dummy },
  { VC_BEAR, 12, 1, "Query Status Response",  handle_vmsg_dummy },
  { VC_GTKG,  7, 1, "UDP Connect Back",       handle_vmsg_dummy },
  { VC_GTKG,  7, 2, "UDP Connect Back",       handle_vmsg_dummy },
  { VC_GTKG,  9, 1, "Time Sync Request",      handle_vmsg_time_sync_request },
  { VC_GTKG, 10, 1, "Time Sync Reply",        handle_vmsg_time_sync_reply },
  { VC_GTKG, 21, 1, "Push-Proxy Cancel",      handle_vmsg_dummy },
  { VC_GTKG, 22, 1, "Node Info Request",      handle_vmsg_dummy },
  { VC_GTKG, 23, 1, "Node Info Reply",        handle_vmsg_dummy },
  { VC_LIME, 11, 1, "OOBv1 Reply ACK",        handle_vmsg_oob_reply_ack },
  { VC_LIME, 11, 2, "OOBv2 Reply ACK",        handle_vmsg_oob_reply_ack },
  { VC_LIME, 11, 3, "OOBv3 Reply ACK",        handle_vmsg_oob_reply_ack },
  { VC_LIME, 12, 1, "OOBv1 Reply Indication", handle_vmsg_oob_reply },
  { VC_LIME, 12, 2, "OOBv2 Reply Indication", handle_vmsg_oob_reply },
  { VC_LIME, 12, 3, "OOBv3 Reply Indication", handle_vmsg_oob_reply },
  { VC_LIME, 13, 1, "OOB Proxy Veto",         handle_vmsg_dummy },
  { VC_LIME, 21, 1, "Push-Proxy Request",     handle_vmsg_dummy },
  { VC_LIME, 21, 2, "Push-Proxy Request",     handle_vmsg_dummy },
  { VC_LIME, 22, 1, "Push-Proxy ACK",         handle_vmsg_port },
  { VC_LIME, 22, 2, "Push-Proxy ACK",         handle_vmsg_addr_port },
  { VC_LIME, 23, 1, "HEAD Ping",              handle_vmsg_dummy },
  { VC_LIME, 23, 2, "HEAD Ping",              handle_vmsg_dummy },
  { VC_LIME, 24, 1, "HEAD Pong",              handle_vmsg_dummy },
  { VC_LIME, 24, 2, "HEAD Pong",              handle_vmsg_dummy },
};

static void
handle_vmsg_priv(const struct gnutella_header *header,
    const char *data, size_t size)
{
  if (size < 8) {
    printf("Too short:  %s\n", escape_buffer(data, size));
  } else {
    char vendor[32], *p;
    size_t vendor_size = sizeof vendor;
    struct vmsg_head vh;
    unsigned i;

    p = append_escaped_chars(vendor, &vendor_size, data, 4);
    *p = '\0';

    vh.vendor = peek_be32(&data[0]);
    vh.selector = peek_le16(&data[4]);
    vh.version = peek_le16(&data[6]);
    printf("%s/%uv%u", vendor, vh.selector, vh.version);

    for (i = 0; i < ARRAY_LEN(vmsg_table); i++) {
      if (
        vmsg_table[i].vendor == vh.vendor &&
        vmsg_table[i].selector == vh.selector &&
        vmsg_table[i].version == vh.version
      ) {
        printf(" %s\n", vmsg_table[i].name);
        vmsg_table[i].handler(header, data, size);
        break;
      }
    }

    if (ARRAY_LEN(vmsg_table) == i) {
      printf("\n");
      handle_extension(&data[8], size - 8);
    }
  }
}

static void
handle_vmsg_std(const char *data, size_t size)
{
  (void) data;
  (void) size;
}

static void
handle_push(const char *data, size_t size)
{
  if (size < 26) {
    fprintf(stderr, "handle_push(): Too small\n");
    return;
  }
  printf("ServentID: %08lx-%08lx-%08lx-%08lx\n",
      (unsigned long) peek_be32(&data[0]),
      (unsigned long) peek_be32(&data[4]),
      (unsigned long) peek_be32(&data[8]),
      (unsigned long) peek_be32(&data[12]));
  printf("Index: %lu\n", (unsigned long) peek_le32(&data[16]));
  printf("Target: %s\n",
      net_addr_port_to_string(net_addr_peek_ipv4(&data[20]),
        peek_le16(&data[24])));

  handle_extension(&data[26], size - 26);
}

static void
handle_hsep(const char *data, size_t size)
{
  (void) data;
  (void) size;
}

void
utf8_regression_1(void)
{
  uint32_t i;
  unsigned valid = 0;

  for (i = 0; i < 0xffffffffUL; i++) {
    static char data[5];
    static char hit[0x10FFFFU + 1];
    uint32_t d;

    if (0 == (i % (((uint32_t) -1) / 100))) {
      printf("i=%u\n", i / (((uint32_t) -1) / 100));
    }

    poke_be32(data, i);
    d = utf8_decode(data, 4);
    if ((uint32_t) -1 == d)
      continue;

    if (d > 0x10ffffU || utf32_is_non_character(d) || utf32_is_surrogate(d)) {
      printf("data: %02x %02x %02x %02x\n",
          (unsigned char) data[0],
          (unsigned char) data[1],
          (unsigned char) data[2],
          (unsigned char) data[3]);
      printf("d: U+%lx\n", (unsigned long) d);
      printf("i: %lu\n", (unsigned long) i);
      RUNTIME_ASSERT(d <= 0x10ffffU);
      RUNTIME_ASSERT(!utf32_is_non_character(d));
      RUNTIME_ASSERT(!utf32_is_surrogate(d));
    }

    if (!hit[d]) {
      hit[d] = 1;
      valid++;
    }

    {
      unsigned n;
      char buf[4];

      n = utf8_encode(d, buf);
      RUNTIME_ASSERT(n > 0);
      RUNTIME_ASSERT(n <= 4);
      RUNTIME_ASSERT(n == utf8_first_byte_length_hint(data[0]));

      if (0 != memcmp(data, buf, n)) {
        printf("buf:  %02x %02x %02x %02x\n",
            (unsigned char) buf[0],
            (unsigned char) buf[1],
            (unsigned char) buf[2],
            (unsigned char) buf[3]);
        printf("data: %02x %02x %02x %02x\n",
            (unsigned char) data[0],
            (unsigned char) data[1],
            (unsigned char) data[2],
            (unsigned char) data[3]);
        printf("d: U+%lx\n", (unsigned long) i);
        printf("i: %lu\n", (unsigned long) i);
        printf("n: %u\n", n);
        RUNTIME_ASSERT(0);
      }
    }
  }
  printf("valid=%u\n", valid);

  printf("PASSED\n");
}

void
utf8_regression_2(void)
{
  uint32_t i;

  for (i = 0; i < 0x10ffffU; i++) {
    static char buf[5];
    uint32_t d;
    unsigned n;

    memset(buf, 0, sizeof buf);
    n = utf8_encode(i, buf);
    RUNTIME_ASSERT(n <= 4);
    if (utf32_is_surrogate(i) || utf32_is_non_character(i)) {
      if (0 != n) {
        printf("i=U+%x, n=%u\n", n, i);
        RUNTIME_ASSERT(0 == n);
      }
      continue;
    }
    if (n <= 0) {
      printf("n=%u\n", n);
      RUNTIME_ASSERT(n > 0);
    }
    d = utf8_decode(buf, n);
    if (d != i) {
      printf("buf: %02x %02x %02x %02x\n",
          (unsigned char) buf[0],
          (unsigned char) buf[1],
          (unsigned char) buf[2],
          (unsigned char) buf[3]);
      printf("i: U+%lx\n", (unsigned long) i);
      printf("d: U+%lx\n", (unsigned long) d);
      printf("n: %u\n", n);
      RUNTIME_ASSERT(d == i);
    }
  }

  printf("PASSED\n");
}

static int
skip_handshake(int fd)
{
  char ch, last = 0;
  int empty_lines = 0;

  if (fd < 0) {
    errno = EBADF;
    return -1;
  }

  for (;;) {
    int ret;

    ret = fill_buffer_from_fd(fd, &ch, 1);
    switch (ret) {
      case 0:
      case (size_t) -1:
        return -1;
      case 1:
        break;
      default:
        RUNTIME_ASSERT(0);
    }

    if ('\n' == last && ('\r' == ch || '\n' == ch)) {
      empty_lines++;
    }
    last = ch;

    if (1 == empty_lines && '\n' == ch)
      break;
  }

  return 0;
}


static void
safe_read(const int fd, void * const dst, const size_t buf_size)
{
  size_t ret = fill_buffer_from_fd(fd, dst, buf_size);
  switch (ret) {
  case 0:
    exit(EXIT_SUCCESS);
  case (size_t) -1:
    fprintf(stderr, "Error: Could not fill packet buffer: %s\n",
        strerror(errno));
    exit(EXIT_FAILURE);
  case 1:
    break;
  default:
    RUNTIME_ASSERT(0);
  }
}

int
main(int argc, char *argv[])
{
  const char *filename;
  bool skip_hs = false;
  bool with_dump_headers = false;
  int fd, c;

  setvbuf(stdout, NULL, _IOLBF, 0);
  
  while (-1 != (c = getopt(argc, argv, "DHh"))) {
    switch (c) {
    case 'h':
      usage(EXIT_SUCCESS);
      break;

    case 'H':
      skip_hs = true;
      break;
     
    case 'D':
      with_dump_headers = true;
      break;
     
    default:
      fprintf(stderr, "Unsupported option: -- %c\n", c);
      usage(EXIT_FAILURE);
    }
  }
  argc -= optind;
  argv += optind;

  if (argc > 1) {
    fprintf(stderr,
      "Error: "
      "Specify exactly one filename or none to read from the standard input."
      "\n");
    usage(EXIT_FAILURE);
  }

  filename = argv[0];
  if (filename) {
    fd = open(filename, O_RDONLY, 0);
    if (fd < 0) {
      fprintf(stderr, "open(\"%s\", O_RDONLY, 0) failed: %s\n",
        filename, strerror(errno));
      exit(EXIT_FAILURE);
    }
  } else {
    fd = STDIN_FILENO;
  }

  /* Discard the handshake */
  if (skip_hs) {
    if (0 != skip_handshake(fd)) {
      fprintf(stderr, "Failed to skip handshake\n");
      exit(EXIT_FAILURE);
    }
    printf("Skipped handshake\n");
  }
 
  for (;;) {
    struct gnutella_header header;
    static char *payload;
    size_t ret;
    uint32_t payload_size;
    
    STATIC_ASSERT(23 == sizeof header);

    if (!payload) {
      payload = malloc(GNUTELLA_MAX_PAYLOAD);
      if (!payload) {
        fprintf(stderr, "malloc(%lu) failed: %s",
            (unsigned long) GNUTELLA_MAX_PAYLOAD, strerror(errno));
        return -1;
      }
    }

    if (with_dump_headers) {
      struct dump_header dh;
      safe_read(fd, &dh, sizeof dh);

      if (dh.flags & DH_F_TO) {
        struct dump_header dh_from;
        safe_read(fd, &dh_from, sizeof dh_from);
        print_dump_from_header(&dh_from);
        print_dump_to_header(&dh);
      } else {
        print_dump_from_header(&dh);
      }
    }

    ret = fill_buffer_from_fd(fd, &header, sizeof header);
    switch (ret) {
    case 0:
      fprintf(stderr, "Error: Unexpected end of file.\n");
      exit(EXIT_FAILURE);
    case (size_t) -1:
      fprintf(stderr, "Error: Could not fill packet buffer: %s\n",
          strerror(errno));
      exit(EXIT_FAILURE);
    case 1:
      break;
    default:
      RUNTIME_ASSERT(0);
    }

    payload_size = peek_le32(header.size);
    printf("GUID: %08lx-%08lx-%08lx-%08lx\n",
        (unsigned long) peek_be32(&header.guid.data[0]),
        (unsigned long) peek_be32(&header.guid.data[4]),
        (unsigned long) peek_be32(&header.guid.data[8]),
        (unsigned long) peek_be32(&header.guid.data[12]));
    printf("Type: %s\n", packet_type_to_string(header.type));
    printf("TTL:  %u\n", (unsigned char) header.ttl);
    printf("Hops: %u\n", (unsigned char) header.hops);
    printf("Size: %lu\n", (unsigned long) payload_size);
    printf("--\n");
   
    if (payload_size > GNUTELLA_MAX_PAYLOAD) {
      fprintf(stderr, "Error: Message is too large.\n");
      return -1;
    }

    if (payload_size > 0) {
      ret = fill_buffer_from_fd(fd, payload, payload_size);
      switch (ret) {
        case 0:
        case (size_t) -1:
          exit(EXIT_FAILURE);
        case 1:
          break;
        default:
          RUNTIME_ASSERT(0);
      }
    }

    switch ((enum gnutella_packet_type) header.type) {
    case GPT_PING:      handle_ping(payload, payload_size); break;
    case GPT_PONG:      handle_pong(payload, payload_size); break;
    case GPT_QRP:       handle_qrp(payload, payload_size); break;
    case GPT_VMSG_PRIV: handle_vmsg_priv(&header, payload, payload_size); break;
    case GPT_VMSG_STD:  handle_vmsg_std(payload, payload_size); break;
    case GPT_PUSH:      handle_push(payload, payload_size); break;
    case GPT_QUERY:     handle_query(&header, payload, payload_size); break;
    case GPT_QHIT:      handle_qhit(payload, payload_size); break;
    case GPT_HSEP:      handle_hsep(payload, payload_size); break;
    }
    printf("==========\n");

  }

  return 0;
}

/* vi: set ai et ts=2 sts=2 sw=2 cindent: */

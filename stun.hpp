#ifndef TINYSTUN_HPP
#define TINYSTUN_HPP

#include <arpa/inet.h>
#include <string.h>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/time.h>

#include <map>
#include <set>
#include <thread>
#include <atomic>

#include "rng.hpp"

extern int h_errno;

struct stun_header
{
  uint16_t msgtype;
  uint16_t msglen;
  uint32_t id[4];
  uint8_t ies[0];
} __attribute__((packed));
typedef struct stun_header stun_header_t;

struct stun_attr
{
  unsigned short attr;
  unsigned short len;
  uint8_t value[0];
} __attribute__((packed));
typedef struct stun_attr stun_attr_t;

struct stun_addr
{
  uint8_t unused;
  uint8_t family;
  uint16_t port;
  uint32_t addr;
} __attribute__((packed));
typedef struct stun_addr stun_addr_t;

#define STUN_IGNORE (0)
#define STUN_ACCEPT (1)

#define STUN_BINDREQ 0x0001
#define STUN_BINDRESP 0x0101
#define STUN_BINDERR 0x0111
#define STUN_SECREQ 0x0002
#define STUN_SECRESP 0x0102
#define STUN_SECERR 0x0112
#define STUN_MAPPED_ADDRESS 0x0001
#define STUN_RESPONSE_ADDRESS 0x0002
#define STUN_CHANGE_REQUEST 0x0003
#define STUN_SOURCE_ADDRESS 0x0004
#define STUN_CHANGED_ADDRESS 0x0005
#define STUN_USERNAME 0x0006
#define STUN_PASSWORD 0x0007
#define STUN_MESSAGE_INTEGRITY 0x0008
#define STUN_ERROR_CODE 0x0009
#define STUN_UNKNOWN_ATTRIBUTES 0x000a
#define STUN_REFLECTED_FROM 0x000b
#define STUN_XOR_MAPPED_ADDRESS 0x0020
#define STUN_SERVERNAME 0x0022

#define STUN_XOR_MAPPED_ADDRESS2 0x8020
#define STUN_SOFTWARE 0x8022
#define STUN_ALTERNATE_SERVER 0x8023
#define STUN_FINGERPRINT 0x8028

#define STUN_MAX_BUFFER_SIZE 1024

#define STUN_NAT_SYMN 0x1
#define STUN_NAT_SYMF 0x2
#define STUN_NAT_OPEN 0x4
#define STUN_NAT_FULL 0x8
#define STUN_NAT_PORT 0x10
#define STUN_NAT_RES 0x20
#define STUN_NAT_BLOCK 0x0

#define STUN_CHANGE_NONE 0x0000000
#define STUN_CHANGE_PORT 0x00000002
#define STUN_CHANGE_IP 0x00000004
#define STUN_CHANGE_BOTH 0x00000006

#ifdef STUN_DEBUG
#define DEBUGF(...) printf(__VA_ARGS__)
#else
#define DEBUGF(...) \
  while (0)         \
  {                 \
  }
#endif

std::map<uint32_t, std::string> msgs = {
    {STUN_BINDREQ, "Binding Request"},
    {STUN_BINDRESP, "Binding Response"},
    {STUN_BINDERR, "Binding Error Response"},
    {STUN_SECREQ, "Shared Secret Request"},
    {STUN_SECRESP, "Shared Secret Response"},
    {STUN_SECERR, "Shared Secret Error Response"}};

std::map<uint32_t, std::string> attr_msgs = {
    {STUN_MAPPED_ADDRESS, "Mapped Address"},
    {STUN_RESPONSE_ADDRESS, "Response Address"},
    {STUN_CHANGE_REQUEST, "Change Request"},
    {STUN_SOURCE_ADDRESS, "Source Address"},
    {STUN_CHANGED_ADDRESS, "Changed Address"},
    {STUN_USERNAME, "Username"},
    {STUN_PASSWORD, "Password"},
    {STUN_MESSAGE_INTEGRITY, "Message Integrity"},
    {STUN_ERROR_CODE, "Error Code"},
    {STUN_UNKNOWN_ATTRIBUTES, "Unknown Attributes"},
    {STUN_REFLECTED_FROM, "Reflected From"}};

inline struct sockaddr_in stun_addr_message(stun_addr_t *attrval)
{
  struct sockaddr_in attraddr = {
      .sin_family = AF_INET,
      .sin_port = attrval->port,
      .sin_addr = {attrval->addr}
  };
  return attraddr;
}

struct sockaddr_in stunserver = {
    AF_INET,
};

class StunAttr
{
public:
  stun_attr_t *raw;
  StunAttr()
  {
    raw = (stun_attr_t *)calloc(1, STUN_MAX_BUFFER_SIZE - sizeof(stun_header_t));
  }

  ~StunAttr()
  {
    free(raw);
  }

  int changeAttr(uint64_t flag, int offset)
  {
    uint16_t attrlen = sizeof(flag);
    stun_attr_t *attr = (stun_attr_t *)(raw + offset);
    attr->attr = htons(STUN_CHANGE_REQUEST);
    attr->len = htons(attrlen);
    uint64_t val = htonl(flag);
    memcpy(&attr->value, (long *)&val, sizeof(val));
    return attrlen + sizeof(stun_attr_t);
  }

  int attrString(char *s, int16_t msgtype, int offset)
  {
    int16_t attrlen;
    stun_attr_t *attr = (stun_attr_t *)(raw + offset);

    attr->attr = htons(msgtype);
    attrlen = strlen(s);
    memcpy(&attr->value, s, attrlen);

    while (attrlen % 4)
    {
      attrlen++;
    }
    attr->len = htons(attrlen);
    return attrlen + sizeof(stun_attr_t);
  }

  int attrAddr(struct sockaddr_in *sin, int16_t msgtype, int offset)
  {
    int16_t attrlen = sizeof(stun_addr_t);
    stun_attr_t *attr = (stun_attr_t *)(raw + offset);
    stun_addr_t *addr;

    attr->attr = htons(msgtype);
    attr->len = htons(attrlen);

    addr = (stun_addr_t *)attr->value;
    addr->unused = 0;
    addr->family = 0x01;
    addr->port = sin->sin_port;
    addr->addr = sin->sin_addr.s_addr;

    return attrlen + sizeof(stun_attr_t);
  }
};

class StunState
{
private:
  std::thread *send_thread;
  std::thread *recv_thread;
  XShiro1024pp rng;
  std::atomic<bool> _shutdown;

public:
  char *username;
  char *password;
  struct sockaddr_in caddr, maddr;
  int result, pcnt;
  struct timeval laststun;
  struct sockaddr_in bindaddr; //bindaddr ast_rtp->us
  int sock;                    //ast_rtp->s
  std::set<std::string> ips;

  StunState() : rng(time(nullptr))
  {
  }

  ~StunState()
  {
    if (send_thread != nullptr)
      delete send_thread;
    if (recv_thread != nullptr)
      delete recv_thread;
  }

  void send(uint16_t msgtype, StunAttr &attr, int len, int testid)
  {
    struct sockaddr_in *dst;
    if (testid > 1)
      dst = &caddr;
    else
      dst = &stunserver;

    uint8_t *buf = (uint8_t *)calloc(1, STUN_MAX_BUFFER_SIZE);
    stun_header_t *req = (stun_header_t *)buf;

    for (int x = 0; x < 4; x++)
      req->id[x] = rng.next() & 0xffffffff;

    req->id[3] = (req->id[3] & 0xFFFFFF00) | testid;
    req->msgtype = htons(msgtype);
    req->msglen = htons(len);
    memcpy(buf + sizeof(stun_header_t), attr.raw, len);

    sendto(sock, buf, len + sizeof(stun_header_t), 0, (struct sockaddr *)dst, sizeof(*dst));
    free(buf);
  }

  void addIfaceIP(std::string stunhost)
  {
    //printf("D: Stun host: %s\n", stunhost.c_str());
    struct hostent *hp = gethostbyname(stunhost.c_str());
    if (hp == nullptr)
      return;
    memcpy(&stunserver.sin_addr, hp->h_addr, sizeof(stunserver.sin_addr));
    stunserver.sin_port = htons(3478);

    int32_t tmpsock = socket(PF_INET, SOCK_DGRAM, 0);
    int32_t flags = fcntl(tmpsock, F_GETFL);
    fcntl(tmpsock, F_SETFL, flags | O_NONBLOCK);
    bindaddr.sin_family = AF_INET;
    bindaddr.sin_port = htons((rng.next() % (65535 - 1023)) + 1023);

    connect(tmpsock, (struct sockaddr *)&stunserver, sizeof(struct sockaddr_in));
    uint32_t addrlen = sizeof(bindaddr);
    getsockname(tmpsock, (struct sockaddr *)&bindaddr, &addrlen);
    DEBUGF("BOUND TO:%s:%i\n", inet_ntoa(bindaddr.sin_addr), ntohs(bindaddr.sin_port));
    ips.emplace(std::string(inet_ntoa(bindaddr.sin_addr)));
    shutdown(tmpsock, SHUT_RDWR);
  }

  bool isFinished(){
    return _shutdown.load() && ips.size() > 0;
  }

  void stopThread()
  {
    _shutdown.store(true);
  }

  void startThread(std::string stunhost, uint32_t timeoutms)
  {
    _shutdown.store(false);
    addIfaceIP(stunhost);

    struct hostent *hp = gethostbyname(stunhost.c_str());
    memcpy(&stunserver.sin_addr, hp->h_addr, sizeof(stunserver.sin_addr));
    stunserver.sin_port = htons(3478);

    sock = socket(PF_INET, SOCK_DGRAM, 0);
    int32_t flags = fcntl(sock, F_GETFL);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    bindaddr.sin_family = AF_INET;
    bindaddr.sin_port = htons((rng.next() % (65535 - 1023)) + 1023);
    // TODO: assert valid status
    bind(sock, (struct sockaddr *)&bindaddr, sizeof(struct sockaddr_in));

    recv_thread = new std::thread([&] {
      result = 0;
      pcnt = 0;
      gettimeofday(&laststun, 0);

      struct pollfd psock[1] = {{.fd = sock, .events = POLLIN}};
      uint8_t *buf = (uint8_t *)calloc(1, STUN_MAX_BUFFER_SIZE);
      while (!_shutdown.load())
      {
        usleep(20000);
        int rv = poll(psock, 1, -1);
        if ((psock[0].revents & POLLIN) && (rv > 0))
        {
          socklen_t sinlen = sizeof(struct sockaddr_in);
          struct sockaddr_in sin;
          int len = recvfrom(sock, buf, STUN_MAX_BUFFER_SIZE, MSG_WAITALL, (struct sockaddr *)&sin, &sinlen);
          if (len > 0)
          {
            gettimeofday(&laststun, 0);
            DEBUGF("Got new packet, updating timeout\n");
            handlePacket(&sin, buf, len);
          }
        }
      }
      free(buf);
      DEBUGF("Shutting down recv_thread\n");
      _shutdown.store(true);
    });
    send_thread = new std::thread([&] {
      // Send initial request
      {
        StunAttr msg;
        uint32_t len = msg.changeAttr(STUN_CHANGE_NONE, 0);
        send(STUN_BINDREQ, msg, 0, 0);
      }

      struct timeval tv;
      while (!_shutdown.load())
      {
        usleep(200000);
        gettimeofday(&tv, 0);
        if ((tv.tv_sec * 1000000 + tv.tv_usec) - (laststun.tv_sec * 1000000 + laststun.tv_usec) > timeoutms * 1000)
        {
          if ((result & STUN_NAT_SYMN) && (pcnt == 1))
          {
            {
              DEBUGF("Sending BINDREQ %d\n", 2);
              StunAttr msg;
              uint32_t len = msg.changeAttr(STUN_CHANGE_NONE, 0);
              send(STUN_BINDREQ, msg, 0, 2);
            }
          }
          else
          {
            if (result < STUN_NAT_OPEN)
            {
              // Got bind IP (we are in DMZ-mode)
              ips.emplace(std::string(inet_ntoa(bindaddr.sin_addr)));
              DEBUGF("NEW IP:%s:%i Result: %i\n", inet_ntoa(bindaddr.sin_addr), ntohs(bindaddr.sin_port), this->result);
            }
            else
            {
              // Got external IP (we are behind NAT)
              ips.emplace(std::string(inet_ntoa(maddr.sin_addr)));
              DEBUGF("NEW IP:%s:%i Result: %i\n", inet_ntoa(maddr.sin_addr), ntohs(maddr.sin_port), this->result);
            }
            break;
          }
        }
      }
      shutdown(sock, SHUT_RDWR);
      DEBUGF("Shutting down send_thread\n");
      _shutdown.store(true);
    });
  }

  void handlePacket(struct sockaddr_in *src, void *buf, int32_t len)
  {
    stun_header_t *hdr = (stun_header_t *)buf;
    int32_t msgtype = ntohs(hdr->msgtype);

    if ((msgtype != STUN_BINDREQ) && (msgtype != STUN_BINDRESP))
    {
      DEBUGF("Dunno what to do with STUN message %04x (%s)\n", msgtype, msgs[msgtype].c_str());
      return;
    }

    if (len < sizeof(stun_header_t))
    {
      DEBUGF("Runt STUN packet (only %d, wanting at least %zd)\n", len, sizeof(stun_header_t));
      return;
    }

    DEBUGF("STUN Packet, msg %s (%04x), length: %d\n", msgs[ntohs(hdr->msgtype)].c_str(), ntohs(hdr->msgtype), ntohs(hdr->msglen));

    if (ntohs(hdr->msglen) > len - sizeof(stun_header_t))
    {
      DEBUGF("Scrambled STUN packet length (got %d, expecting %d)\n", ntohs(hdr->msglen), (int)(len - sizeof(stun_header_t)));
      return;
    }

    len = ntohs(hdr->msglen);
    // struct sockaddr_in caddr;
    struct sockaddr_in maddr = bindaddr;
    int32_t pcnt = hdr->id[3] & 0x000000FF;
    uint8_t *data = (uint8_t *)buf + sizeof(stun_header_t);

    if (len <= 0)
      return;

    while (len)
    {
      if (len < sizeof(stun_attr_t))
      {
        DEBUGF("Runt Attribute (got %d, expecting %zd)\n", len, sizeof(stun_attr_t));
        break;
      }
      stun_attr_t *attr = (stun_attr_t *)data;
      if (ntohs(attr->len) > len)
      {
        DEBUGF("Inconsistent Attribute (length %d exceeds remaining msg len %d)\n", ntohs(attr->len), len);
        break;
      }
      switch (ntohs(attr->attr))
      {
      case STUN_USERNAME:
        username = (char *)attr->value;
        break;
      case STUN_PASSWORD:
        password = (char *)attr->value;
        break;
      case STUN_MAPPED_ADDRESS:
        maddr = stun_addr_message((stun_addr_t *)attr->value);
        break;
      case STUN_CHANGED_ADDRESS:
        caddr = stun_addr_message((stun_addr_t *)attr->value);
        break;
      case STUN_CHANGE_REQUEST:
        DEBUGF("Change Request Sent Value %d\n", ntohl(*(long *)attr->value));
        break;
      case STUN_SOURCE_ADDRESS:
      {
        stun_addr_t *addr = (stun_addr_t *)attr->value;
        uint32_t inet_addr = addr->addr;
        DEBUGF("SOURCE ADDR:%s:%i\n", inet_ntoa(*(struct in_addr *)&inet_addr), ntohs(addr->port));
        break;
      }
      case STUN_SOFTWARE:
        DEBUGF("REMOTE SOFTWARE: %.*s\n", attr->len, attr->value);
        break;
      case STUN_XOR_MAPPED_ADDRESS2:
      case STUN_XOR_MAPPED_ADDRESS:
      {
        auto xoraddr = (stun_addr_t *)attr->value;
        xoraddr->addr ^= hdr->id[0];
        xoraddr->port ^= hdr->id[0] & 0xffff;
        maddr = stun_addr_message(xoraddr);
        DEBUGF("XORED ADDR:%s:%i\n", inet_ntoa(maddr.sin_addr), ntohs(maddr.sin_port));
        break;
      }
      default:
        DEBUGF("Ignoring STUN attribute %s (0x%04x), length %d\n", attr_msgs[ntohs(attr->attr)].c_str(), ntohs(attr->attr), ntohs(attr->len));
        DEBUGF("Failed to handle attribute %s (0x%04x)\n", attr_msgs[ntohs(attr->attr)].c_str(), ntohs(attr->attr));
        break;
      }
      data += ntohs(attr->len) + sizeof(stun_attr_t);
      len -= ntohs(attr->len) + sizeof(stun_attr_t);
    }

    DEBUGF("MSGTYPE=%d\n", msgtype);
    switch (msgtype)
    {
    case STUN_BINDREQ:
    {
      DEBUGF("Got BINDREQ\n");
      StunAttr attr;
      int32_t msglen = 0;
      if (username)
        msglen = attr.attrString(username, STUN_USERNAME, msglen);
      attr.attrAddr(src, STUN_MAPPED_ADDRESS, msglen);
      send(STUN_BINDRESP, attr, msglen, 0);
      break;
    }
    case STUN_BINDRESP:
      DEBUGF("Got BINDRESP pcnt=%d\n", pcnt);
      switch (pcnt)
      {
      case 0:
      {
        maddr = maddr;
        caddr = caddr;
        result |= STUN_NAT_SYMN;
        if ((bindaddr.sin_addr.s_addr == maddr.sin_addr.s_addr) && (bindaddr.sin_port == maddr.sin_port))
          result |= STUN_NAT_SYMF;
        StunAttr msg;
        int32_t msglen = msg.changeAttr(STUN_CHANGE_PORT | STUN_CHANGE_IP, 0);
        DEBUGF("SEND BINDREQ w/ CHANGE_PORT | CHANGE_IP %d\n", 1);
        send(STUN_BINDREQ, msg, msglen, 1);
        break;
      }
      case 1:
        if (result & STUN_NAT_SYMF)
          result |= STUN_NAT_OPEN;
        else
          result |= STUN_NAT_FULL;
        break;
      case 2:
      {
        if ((maddr.sin_addr.s_addr == maddr.sin_addr.s_addr) && (maddr.sin_port == maddr.sin_port))
          result |= STUN_NAT_PORT;
        StunAttr msg;
        int32_t msglen = msg.changeAttr(STUN_CHANGE_PORT, 0);
        DEBUGF("SEND BINDREQ w/ CHANGE_PORT %d\n", 1);
        send(STUN_BINDREQ, msg, msglen, 3);
        break;
      }
      case 3:
        result |= STUN_NAT_RES;
        break;
      }
      pcnt++;
      break;
    }
  }
};

// void ast_rtp_stun_request_peer(StunState &st)
// {
//   StunAttr attr;
//   int msglen = attr.changeAttr(STUN_CHANGE_NONE, 0);
//   if (st.username)
//   {
//     msglen += attr.attrString(st.username, STUN_USERNAME, msglen);
//   }
//   st.send(STUN_BINDREQ, attr, msglen, 0);
// }
#ifdef STUN_DEBUG
#undef DEBUGF
#endif
#endif

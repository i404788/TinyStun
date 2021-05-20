# TinyStun
TinyStun is a single-header C++11 implementation of a STUN client, it allows you to retrieve your own public-facing IP address from behind a NAT. 
It is a non-blocking library using `std::thread` handle the required communication.

## Usage
```cpp
#include<stun.hpp>

StunState st;
st.startThread("stun01.sipphone.com", 5000);

// Do some other operations, it can take a while
while(!st.isFinished()){ sleep(1); }

// When finished all IPs found are located in:
for (std::string ip : st.ips)
  printf("IP Found: %s\n", ip.c_str());
```


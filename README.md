# TinyStun
TinyStun is a single-header C++11 implementation of a STUN client, it allows you to retrieve your own public-facing IP address from behind a NAT. 
It is a non-blocking library using `std::thread` handle the required communication.

## Usage
```cpp
#include<stun.hpp>

...

StunState st;
st.startThread("stun01.sipphone.com", 5000);

// Do some other operations, it can take a while
while(!st.isFinished()){ sleep(1); }

// When finished all IPs found are located in:
for (std::string ip : st.ips)
  printf("IP Found: %s\n", ip.c_str());
```

Requires linking against libpthread (or whatever std::thread uses) to work.


Compiling with `-DSTUN_DEBUG` will enable protocol-level logging.


## Technical Details
It only works with non-tls STUN servers (most of them at the time of writing). And implements all the common STUN messages, including `XOR_MAPPED_ADDRESS`, the specific flags that are discovered are in `int StunState::result` and can be AND'd with `STUN_NAT_*` flags to check for certain functionality.

It uses xorshiro1024++ (see `rng.hpp`) to generate it's nonces.

## TODO
* [ ] Custom server ports
* [ ] Allow reuse of socket for hole-punching

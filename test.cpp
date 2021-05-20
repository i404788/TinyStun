#include <cstdio>
#include <string>
#include "stun.hpp"

int main(){
  StunState st;
  st.startThread("stun01.sipphone.com", 5000);

  // Do some other operations, it can take a while
  while(!st.isFinished()){ sleep(1); }

  // When finished all IPs found are located in:
  for (std::string ip : st.ips)
    printf("IP Found: %s\n", ip.c_str());
}

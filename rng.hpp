#ifndef XORSHIRO1024PP_HPP
#define XORSHIRO1024PP_HPP

// 2019 - David Blackman and Sebastiano Vigna (vigna@acm.org) CC0 <http://creativecommons.org/publicdomain/zero/1.0/>.
// 2021 - Ferris Kwaijtaal CC0 <http://creativecommons.org/publicdomain/zero/1.0/>

// For details see https://prng.di.unimi.it/

#include <stdint.h>

static inline uint64_t rotl(const uint64_t x, int k)
{
  return (x << k) | (x >> (64 - k));
}

static inline double to_double(uint64_t x)
{
  const union
  {
    uint64_t i;
    double d;
  } u = {.i = UINT64_C(0x3FF) << 52 | x >> 12};
  return u.d - 1.0;
}

static inline uint64_t splitmix64(uint64_t x)
{
  uint64_t z = (x += 0x9e3779b97f4a7c15);
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
  z = (z ^ (z >> 27)) * 0x94d049bb133111eb;
  return z ^ (z >> 31);
}

class XShiro1024pp
{
  uint64_t state[16] = {};
  int32_t p = 0;

public:
  XShiro1024pp(uint64_t iv)
  {
    seed(&iv, 1);
  }

  void seed(uint64_t *seed, uint32_t seedlen)
  {
    for (int i = 0; i < seedlen; i++)
    {
      for (int j = 0; j < 16; j++)
      {
        state[j] ^= splitmix64(seed[i] + i + j);
      }
    }
  }

  /*
  Provides a random double (64-bit) unit value.
  Note there is some bias with the lowest significant bit always being zero.
  */
  double nextf()
  {
    return to_double(next());
  }

  uint64_t next()
  {
    const int q = p;
    p = (p + 1) & 15;
    const uint64_t s0 = state[p];
    uint64_t s15 = state[q];
    const uint64_t result = rotl(s0 + s15, 23) + s15;

    s15 ^= s0;
    state[q] = rotl(s0, 25) ^ s15 ^ (s15 << 27);
    state[p] = rotl(s15, 36);

    return result;
  }

  /* This is the jump function for the generator. It is equivalent
   to 2^512 calls to next(); it can be used to generate 2^512
   non-overlapping subsequences for parallel computations. */
  void jump()
  {
    static const uint64_t JUMP[] = {0x931197d8e3177f17,
                                    0xb59422e0b9138c5f, 0xf06a6afb49d668bb, 0xacb8a6412c8a1401,
                                    0x12304ec85f0b3468, 0xb7dfe7079209891e, 0x405b7eec77d9eb14,
                                    0x34ead68280c44e4a, 0xe0e4ba3e0ac9e366, 0x8f46eda8348905b7,
                                    0x328bf4dbad90d6ff, 0xc8fd6fb31c9effc3, 0xe899d452d4b67652,
                                    0x45f387286ade3205, 0x03864f454a8920bd, 0xa68fa28725b1b384};

    uint64_t t[sizeof(state) / sizeof(*state)] = {};
    for (int i = 0; i < sizeof(JUMP) / sizeof(*JUMP); i++)
    {
      for (int b = 0; b < 64; b++)
      {
        if (JUMP[i] & UINT64_C(1) << b)
          for (int j = 0; j < sizeof(state) / sizeof(*state); j++)
            t[j] ^= state[(j + p) & sizeof(state) / sizeof(*state) - 1];
        next();
      }
    }

    for (int i = 0; i < sizeof(state) / sizeof(*state); i++)
    {
      state[(i + p) & sizeof(state) / sizeof(*state) - 1] = t[i];
    }
  }

  /* This is the long-jump function for the generator. It is equivalent to
   2^768 calls to next(); it can be used to generate 2^256 starting points,
   from each of which jump() will generate 2^256 non-overlapping
   subsequences for parallel distributed computations. */

  void long_jump(void)
  {
    static const uint64_t LONG_JUMP[] = {0x7374156360bbf00f,
                                         0x4630c2efa3b3c1f6, 0x6654183a892786b1, 0x94f7bfcbfb0f1661,
                                         0x27d8243d3d13eb2d, 0x9701730f3dfb300f, 0x2f293baae6f604ad,
                                         0xa661831cb60cd8b6, 0x68280c77d9fe008c, 0x50554160f5ba9459,
                                         0x2fc20b17ec7b2a9a, 0x49189bbdc8ec9f8f, 0x92a65bca41852cc1,
                                         0xf46820dd0509c12a, 0x52b00c35fbf92185, 0x1e5b3b7f589e03c1};

    uint64_t t[sizeof(state) / sizeof(*state)] = {};
    for (int i = 0; i < sizeof(LONG_JUMP) / sizeof(*LONG_JUMP); i++)
    {
      for (int b = 0; b < 64; b++)
      {
        if (LONG_JUMP[i] & UINT64_C(1) << b)
          for (int j = 0; j < sizeof(state) / sizeof(*state); j++)
            t[j] ^= state[(j + p) & sizeof(state) / sizeof(*state) - 1];
        next();
      }
    }

    for (int i = 0; i < sizeof(state) / sizeof(*state); i++)
    {
      state[(i + p) & sizeof(state) / sizeof(*state) - 1] = t[i];
    }
  }
};

#endif
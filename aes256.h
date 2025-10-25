#pragma once
#include <cstdint>
#include <wmmintrin.h>

struct alignas(64) aes256_t
{
	__m128i r1[15];
	__m128i r2[15];

#define M1(x) do { \
	__m128i t = _mm_slli_si128(x, 4); \
	x = _mm_xor_si128(x, t); \
	t = _mm_slli_si128(t, 4); \
	x = _mm_xor_si128(x, t); \
	t = _mm_slli_si128(t, 4); \
	x = _mm_xor_si128(x, t); \
} while(0)

#define M2(round, rcon) do { \
	c = _mm_aeskeygenassist_si128(b, rcon); \
	c = _mm_shuffle_epi32(c, 0xff); \
	M1(a); \
	a = _mm_xor_si128(a, c); \
	r1[round] = a; \
} while(0)

#define M3(round) do { \
	d = _mm_aeskeygenassist_si128(a, 0x00); \
	c = _mm_shuffle_epi32(d, 0xaa); \
	M1(b); \
	b = _mm_xor_si128(b, c); \
	r1[round] = b; \
} while(0)

	__forceinline aes256_t(const uint8_t key[32]) noexcept
	{
		__m128i a = _mm_loadu_si128((const __m128i*)key);
		__m128i b = _mm_loadu_si128((const __m128i*)(key + 16));
		__m128i c, d;

		r1[0] = a; r1[1] = b;

		M2(2, 0x01); M3(3); M2(4, 0x02); M3(5); M2(6, 0x04); M3(7); M2(8, 0x08); M3(9); M2(10, 0x10); M3(11); M2(12, 0x20); M3(13); M2(14, 0x40);

		r2[0] = r1[0];
		for (int i = 1; i < 14; ++i) r2[i] = _mm_aesimc_si128(r1[i]);
		r2[14] = r1[14];
	}

	~aes256_t() noexcept
	{
		volatile __m128i* a = r1;
		volatile __m128i* b = r2;
		for (int i = 0; i < 15; ++i)
		{
			_mm_store_si128((__m128i*) & a[i], _mm_setzero_si128());
			_mm_store_si128((__m128i*) & b[i], _mm_setzero_si128());
		}
	}

#undef M1
#undef M2
#undef M3
};
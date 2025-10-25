#pragma once
#include <cstdint>
#include <array>
#include <vector>
#include <fstream>
#include <intrin.h>
#include "aes256.h"
#include "sha512.h"

namespace _cr
{
	__forceinline static uint64_t rdrand64() noexcept
	{
		uint64_t val = 0;
		while (!_rdrand64_step(&val));
		return val;
	}

	__forceinline static void fmemcpy(void* dst, const void* src, size_t n) noexcept
	{
		uint8_t* d = reinterpret_cast<uint8_t*>(dst);
		const uint8_t* s = reinterpret_cast<const uint8_t*>(src);

		while (n >= 32)
		{
			_mm256_storeu_si256(reinterpret_cast<__m256i*>(d), _mm256_loadu_si256(reinterpret_cast<const __m256i*>(s)));
			d += 32;
			s += 32;
			n -= 32;
		}

		while (n--) *d++ = *s++;
	}

	__forceinline static bool is_aligned16(const void* p) noexcept
	{
		return (reinterpret_cast<uint64_t>(p) & 0xF) == 0;
	}

	__forceinline static void prefetch_read(const void* p) noexcept
	{
		_mm_prefetch(reinterpret_cast<const char*>(p), _MM_HINT_T0);
	}

#define M1(dst) dst = _mm_set_epi64x((long long)hi_copy, (long long)lo_copy); ++lo_copy; if (lo_copy == 0) ++hi_copy;
#define M2(dst) dst = _mm_xor_si128(dst, aes.r1[0]);
#define M3(dst, idx) dst = _mm_aesenc_si128(dst, aes.r1[idx]);
#define M4(idx) M3(s0, idx); M3(s1, idx); M3(s2, idx); M3(s3, idx); M3(s4, idx); M3(s5, idx); M3(s6, idx); M3(s7, idx);
#define M5(dst) dst = _mm_aesenclast_si128(dst, aes.r1[14]);
#define M6(dst) _mm_loadu_si128(reinterpret_cast<const __m128i*>(dst))
#define M7(a, b) _mm_stream_si128(reinterpret_cast<__m128i*>(a), b);
#define M8(a, b) _mm_storeu_si128(reinterpret_cast<__m128i*>(a), b);
#define M9(a, b) a = _mm_xor_si128(a, b);
#define M0(idx) s = _mm_aesenc_si128(s, aes.r1[idx]);
#define MZ(dst) _cr::prefetch_read(dst + 512);

	__forceinline static void main_loop(aes256_t& aes, const std::array<uint8_t, 16>& iv, const uint8_t* in, uint8_t* out, size_t n) noexcept
	{
		constexpr size_t BLOCK = 16;
		constexpr size_t LANES = 8;
		constexpr size_t CHUNK = BLOCK * LANES;
		constexpr size_t THRESHOLD = (4 << 20);

		bool out_aligned = _cr::is_aligned16(out);
		bool in_aligned = _cr::is_aligned16(in);

		uint64_t lo = 0, hi = 0;
		_cr::fmemcpy(&lo, iv.data(), 8);
		_cr::fmemcpy(&hi, iv.data() + 8, 8);

		size_t i = 0;
		size_t limit = n / CHUNK;

		for (size_t t = 0; t < limit; ++t)
		{
			__m128i s0, s1, s2, s3, s4, s5, s6, s7;
			uint64_t lo_copy = lo;
			uint64_t hi_copy = hi;

			M1(s0); M1(s1); M1(s2); M1(s3); M1(s4); M1(s5); M1(s6); M1(s7);

			lo = lo_copy;
			hi = hi_copy;

			M2(s0); M2(s1); M2(s2); M2(s3); M2(s4); M2(s5); M2(s6); M2(s7);

			M4(1); M4(2); M4(3); M4(4); M4(5); M4(6); M4(7); M4(8); M4(9); M4(10); M4(11); M4(12); M4(13);

			M5(s0); M5(s1); M5(s2); M5(s3); M5(s4); M5(s5); M5(s6); M5(s7);

			const uint8_t* p0 = in + i, * p1 = p0 + 16, * p2 = p0 + 32, * p3 = p0 + 48, * p4 = p0 + 64, * p5 = p0 + 80, * p6 = p0 + 96, * p7 = p0 + 112;

			MZ(p0); MZ(p1); MZ(p2); MZ(p3); MZ(p4); MZ(p5); MZ(p6); MZ(p7);

			uint8_t* q0 = out + i, * q1 = q0 + 16, * q2 = q0 + 32, * q3 = q0 + 48, * q4 = q0 + 64, * q5 = q0 + 80, * q6 = q0 + 96, * q7 = q0 + 112;

			__m128i t0 = M6(p0), t1 = M6(p1), t2 = M6(p2), t3 = M6(p3), t4 = M6(p4), t5 = M6(p5), t6 = M6(p6), t7 = M6(p7);

			M9(t0, s0); M9(t1, s1); M9(t2, s2); M9(t3, s3); M9(t4, s4); M9(t5, s5); M9(t6, s6);  M9(t7, s7);

			if (out_aligned && (n >= THRESHOLD))
			{
				M7(q0, t0); M7(q1, t1); M7(q2, t2); M7(q3, t3); M7(q4, t4); M7(q5, t5); M7(q6, t6); M7(q7, t7);
			}
			else
			{
				M8(q0, t0); M8(q1, t1); M8(q2, t2); M8(q3, t3); M8(q4, t4); M8(q5, t5); M8(q6, t6); M8(q7, t7);
			}

			i += CHUNK;
		}

		for (; i + BLOCK <= n; i += BLOCK)
		{
			uint8_t ctr[16];
			_cr::fmemcpy(ctr, &lo, 8);
			_cr::fmemcpy(ctr + 8, &hi, 8);
			++lo; if (lo == 0) ++hi;

			__m128i s = _mm_loadu_si128(reinterpret_cast<const __m128i*>(ctr));
			s = _mm_xor_si128(s, aes.r1[0]);

			M0(1); M0(2); M0(3); M0(4); M0(5); M0(6); M0(7); M0(8); M0(9); M0(10); M0(11); M0(12); M0(13);

			s = _mm_aesenclast_si128(s, aes.r1[14]);

			__m128i ct = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + i));
			__m128i pt = _mm_xor_si128(ct, s);

			if (out_aligned && (n >= THRESHOLD))
				_mm_stream_si128(reinterpret_cast<__m128i*>(out + i), pt);
			else
				_mm_storeu_si128(reinterpret_cast<__m128i*>(out + i), pt);
		}

		if (i < n)
		{
			uint8_t ctr[16];
			_cr::fmemcpy(ctr, &lo, 8);
			_cr::fmemcpy(ctr + 8, &hi, 8);

			__m128i s = _mm_loadu_si128(reinterpret_cast<const __m128i*>(ctr));
			s = _mm_xor_si128(s, aes.r1[0]);

			M0(1); M0(2); M0(3); M0(4); M0(5); M0(6); M0(7); M0(8); M0(9); M0(10); M0(11); M0(12); M0(13);

			s = _mm_aesenclast_si128(s, aes.r1[14]);

			alignas(16) uint8_t tmp[16];
			_mm_store_si128(reinterpret_cast<__m128i*>(tmp), s);

			size_t tail = n - i;
			for (size_t j = 0; j < tail; ++j)
				out[i + j] = in[i + j] ^ tmp[j];
		}

		if (out_aligned && (n >= THRESHOLD))
			_mm_sfence();
	}

	__forceinline static bool main_loop_file(aes256_t& aes, std::ifstream& in, std::ofstream& out, std::array<uint8_t, 16>& iv) noexcept
	{
		constexpr size_t FILE_CHUNK = 8 * 1024 * 1024;

		std::vector<uint8_t> inbuf(FILE_CHUNK);
		std::vector<uint8_t> outbuf(FILE_CHUNK);

		while (true)
		{
			in.read(reinterpret_cast<char*>(inbuf.data()), FILE_CHUNK);
			std::streamsize got = in.gcount();
			if (got <= 0) break;

			const size_t n = static_cast<size_t>(got);

			main_loop(aes, iv, inbuf.data(), outbuf.data(), n);

			out.write(reinterpret_cast<const char*>(outbuf.data()), n);
			if (!out) return false;

			uint64_t lo, hi;
			_cr::fmemcpy(&lo, iv.data(), 8);
			_cr::fmemcpy(&hi, iv.data() + 8, 8);

			uint64_t new_lo = lo + (n / 16);
			if (new_lo < lo) ++hi;
			lo = new_lo;

			_cr::fmemcpy(iv.data(), &lo, 8);
			_cr::fmemcpy(iv.data() + 8, &hi, 8);

			if (in.eof()) break;
		}

		return true;
	}

#undef M1
#undef M2
#undef M3
#undef M4
#undef M5
#undef M6
#undef M7
#undef M8
#undef M9
#undef M0
}

static bool encrypt_bin(const std::vector<uint8_t>& indata, const std::array<uint8_t, 32>& key, std::vector<uint8_t>& outdata) noexcept
{
	const size_t n = indata.size();
	aes256_t aes(key.data());

	std::array<uint8_t, 16> iv{};
	uint64_t r1 = _cr::rdrand64(), r2 = _cr::rdrand64();
	_cr::fmemcpy(iv.data(), &r1, 8);
	_cr::fmemcpy(iv.data() + 8, &r2, 8);

	outdata.resize(16 + n);
	_cr::fmemcpy(outdata.data(), iv.data(), 16);

	const uint8_t* in = indata.data();
	uint8_t* out = outdata.data() + 16;

	_cr::main_loop(aes, iv, in, out, n);

	return true;
}

static bool decrypt_bin(const std::vector<uint8_t>& indata, const std::array<uint8_t, 32>& key, std::vector<uint8_t>& outdata) noexcept
{
	if (indata.size() < 16) return false;

	const size_t n = indata.size() - 16;
	aes256_t aes(key.data());

	std::array<uint8_t, 16> iv{};
	_cr::fmemcpy(iv.data(), indata.data(), 16);

	outdata.resize(n);

	const uint8_t* in = indata.data() + 16;
	uint8_t* out = outdata.data();

	_cr::main_loop(aes, iv, in, out, n);

	return true;
}

static bool encrypt_file(const std::wstring& ipath, const std::wstring& opath, const std::array<uint8_t, 32>& key) noexcept
{
	std::ifstream in(ipath, std::ios::binary);
	std::ofstream out(opath, std::ios::binary | std::ios::trunc);
	if (!in || !out)
		return false;

	aes256_t aes(key.data());

	std::array<uint8_t, 16> iv{};
	uint64_t r1 = _cr::rdrand64(), r2 = _cr::rdrand64();
	_cr::fmemcpy(iv.data(), &r1, 8);
	_cr::fmemcpy(iv.data() + 8, &r2, 8);
	out.write(reinterpret_cast<const char*>(iv.data()), 16);
	if (!out) return false;

	return _cr::main_loop_file(aes, in, out, iv);
}

static bool decrypt_file(const std::wstring& ipath, const std::wstring& opath, const std::array<uint8_t, 32>& key) noexcept
{
	std::ifstream in(ipath, std::ios::binary);
	std::ofstream out(opath, std::ios::binary | std::ios::trunc);
	if (!in || !out)
		return false;

	aes256_t aes(key.data());

	std::array<uint8_t, 16> iv{};
	in.read(reinterpret_cast<char*>(iv.data()), 16);
	if (in.gcount() != 16)
		return false;

	return _cr::main_loop_file(aes, in, out, iv);
}

static std::vector<uint8_t> b64_enc(const std::vector<uint8_t>& input) noexcept
{
	static constexpr char enc_table[64]{
		'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
		'Q','R','S','T','U','V','W','X','Y','Z',
		'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p',
		'q','r','s','t','u','v','w','x','y','z',
		'0','1','2','3','4','5','6','7','8','9','+','/'
	};

	const size_t in_len = input.size();
	const size_t out_len = ((in_len + 2) / 3) * 4;

	std::vector<uint8_t> output(out_len);
	size_t o = 0;
	size_t i = 0;

	while (i + 2 < in_len)
	{
		uint32_t val = (uint32_t(input[i]) << 16) |
			(uint32_t(input[i + 1]) << 8) |
			uint32_t(input[i + 2]);

		output[o + 0] = enc_table[(val >> 18) & 0x3F];
		output[o + 1] = enc_table[(val >> 12) & 0x3F];
		output[o + 2] = enc_table[(val >> 6) & 0x3F];
		output[o + 3] = enc_table[val & 0x3F];
		i += 3;
		o += 4;
	}

	if (i < in_len)
	{
		uint32_t val = (uint32_t(input[i]) << 16);
		output[o++] = enc_table[(val >> 18) & 0x3F];

		if (i + 1 < in_len)
		{
			val |= (uint32_t(input[i + 1]) << 8);
			output[o++] = enc_table[(val >> 12) & 0x3F];
			output[o++] = enc_table[(val >> 6) & 0x3F];
			output[o++] = '=';
		}
		else
		{
			output[o++] = enc_table[(val >> 12) & 0x3F];
			output[o++] = '=';
			output[o++] = '=';
		}
	}

	return output;
}

static std::vector<uint8_t> b64_dec(const std::vector<uint8_t>& input) noexcept
{
	static constexpr uint8_t dec_table[256] = {
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3E, 0xFF, 0xFF, 0xFF, 0x3F,
		0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
		0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	};

	const size_t in_len = input.size();
	std::vector<uint8_t> output;
	output.reserve((in_len / 4) * 3);

	uint32_t val = 0;
	int bits = 0;

	for (uint8_t c : input)
	{
		if (c == '\r' || c == '\n' || c == ' ' || c == '\t')
			continue;

		if (c == '=') break;

		uint8_t d = dec_table[c];
		if (d == 0xFF) return {};

		val = (val << 6) | d;
		bits += 6;

		if (bits >= 8)
		{
			bits -= 8;
			output.push_back(static_cast<uint8_t>((val >> bits) & 0xFF));
		}
	}

	return output;
}

static inline std::array<uint8_t, 64> sha512_bytes(const std::string& input) noexcept
{
	sha512_t ctx;
	ctx.update(input.data(), input.size());
	std::array<uint8_t, 64> hash{};
	ctx.finish(hash.data());
	return hash;
}
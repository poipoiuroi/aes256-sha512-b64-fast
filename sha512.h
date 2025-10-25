#pragma once

extern "C" void sha512_block_data_order(void* vctx, const void* in, size_t num) noexcept; // ultra ASM optimized from OpenSSL

struct alignas(64) sha512_t
{
private:
    uint64_t state[8];
    uint64_t total_low = 0;
    uint64_t total_high = 0;
    uint8_t buffer[128]{};

    static __forceinline void fmemcpy(void* dst, const void* src, size_t n) noexcept
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

    static __forceinline void fmemset_zero(void* dst, size_t n) noexcept
    {
        uint8_t* d = reinterpret_cast<uint8_t*>(dst);
        __m256i z = _mm256_setzero_si256();

        while (n >= 32)
        {
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(d), z);
            d += 32;
            n -= 32;
        }

        while (n--) *d++ = 0;
    }

    static __forceinline void process_blocks(const uint8_t* data, size_t num, uint64_t st[8]) noexcept
    {
        if (num == 0) return;

        struct { uint64_t h[8]; } ctx;
        for (int i = 0; i < 8; ++i) ctx.h[i] = st[i];

        sha512_block_data_order(&ctx, data, num);

        for (int i = 0; i < 8; ++i) st[i] = ctx.h[i];
    }

public:
    sha512_t() { reset(); }

    __forceinline void reset() noexcept
    {
        total_low = 0; total_high = 0;
        state[0] = 0x6a09e667f3bcc908ULL; state[1] = 0xbb67ae8584caa73bULL;
        state[2] = 0x3c6ef372fe94f82bULL; state[3] = 0xa54ff53a5f1d36f1ULL;
        state[4] = 0x510e527fade682d1ULL; state[5] = 0x9b05688c2b3e6c1fULL;
        state[6] = 0x1f83d9abfb41bd6bULL; state[7] = 0x5be0cd19137e2179ULL;
    }

    void update(const void* input, uint64_t len) noexcept
    {
        const uint8_t* data = reinterpret_cast<const uint8_t*>(input);
        uint64_t filled = total_low & 127;
        uint64_t prev = total_low;
        total_low += len;
        if (total_low < prev) ++total_high;

        if (filled)
        {
            uint64_t need = 128 - filled;
            if (len >= need)
            {
                fmemcpy(buffer + filled, data, (size_t)need);
                process_blocks(buffer, 1, state);
                data += need;
                len -= need;
                filled = 0;
            }
            else
            {
                fmemcpy(buffer + filled, data, (size_t)len);
                return;
            }
        }

        if (len >= 128)
        {
            size_t blocks = static_cast<size_t>(len / 128);
            process_blocks(data, blocks, state);
            size_t consumed = blocks * 128;
            data += consumed;
            len -= consumed;
        }

        if (len > 0)
        {
            fmemcpy(buffer, data, (size_t)len);
        }
    }

    void finish(void* output) noexcept
    {
        uint64_t bits_low = total_low << 3;
        uint64_t bits_high = (total_high << 3) | (total_low >> 61);
        uint8_t lenbuf[16];

        for (int i = 0; i < 8; i++) 
            lenbuf[i] = uint8_t(bits_high >> (56 - 8 * i));

        for (int i = 0; i < 8; i++)
            lenbuf[8 + i] = uint8_t(bits_low >> (56 - 8 * i));

        uint64_t last = total_low & 127;
        buffer[last++] = 0x80;

        if (last > 112) 
        {
            fmemset_zero(buffer + last, 128 - last);
            process_blocks(buffer, 1, state);
            last = 0; 
        }

        fmemset_zero(buffer + last, 112 - last);
        fmemcpy(buffer + 112, lenbuf, 16);
        process_blocks(buffer, 1, state);

        uint8_t* out = reinterpret_cast<uint8_t*>(output);
        for (int i = 0; i < 8; i++)
        {
            uint64_t v = state[i];
            out[i * 8 + 0] = uint8_t(v >> 56);
            out[i * 8 + 1] = uint8_t(v >> 48);
            out[i * 8 + 2] = uint8_t(v >> 40);
            out[i * 8 + 3] = uint8_t(v >> 32);
            out[i * 8 + 4] = uint8_t(v >> 24);
            out[i * 8 + 5] = uint8_t(v >> 16);
            out[i * 8 + 6] = uint8_t(v >> 8); 
            out[i * 8 + 7] = uint8_t(v);
        }
    }
};
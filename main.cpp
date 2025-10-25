#include <array>
#include <vector>
#include <string>
#include <numeric>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <windows.h>
#include "cryptor.h"

template<typename F>
double benchmark(size_t data_size, F&& func)
{
	DWORD_PTR p = SetThreadAffinityMask(GetCurrentThread(), 1);
	LARGE_INTEGER freq, t1, t2;
	QueryPerformanceFrequency(&freq);
	QueryPerformanceCounter(&t1);
	func();
	QueryPerformanceCounter(&t2);
	if (p) SetThreadAffinityMask(GetCurrentThread(), p);
	double secs = double(t2.QuadPart - t1.QuadPart) / double(freq.QuadPart);
	return (double)data_size / (1024.0 * 1024.0) / secs;
}

int main()
{
	constexpr size_t data_size = 256ull * 1024 * 1024;
	constexpr int iters = 1;

	auto sha512_key = sha512_bytes("zIA90BP+e=2zxdNd4QBbx*FwEK!w1fY6C@I%4SIeR$^%=BH*irg@@C3swH#kH5xr");
	std::array<uint8_t, 32> aes_key;
	std::copy_n(sha512_key.begin(), 32, aes_key.begin());

	std::vector<uint8_t> data(data_size);

	uint64_t r1 = _cr::rdrand64(), r2 = _cr::rdrand64();
	for (size_t i = 0; i < data_size; i += 32)
		_mm256_storeu_si256((__m256i*)(data.data() + i), _mm256_broadcastsi128_si256(_mm_set_epi64x(r1, r2)));

	std::vector<uint8_t> encdata, decdata;

	auto summarize = [](const std::vector<double>& v) {
		double avg = std::accumulate(v.begin(), v.end(), 0.0) / v.size();
		double minv = *std::min_element(v.begin(), v.end());
		double maxv = *std::max_element(v.begin(), v.end());
		return std::tuple<double, double, double>(avg, minv, maxv);
		};

	auto run_bench = [&](auto&& fn, size_t size, int iter) {
		std::vector<double> rates;
		rates.reserve(iter);
		for (int i = 0; i < iter; ++i)
			rates.push_back(benchmark(size, fn));
		return summarize(rates);
		};

	auto [aes_enc_avg, aes_enc_min, aes_enc_max] = run_bench([&]() { encrypt_bin(data, aes_key, encdata); }, data_size, iters);
	auto [aes_dec_avg, aes_dec_min, aes_dec_max] = run_bench([&]() { decrypt_bin(encdata, aes_key, decdata); }, data_size, iters);

	auto [sha_avg, sha_min, sha_max] =
		run_bench([&]() {
		sha512_t sha;
		sha.update(data.data(), data.size());
		std::array<uint8_t, 64> digest{};
		sha.finish(digest.data()); }, data_size, iters);

	std::vector<uint8_t> b64_out;
	auto [b64_enc_avg, b64_enc_min, b64_enc_max] = run_bench([&]() { b64_out = b64_enc(data); }, data_size, iters);

	std::vector<uint8_t> b64_dec_out;
	auto [b64_dec_avg, b64_dec_min, b64_dec_max] = run_bench([&]() { b64_dec_out = b64_dec(b64_out); }, b64_out.size(), iters);

	printf("AES-256 Encrypt: avg %.2f MB/s (min %.2f, max %.2f)\n", aes_enc_avg, aes_enc_min, aes_enc_max);
	printf("AES-256 Decrypt: avg %.2f MB/s (min %.2f, max %.2f)\n", aes_dec_avg, aes_dec_min, aes_dec_max);
	printf("SHA-512 Hash:    avg %.2f MB/s (min %.2f, max %.2f)\n", sha_avg, sha_min, sha_max);
	printf("Base64 Encode:   avg %.2f MB/s (min %.2f, max %.2f)\n", b64_enc_avg, b64_enc_min, b64_enc_max);
	printf("Base64 Decode:   avg %.2f MB/s (min %.2f, max %.2f)\n", b64_dec_avg, b64_dec_min, b64_dec_max);

	{
		std::wstring f_in = L"test_input.bin";
		std::wstring f_enc = L"test_encrypted.bin";
		std::wstring f_dec = L"test_decrypted.bin";

		constexpr size_t file_size = 32ull * 1024 * 1024;

		{
			std::ofstream out(f_in, std::ios::binary | std::ios::trunc);
			out.write(reinterpret_cast<const char*>(data.data()), file_size);
		}

		double enc_rate = benchmark(file_size, [&]() { encrypt_file(f_in, f_enc, aes_key); });
		double dec_rate = benchmark(file_size, [&]() { decrypt_file(f_enc, f_dec, aes_key); });

		printf("File Encrypt: %.2f MB/s, File Decrypt: %.2f MB/s\n", enc_rate, dec_rate);

		std::filesystem::remove(f_in);
		std::filesystem::remove(f_enc);
		std::filesystem::remove(f_dec);
	}

	return 0;
}
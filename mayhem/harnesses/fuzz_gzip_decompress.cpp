// Fuzzes ix::gzipDecompress (the gzip decoder used for HTTP bodies). When the input decodes, the
// output must survive a gzipCompress/gzipDecompress round trip unchanged.
#include <ixwebsocket/IXGzipCodec.h>

#include <cstddef>
#include <cstdint>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    std::string in(reinterpret_cast<const char*>(data), size);
    std::string out;
    if (!ix::gzipDecompress(in, out)) return 0;

    std::string again;
    if (!ix::gzipDecompress(ix::gzipCompress(out), again) || again != out) __builtin_trap();
    return 0;
}

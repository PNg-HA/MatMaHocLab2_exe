#include "cryptlib.h"
#include "secblock.h"
#include "hrtimer.h"
#include "osrng.h"
#include "modes.h"
#include "aes.h"
#include "hex.h"
#include <iostream>

const double runTimeInSeconds = 3.0;
const double cpuFreq = 2.7 * 1000 * 1000 * 1000;

int main(int argc, char* argv[])
{
    using namespace CryptoPP;
    AutoSeededRandomPool prng;

    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key, key.size());

    byte iv[AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));
    
    CBC_Mode< AES >::Decryption plain;
    plain.SetKeyWithIV(key, key.size(), iv);

    const int BUF_SIZE = RoundUpToMultipleOf(2048U,
        dynamic_cast<StreamTransformation&>(plain).OptimalBlockSize());

    AlignedSecByteBlock buf(BUF_SIZE); //cipher
    prng.GenerateBlock(buf, buf.size());

    std::string encoded;
    encoded.clear();
		StringSource(buf, sizeof(buf), true,
				new HexEncoder(
					new StringSink(encoded)
				) // HexEncoder
			); // StringSource
    std::cout << "cipher text: " << encoded << std::endl;

    double elapsedTimeInSeconds;
    unsigned long i=0, blocks=1;

    ThreadUserTimer timer;
    timer.StartTimer();

    do
    {
        blocks *= 2;
        for (; i<blocks; i++)
            plain.ProcessString(buf, BUF_SIZE);
        elapsedTimeInSeconds = timer.ElapsedTimeAsDouble();
    }
    while (elapsedTimeInSeconds < runTimeInSeconds);

    encoded.clear();
		StringSource(buf, sizeof(buf), true,
				new HexEncoder(
					new StringSink(encoded)
				) // HexEncoder
			); // StringSource
    std::cout << "recovered text: " << encoded << std::endl;

    const double bytes = static_cast<double>(BUF_SIZE) * blocks;
    const double ghz = cpuFreq / 1000 / 1000 / 1000;
    const double mbs = bytes / elapsedTimeInSeconds / 1024 / 1024;
    const double cpb = elapsedTimeInSeconds * cpuFreq / bytes;

    std::cout << plain.AlgorithmName() << " benchmarks..." << std::endl;
    std::cout << "  " << ghz << " GHz cpu frequency"  << std::endl;
    std::cout << "  " << cpb << " cycles per byte (cpb)" << std::endl;
    std::cout << "  " << mbs << " MiB per second (MiB)" << std::endl;

    // std::cout << "  " << elapsedTimeInSeconds << " seconds passed" << std::endl;
    // std::cout << "  " << (word64) bytes << " bytes processed" << std::endl;

    return 0;
}
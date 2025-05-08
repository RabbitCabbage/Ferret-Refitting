#ifndef EMP_SSD_F2_H__
#define EMP_SSD_F2_H__

#include "emp-tool/emp-tool.h"
using namespace emp;

template<typename IO, int d = 10>
class SsdF2 { public:
    int party;
    int64_t n;
    ThreadPool * pool;
    IO *io;
    int threads, k, mask;
    block seed;
    block *cache = nullptr;

    SsdF2 (int party, int64_t n, int k, ThreadPool * pool, IO *io, int threads) {
        this->party = party;
        this->k = k;
        this->n = n;
        this->pool = pool;
        this->io = io;
        this->threads = threads;
        mask = 1;
        while(mask < k) {
            mask <<=1;
            mask = mask | 0x1;
        }
    }

    ~SsdF2 () {
        if (cache != nullptr) delete[] cache;
    }


    // compute: Stationary Syndrome Decoding
    // nn = H * kk, where H is the n*k parity check matrix, random
    // kk is the noise vector, cached by the stationary vector
    void __compute4(block * nn, int64_t i, PRP * prp) {
        block tmp[d];
        for(int m = 0; m < d; ++m)
            tmp[m] = makeBlock(i, m);
        AES_ecb_encrypt_blks(tmp, d, &prp->aes);
        uint32_t* r = (uint32_t*)(tmp);
        for(int m = 0; m < 4; ++m)
            for (int j = 0; j < d; ++j) {
                int index = (*r) & mask;
                ++r;
                index = index >= k? index-k:index;
                nn[i+m] = cache[index] ^ nn[i+m];
            }
    }

    // compute: Stationary Syndrome Decoding
    // nn = H * kk, where H is the parity check matrix, random
    // kk is the noise vector, cached by the stationary vector
    void __compute1(block * nn, int64_t i, PRP*prp) {
        const auto nr_blocks = d/4 + (d % 4 != 0);
        block tmp[nr_blocks];
        for(int m = 0; m < nr_blocks; ++m)
            tmp[m] = makeBlock(i, m);
        prp->permute_block(tmp, nr_blocks);
        uint32_t* r = (uint32_t*)(tmp);
        for (int j = 0; j < d; ++j)
            nn[i] = cache[r[j]%k] ^ nn[i];
    }

    void task(block * nn, int64_t start, int64_t end) {
        PRP prp(seed);
        int64_t j = start;
        for(; j < end-4; j+=4)
            __compute4(nn, j, &prp);
        for(; j < end; ++j)
            __compute1(nn, j, &prp);
    }

    void compute(block * nn, const block * kk, block s = zero_block) {
        if (cache == nullptr) {
            if(kk == nullptr) {
                std::cout << "kk not cached!" << std::endl;
                exit(1);
            }
            cache = new block[k]; 
            // cache the stationary noise vector
            memset(cache, 0, k*sizeof(block));
            memcpy(cache, kk, k*sizeof(block));
        } 
        // else {
        //     // compare the cache with the new kk
        //     // debug, can be deleted if there is no mismatch
        //     if (!cmpBlock(cache, kk, k)) {
        //         std::cout << "Cache mismatch! qwq" << std::endl;
        //         memcpy(cache, kk, k*sizeof(block));
        //     }
        // }
		vector<std::future<void>> fut;
		int64_t width = n/threads;
        if(!cmpBlock(&s, &zero_block, 1)) seed = s;
		else seed = seed_gen();
		for(int i = 0; i < threads - 1; ++i) {
			int64_t start = i * width;
			int64_t end = min((i+1)* width, n);
			fut.push_back(pool->enqueue([this, nn, kk, start, end]() {
				task(nn, start, end);
			}));
		}
		int64_t start = (threads - 1) * width;
        	int64_t end = n;
		task(nn, start, end);

		for (auto &f: fut) f.get();
	}

	block seed_gen() {
		block seed;
		if(party == ALICE) {
			PRG prg;
			prg.random_block(&seed, 1);
			io->send_data(&seed, sizeof(block));
		} else {
			io->recv_data(&seed, sizeof(block));
		}io->flush();
		return seed;
	}

	void bench(block * nn, const block * kk) {
		vector<std::future<void>> fut;
		int64_t width = n/threads;
		for(int i = 0; i < threads - 1; ++i) {
			int64_t start = i * width;
			int64_t end = min((i+1)* width, n);
			fut.push_back(pool->enqueue([this, nn, kk, start, end]() {
				task(nn, kk, start, end);
			}));
		}
		int64_t start = (threads - 1) * width;
        	int64_t end = n;
		task(nn, kk, start, end);

		for (auto &f: fut) f.get();
	}
};
    
#endif //EMP_SSD_F2_H__
#ifndef EMP_SSD_F2_H__
#define EMP_SSD_F2_H__

#include "emp-tool/emp-tool.h"
using namespace emp;

// this file is wrong and deprecated
// because the stationary is not implemented by cache the noise vector but by reuse the 1~(h-1) levels of the ggm tree for spcot.

template<typename IO>
class SsdF2 { public:
    int party;
    int64_t n;
    ThreadPool * pool;
    IO *io;
    int threads, k, mask;
    block seed;
    block *cache = nullptr;
    std::vector<int> stationary_w;

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
    void __compute(block * nn, int64_t i, PRG * prg) {
        int w = stationary_w.size();
        block* tmp = new block[w];
        // random stationary_w blocks to be multiplied by cache
        prg->random_block(tmp, w);
        for (int j = 0; j < w; ++j) {
            nn[i] = nn[i] ^ tmp[j]*cache[stationary_w[j]]; // dstodo: block multiplication?
        }
        delete[] tmp;
    }

    void task(block * nn, int64_t start, int64_t end) {
        PRG prg(&seed);
        int64_t j = start;
        for(; j < end; ++j)
            __compute(nn, j, &prg);
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
            // count the stationary weight of the noise vector
            stationary_w.clear();
            for (int i = 0; i < k; ++i) {
                // std::cout << cache[i] << std::endl;
                if (!cmpBlock(&cache[i], &zero_block, 1)) stationary_w.push_back(i);
            }
            std::cout << stationary_w.size() << std::endl;
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
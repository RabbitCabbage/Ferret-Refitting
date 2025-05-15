#ifndef SPCOT_SENDER_H__
#define SPCOT_SENDER_H__
#include <iostream>
#include "emp-tool/emp-tool.h"
#include "emp-ot/emp-ot.h"
#include "emp-ot/ferret/twokeyprp.h"

using namespace emp;

template<typename IO>
class SPCOT_Sender { public:
	block seed;
	// block delta;
	block *ggm_tree, *m;
	IO *io;
	int depth, leave_n;
	PRG prg;
	block secret_sum_f2;
	block *cache_node;
	block *cache_msg;
	bool cached;

	SPCOT_Sender(IO *io, int depth_in) {
		initialization(io, depth_in);
		prg.random_block(&seed, 1);
	}

	void initialization(IO *io, int depth_in) {
		this->io = io;
		this->depth = depth_in;
		this->leave_n = 1<<(this->depth-1);
		m = new block[(depth-1)*2];
		// cache the nodes on all layer above the leaves
		cache_node = new block[1<<(depth-2)];
		cache_msg = new block[(depth-2)*2];
		cached = false;
	}

	~SPCOT_Sender() {
		delete[] m;
		delete[] cache_node;
		delete[] cache_msg;
	}

	// generate GGM tree, transfer secret, F2^k
	void compute(block* ggm_tree_mem, block secret) {
		// this->delta = secret;
		ggm_tree_gen(m, m+depth-1, ggm_tree_mem, secret);
	}

	// send the nodes by oblivious transfer, F2^k
	template<typename OT>
	void send_f2k(OT * ot, IO * io2, int s) {
		ot->send(m, &m[depth-1], depth-1, io2, s);
		io2->send_data(&secret_sum_f2, sizeof(block));
	}

	void ggm_tree_gen(block *ot_msg_0, block *ot_msg_1, block* ggm_tree_mem, block secret) {
		ggm_tree_gen(ot_msg_0, ot_msg_1, ggm_tree_mem);
		secret_sum_f2 = zero_block;
		block one = makeBlock(0xFFFFFFFFFFFFFFFFLL,0xFFFFFFFFFFFFFFFELL);
		for(int i = 0; i < leave_n; ++i) {
			ggm_tree[i] = ggm_tree[i] & one;
			secret_sum_f2 = secret_sum_f2 ^ ggm_tree[i];
		}
		secret_sum_f2 = secret_sum_f2 ^ secret;
	}

	// generate GGM tree from the top
	void ggm_tree_gen(block *ot_msg_0, block *ot_msg_1, block* ggm_tree_mem) {
		this->ggm_tree = ggm_tree_mem;
		TwoKeyPRP *prp = new TwoKeyPRP(zero_block, makeBlock(0, 1));
		if(!cached) {
			prp->node_expand_1to2_correlated(ggm_tree, seed);
			ot_msg_0[0] = ggm_tree[0];
			ot_msg_1[0] = ggm_tree[1];
			prp->node_expand_2to4_correlated(&ggm_tree[0], &ggm_tree[0]);
			ot_msg_0[1] = ggm_tree[0] ^ ggm_tree[2];
			ot_msg_1[1] = ggm_tree[1] ^ ggm_tree[3];
			for(int h = 2; h < depth-2; ++h) {
				ot_msg_0[h] = ot_msg_1[h] = zero_block;
				int sz = 1<<h;
				for(int i = sz-4; i >=0; i-=4) {
					prp->node_expand_4to8_correlated(&ggm_tree[i*2], &ggm_tree[i]);
					ot_msg_0[h] ^= ggm_tree[i*2];
					ot_msg_0[h] ^= ggm_tree[i*2+2];
					ot_msg_0[h] ^= ggm_tree[i*2+4];
					ot_msg_0[h] ^= ggm_tree[i*2+6];
					ot_msg_1[h] ^= ggm_tree[i*2+1];
					ot_msg_1[h] ^= ggm_tree[i*2+3];
					ot_msg_1[h] ^= ggm_tree[i*2+5];
					ot_msg_1[h] ^= ggm_tree[i*2+7];
				}
			}
			// after this, there are 2^(depth-2) blocks in ggm_tree
			// and depth-2 blocks in ot_msg_0 and ot_msg_1
			// cache them
			memcpy(cache_node, ggm_tree, (1<<(depth-2))*sizeof(block));
			memcpy(cache_msg, ot_msg_0, (depth-2)*sizeof(block));
			memcpy(cache_msg+depth-2, ot_msg_1, (depth-2)*sizeof(block));
			cached = true;
		} else {
			// use the cached values
			memcpy(ggm_tree, cache_node, (1<<(depth-2))*sizeof(block));
			memcpy(ot_msg_0, cache_msg, (depth-2)*sizeof(block));
			memcpy(ot_msg_1, cache_msg+depth-2, (depth-2)*sizeof(block));
		}
		
		int h = depth-2;
		ot_msg_0[h] = ot_msg_1[h] = zero_block;
		int sz = 1<<h;
		// using ccr_function
		for(int i = sz-4; i >=0; i-=4) {
			// // prepare the input, 8 blocks in total
			// // temporarily put the input in ggm_tree[i*2] (children)
			// for (int j = 0; j < 4; ++j) {
			// 	// std::cout << "ggm_tree[" << i+j << "] = " << ggm_tree[i+j] << std::endl;
			// 	// xor with 0
			// 	ggm_tree[i*2+j*2] = ggm_tree[i+j] ^ zero_block;
			// 	// xor with 1
			// 	ggm_tree[i*2+j*2+1] = ggm_tree[i+j] ^ makeBlock(0, 1);
			// }

			// ccr_function(&ggm_tree[i*2], &ggm_tree[i*2], 8);

			prp->node_expand_4to8(&ggm_tree[i*2], &ggm_tree[i]);
			ot_msg_0[h] ^= ggm_tree[i*2];
			ot_msg_0[h] ^= ggm_tree[i*2+2];
			ot_msg_0[h] ^= ggm_tree[i*2+4];
			ot_msg_0[h] ^= ggm_tree[i*2+6];
			ot_msg_1[h] ^= ggm_tree[i*2+1];
			ot_msg_1[h] ^= ggm_tree[i*2+3];
			ot_msg_1[h] ^= ggm_tree[i*2+5];
			ot_msg_1[h] ^= ggm_tree[i*2+7];
		}
		delete prp;
	}

	void consistency_check_msg_gen(block *V) {
		// X
		block *chi = new block[leave_n];
		Hash hash;
		block digest[2];
		hash.hash_once(digest, &secret_sum_f2, sizeof(block));
		uni_hash_coeff_gen(chi, digest[0], leave_n);

		vector_inn_prdt_sum_red(V, chi, ggm_tree, leave_n);
		delete[] chi;
	}
};

#endif
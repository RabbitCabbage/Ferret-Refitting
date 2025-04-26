#ifndef COT_H__
#define COT_H__

#include "emp-ot/ferret/preot.h"
#include "emp-ot/ferret/constants.h"
#include "emp-ot/ferret/quiet-bipsw/include/bipsw.h"
#include "emp-ot/ferret/quiet-bipsw/include/utils.h"
#include "emp-ot/ferret/quiet-bipsw/include/params.h"
#include "emp-ot/ferret/pr/prg.h"
#include "emp-ot/ferret/pr/prf.h"
#include "emp-ot/ferret/pr/polymur.h"

// debug
// std::string uint128_to_string(uint128_t value) {
// 	std::ostringstream oss;
// 	oss << (unsigned long long)(value >> 64) << std::setfill('0') << std::setw(20) << (unsigned long long)(value & 0xFFFFFFFFFFFFFFFFULL);
// 	return oss.str();
// }

template<typename IO>
class BaseCotQuiet { public:
	int party;
	// &-1 ^1 to ensure not all 0 for iknp
	// block one, minusone;
	block ot_delta;
	bool *ot_bool;
	int64_t ot_size;
	IO *io;
	bool malicious = false;
	
	//------ QuietOT ------//
	PublicParams *pp;
	Key *msk;
	KeyCache *msk_cache;
	uint8_t *constraint;
	Key *csk;
	KeyCache *csk_cache;


	BaseCotQuiet(int party, IO *io, bool malicious = false) {
		this->party = party;
		this->io = io;
		this->malicious = false; // QuietOT is not malicious
		ot_bool = nullptr;
		ot_size = 0;

		//------ QuietOT ------//
		pp = (PublicParams *)malloc(sizeof(PublicParams));
		pp_gen(pp, KEY_LEN);
		if (party == ALICE) {
			msk = (Key *)malloc(sizeof(Key));
			msk_cache = (KeyCache *)malloc(sizeof(KeyCache));
			msk->key_2 = NULL;
			msk->key_3 = NULL;
			msk->corrections_3 = NULL;
			msk->delta = NULL;
			msk_cache->cache_2 = NULL;
			msk_cache->cache_3 = NULL;
		}
		else {
			constraint = (uint8_t *)malloc(sizeof(uint8_t) * KEY_LEN);
			csk = (Key *)malloc(sizeof(Key));
			csk_cache = (KeyCache *)malloc(sizeof(KeyCache));	
			csk->key_2 = NULL;
			csk->key_3 = NULL;
			csk->corrections_3 = NULL;
			csk->delta = NULL;
			csk_cache->cache_2 = NULL;
			csk_cache->cache_3 = NULL;
		}
	
	}

	~BaseCotQuiet() {
		if (ot_bool != nullptr) {
			delete[] ot_bool;
		}

		//------ QuietOT ------//
		if (party == ALICE) {
			if (msk->key_2 != NULL) free(msk->key_2);
			if (msk->key_3 != NULL) free(msk->key_3);
			if (msk->corrections_3 != NULL) free(msk->corrections_3);
			if (msk->delta != NULL) free(msk->delta);
			if (msk_cache->cache_2 != NULL) free(msk_cache->cache_2);
			if (msk_cache->cache_3 != NULL) free(msk_cache->cache_3);
			free(msk);
			free(msk_cache);
		}
		else {
			free(constraint);
			if (csk->key_2 != NULL) free(csk->key_2);
			if (csk->key_3 != NULL) free(csk->key_3);
			if (csk->corrections_3 != NULL) free(csk->corrections_3);
			if (csk->delta != NULL) free(csk->delta);
			if (csk_cache->cache_2 != NULL) free(csk_cache->cache_2);
			if (csk_cache->cache_3 != NULL) free(csk_cache->cache_3);
			free(csk);
			free(csk_cache);
		}
		pp_free(pp);
	}

	// Setup for QuietOT, just like IKNP setup
	void cot_gen_pre(block deltain) {
		size_t mem_size = (1UL << CACHE_BITS) * (KEY_LEN / CACHE_BITS) * sizeof(uint128_t);
		if (this->party == ALICE) {
			this->ot_delta = deltain;
			key_gen(pp, msk);
		    compute_key_caches(pp, msk, msk_cache, mem_size);
			// WARNING: this is not the distributed setup
			// pack constraint and csk, also the mem used in csk for the receiver to access in another process
			// constraint: sizeof(uint8_t) * KEY_LEN
			// csk->key2: sizeof(uint128_t) * KEY_LEN
			// csk->key3: sizeof(uint128_t) * KEY_LEN * 2
			void *tmp = malloc(sizeof(uint8_t) * KEY_LEN + sizeof(uint128_t) * KEY_LEN * (2 + 1));
			constraint = (uint8_t *)tmp;
			csk = (Key *)malloc(sizeof(Key));
			sample_mod_6(constraint, RING_DIM);
			constrain_key_gen(pp, msk, csk, constraint);
			// pack the csk keys to tmp
			memcpy((uint8_t *)tmp + sizeof(uint8_t) * KEY_LEN, csk->key_2, sizeof(uint128_t) * KEY_LEN);
			memcpy((uint8_t *)tmp + sizeof(uint8_t) * KEY_LEN + sizeof(uint128_t) * KEY_LEN, csk->key_3, sizeof(uint128_t) * KEY_LEN * 2);
			io->send_data(tmp, sizeof(uint8_t) * KEY_LEN + sizeof(uint128_t) * KEY_LEN * (2 + 1));
			io->flush();
			free(tmp);
			free(csk->key_2);
			free(csk->key_3);
			free(csk);
		} else {
			void *tmp = malloc(sizeof(uint8_t) * KEY_LEN + sizeof(uint128_t) * KEY_LEN * (2 + 1));
			io->recv_data(tmp, sizeof(uint8_t) * KEY_LEN + sizeof(uint128_t) * KEY_LEN * (2 + 1));
			io->flush();
			memcpy(constraint, tmp, sizeof(uint8_t) * KEY_LEN);
			csk->key_2 = (uint128_t *)malloc(sizeof(uint128_t) * KEY_LEN);
			csk->key_3 = (uint128_t *)malloc(sizeof(uint128_t) * KEY_LEN * 2);
			memcpy(csk->key_2, (uint8_t *)tmp + sizeof(uint8_t) * KEY_LEN, sizeof(uint128_t) * KEY_LEN);
			memcpy(csk->key_3, (uint8_t *)tmp + sizeof(uint8_t) * KEY_LEN + sizeof(uint128_t) * KEY_LEN, sizeof(uint128_t) * KEY_LEN * 2);
			free(tmp);
			compute_key_caches(pp, csk, csk_cache, mem_size);
		}
	}

	void cot_gen_pre() {
		if (this->party == ALICE) {
			PRG prg;
			prg.random_block(&ot_delta, 1);
			cot_gen_pre(ot_delta);
		} else {
			cot_gen_pre(zero_block);
		}
	}
	
	void cot_gen(block *ot_data, int64_t size, bool *pre_bool = nullptr) {
		int64_t listot_num = size; // each list entry is one uint128_t, each list pair has 6 entries

		size_t input_block_num = (KEY_LEN / CACHE_BITS) * listot_num / 8;
		uint16_t *inputs = (uint16_t *)malloc(sizeof(uint16_t) * (KEY_LEN / CACHE_BITS) * listot_num);
		prg_eval(pp->prg_ctx,(uint128_t *)inputs, (uint128_t *)inputs, input_block_num);

		if (this->party == ALICE) {
			// get the outputs: uint128_t array with 6*listot_num
			// total listot_num pairs of lists
			uint128_t *sender_outputs;
			posix_memalign((void **)&sender_outputs, 64, listot_num * 6 * sizeof(uint128_t));
			sender_eval(pp, msk, msk_cache, inputs, sender_outputs, listot_num);

			// gen size blocks of data as m0 and m1
			block *m0 = new block[size];
			block *m1 = new block[size];
			PRG prg;
			prg.random_block(m0, size);
			// copy the m0 to ot_data
			memcpy(ot_data, m0, size * sizeof(block));
			// m1 = m0 ^ delta
			for (int64_t i = 0; i < size; i++) {
				m1[i] = m0[i] ^ ot_delta;
			}
			// // turn block to uint128_t, so that we can xor with the list
			uint128_t *m0_128 = new uint128_t;
			uint128_t *m1_128 = new uint128_t;
			uint128_t *lists_prime = new uint128_t[listot_num * 6];
			for (int64_t i = 0; i < size; i++) {
				// convert m0 and m1 to uint128_t
				// LSB at index 0, MSB at index 127
				*m0_128 = (uint128_t)m0[i];
				*m1_128 = (uint128_t)m1[i];

				// there are size * 6 list entries in total
				// xor m0 and m1 with the lists
				// each list has 6 entries, 3 for list0, 3 for list1
				lists_prime[i * 6] = sender_outputs[i * 6] ^ *m0_128;
				lists_prime[i * 6 + 1] = sender_outputs[i * 6 + 1] ^ *m0_128;
				lists_prime[i * 6 + 2] = sender_outputs[i * 6 + 2] ^ *m0_128;
				lists_prime[i * 6 + 3] = sender_outputs[i * 6 + 3] ^ *m1_128;
				lists_prime[i * 6 + 4] = sender_outputs[i * 6 + 4] ^ *m1_128;
				lists_prime[i * 6 + 5] = sender_outputs[i * 6 + 5] ^ *m1_128;
			}
			// send the list_prime to receiver
			io->send_data(lists_prime, listot_num * 6 * sizeof(uint128_t));
			io->flush();
			// free memory
			delete m0_128;
			delete m1_128;
			delete[] m0;
			delete[] m1;
			delete[] lists_prime;
			free(sender_outputs);
		} else {
			ot_bool = new bool[size];
			// get the outputs: uint8_t array with listot_num, total listot_num entries
			uint128_t *receiver_outputs;
			posix_memalign((void **)&receiver_outputs, 64, listot_num * sizeof(uint128_t));
			receiver_eval(pp, csk, csk_cache, inputs, receiver_outputs, listot_num);

			PRG prg;
			// WARNING: the pre_bool is not used actually
			// get the list ot choice bit from constraint
			bool *listot_choice = new bool[listot_num];
			size_t *listot_idx = new size_t[listot_num];
			for (size_t n = 0; n < listot_num; n++)
			{
				// compute weak PRF output (inner product between input and constraint)
				uint16_t *input = &inputs[n * (KEY_LEN / CACHE_BITS)];
				uint16_t input_block;
				size_t in_idx = 0;
				size_t idx = 0;
				size_t shift = 0;
				for (size_t i = 0; i < KEY_LEN; i++)
				{
					if (shift % CACHE_BITS == 0)
					{
						shift = 0;
						input_block = input[in_idx];
						in_idx++;
					}

					idx += constraint[i] * ((input_block >> shift) & 1);
					shift++;
				}

				idx %= 6;    // index of the receiver's value in the sender's list
				listot_idx[n] = idx;
				if (idx == 0 || idx == 1 || idx == 2)
					listot_choice[n] = 0; // receiver's value is in L0
				else
					listot_choice[n] = 1; // receiver's value is in L1
				ot_bool[n] = listot_choice[n];
				// relation sender_outputs[n * 6 + idx] != receiver_outputs[n]
			}

			// receive the list_prime from sender
			uint128_t *lists_prime = new uint128_t[listot_num * 6];
			io->recv_data(lists_prime, listot_num * 6 * sizeof(uint128_t));
			io->flush();

			// xor receiver_outputs with the list_prime at right index
			for (int64_t i = 0; i < listot_num; i++) {
				uint128_t tmp = receiver_outputs[i] ^ lists_prime[i * 6 + listot_idx[i]];
				// convert uint128_t to block
				ot_data[i] = makeBlock(tmp >> 64, tmp & 0xFFFFFFFFFFFFFFFFULL);
			}

			// free memory
			delete[] lists_prime;
			delete[] listot_choice;
			delete[] listot_idx;
			free(receiver_outputs);
		}
		// free memory
		free(inputs);
	}

	void cot_gen(OTPre<IO> *pre_ot, int64_t size, bool *pre_bool = nullptr) {
		block *ot_data = new block[size];
		if (this->party == ALICE) {
			cot_gen(ot_data, size, pre_bool);
			pre_ot->send_pre(ot_data, ot_delta);
		} else {
			PRG prg;
			bool *ot_bool = new bool[size];
			if(pre_bool && !malicious)
				memcpy(ot_bool, pre_bool, size);
			else
				prg.random_bool(ot_bool, size);
			cot_gen(ot_data, size, ot_bool);
			pre_ot->recv_pre(ot_data, ot_bool);
		}
		delete [] ot_data;
	}

	// debug
	bool check_cot(block *data, int64_t len) {
		if(party == ALICE) {
			io->send_block(&ot_delta, 1);
			io->send_block(data, len); 
			io->flush();
			return true;
		} else {
			block * tmp = new block[len];
			block ch[2];
			ch[0] = zero_block;
			io->recv_block(ch+1, 1);
			io->recv_block(tmp, len);
			for(int64_t i = 0; i < len; ++i)
				tmp[i] = tmp[i] ^ ch[ot_bool[i]];
			bool res = cmpBlock(tmp, data, len);
			delete[] tmp;
			return res;
		}
	}
};

template<typename IO>
class BaseCot { public:
   int party;
	block one, minusone;
	block ot_delta;
	IO *io;
	IKNP<IO> *iknp;
	bool malicious = false;

	BaseCot(int party, IO *io, bool malicious = false) {
		this->party = party;
		this->io = io;
		this->malicious = malicious;
		iknp = new IKNP<IO>(io, malicious);
		minusone = makeBlock(0xFFFFFFFFFFFFFFFFLL,0xFFFFFFFFFFFFFFFELL);
		one = makeBlock(0x0LL, 0x1LL);
	}
	
	~BaseCot() {
		delete iknp;
	}

	void cot_gen_pre(block deltain) {
		if (this->party == ALICE) {
			this->ot_delta = deltain;
			bool delta_bool[128];
			block_to_bool(delta_bool, ot_delta);
			iknp->setup_send(delta_bool);
		} else {
			iknp->setup_recv();
		}
	}

	void cot_gen_pre() {
		if (this->party == ALICE) {
			PRG prg;
			prg.random_block(&ot_delta, 1);
			ot_delta = ot_delta & minusone;
			ot_delta = ot_delta ^ one;
			bool delta_bool[128];
			block_to_bool(delta_bool, ot_delta);
			iknp->setup_send(delta_bool);
		} else {
			iknp->setup_recv();
		}
	}

	void cot_gen(block *ot_data, int64_t size, bool * pre_bool = nullptr) {
		if (this->party == ALICE) {
			iknp->send_cot(ot_data, size);
			io->flush();
			for(int64_t i = 0; i < size; ++i)
				ot_data[i] = ot_data[i] & minusone;
		} else {
			PRG prg;
			bool *pre_bool_ini = new bool[size];
			if(pre_bool && !malicious)
				memcpy(pre_bool_ini, pre_bool, size);
			else
				prg.random_bool(pre_bool_ini, size);
			iknp->recv_cot(ot_data, pre_bool_ini, size);
			block ch[2];
			ch[0] = zero_block;
			ch[1] = makeBlock(0, 1);
			for(int64_t i = 0; i < size; ++i)
				ot_data[i] = 
						(ot_data[i] & minusone) ^ ch[pre_bool_ini[i]];
			delete[] pre_bool_ini;
		}
	}

	void cot_gen(OTPre<IO> *pre_ot, int64_t size, bool * pre_bool = nullptr) {
		block *ot_data = new block[size];
		if (this->party == ALICE) {
			iknp->send_cot(ot_data, size);
			io->flush();
			for(int64_t i = 0; i < size; ++i)
				ot_data[i] = ot_data[i] & minusone;
			pre_ot->send_pre(ot_data, ot_delta);
		} else {
			PRG prg;
			bool *pre_bool_ini = new bool[size];
			if(pre_bool && !malicious)
				memcpy(pre_bool_ini, pre_bool, size);
			else
				prg.random_bool(pre_bool_ini, size);
			iknp->recv_cot(ot_data, pre_bool_ini, size);
			block ch[2];
			ch[0] = zero_block;
			ch[1] = makeBlock(0, 1);
			for(int64_t i = 0; i < size; ++i)
				ot_data[i] = 
						(ot_data[i] & minusone) ^ ch[pre_bool_ini[i]];
			pre_ot->recv_pre(ot_data, pre_bool_ini);
			delete[] pre_bool_ini;
		}
		delete[] ot_data;
	}

	// debug
	bool check_cot(block *data, int64_t len) {
		if(party == ALICE) {
			io->send_block(&ot_delta, 1);
			io->send_block(data, len); 
			io->flush();
			return true;
		} else {
			block * tmp = new block[len];
			block ch[2];
			io->recv_block(ch+1, 1);
			ch[0] = zero_block;
			io->recv_block(tmp, len);

			// transfer block to bits
			bool * delta_bool = new bool[128];
			bool * sender_data_bool = new bool[len*128];
			bool * receiver_data_bool = new bool[len*128];
			block_to_bool(delta_bool, ch[1]);
			for (int64_t i = 0; i < len; ++i) {
				block_to_bool(sender_data_bool + i*128, tmp[i]);
				block_to_bool(receiver_data_bool + i*128, data[i]);
				// traverse the bits to see if they are equal
				// do not compare the least significant bit
				for (int j = 0; j < 128; ++j) {
					if ((j!=0) && (getLSB(data[i])) && (sender_data_bool[i*128+j] != receiver_data_bool[i*128+j] ^ delta_bool[j])) {
						std::cout << "different at " << i*128+j << std::endl;
						std::cout << "sender_data_bool: " << sender_data_bool[i*128+j] << std::endl;
						std::cout << "receiver_data_bool: " << receiver_data_bool[i*128+j] << std::endl;
						std::cout << "delta_bool: " << delta_bool[j] << std::endl;
						return false;
					}
				}
			}
			
			// should not compare the least significant bit
			// for(int64_t i = 0; i < len; ++i)
			// 	tmp[i] = tmp[i] ^ ch[getLSB(data[i])];
			// bool res = cmpBlock(tmp, data, len);
			delete[] tmp;
			delete[] delta_bool;
			delete[] sender_data_bool;
			delete[] receiver_data_bool;
			return true;
		}
	}
};

#endif

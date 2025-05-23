#ifndef EMP_FERRET_COT_H_
#define EMP_FERRET_COT_H_
#include "emp-ot/ferret/mpcot_reg.h"
#include "emp-ot/ferret/base_cot.h"
#include "emp-ot/ferret/lpn_f2.h"
#include "emp-ot/ferret/ssd_f2.h"
#include "emp-ot/ferret/constants.h"

namespace emp {

/*
 * Ferret COT binary version
 * [REF] Implementation of "Ferret: Fast Extension for coRRElated oT with small communication"
 * https://eprint.iacr.org/2020/924.pdf
 *
 */
template<typename T>
class FerretCOT: public COT<T> { 
public:
	using COT<T>::io;
	using COT<T>::Delta;

	// PrimalLPNParameter param;
	SyndromeDecodingParameter param;
	int64_t ot_used, ot_limit;

	FerretCOT(int party, int threads, T **ios, bool malicious = false, bool run_setup = true, 
// PrimalLPNParameter param = ferret_b13, std::string pre_file="");
	SyndromeDecodingParameter param = ssd_b8, std::string pre_file="");
	

	~FerretCOT();

	void setup(block Deltain, std::string pre_file = "", bool *choice=nullptr, block seed=zero_block);

	void setup(std::string pre_file = "", bool *choice = nullptr, block seed= zero_block);

	void send_cot(block * data, int64_t length) override;

	void recv_cot(block* data, const bool * b, int64_t length) override;

	void rcot(block *data, int64_t num);

	int64_t rcot_inplace(block *ot_buffer, int64_t length, block seed = zero_block);

	int64_t byte_memory_need_inplace(int64_t ot_need);

	void assemble_state(void * data, int64_t size);

	int disassemble_state(const void * data, int64_t size);

	int64_t state_size();
private:
	block ch[2];

	T **ios;
	int party, threads;
	int64_t M;
	bool is_malicious;
	bool extend_initialized;

	block one;

	block * ot_pre_data = nullptr;
	block * ot_data = nullptr;

	std::string pre_ot_filename;

	BaseCotQuiet<T> *base_cot = nullptr;
	OTPre<T> *pre_ot = nullptr;
	ThreadPool *pool = nullptr;
	MpcotReg<T> *mpcot = nullptr;
	// LpnF2<T, 10> *lpn_f2 = nullptr;
	SsdF2<T> *ssd_f2 = nullptr;

	
	void online_sender(block *data, int64_t length);

	void online_recver(block *data, const bool *b, int64_t length);

	void set_param();

	void set_preprocessing_param();

	void extend_initialization();

	// void extend(block* ot_output, MpcotReg<T> *mpfss, OTPre<T> *preot, 
			// LpnF2<T, 10> *lpn, block *ot_input, block seed = zero_block);
	// first extension: run the GGMs and cuckoo hash
	// further extensions: keep using the same cot
	// it seems the delta is not changed, maybe, store a bool and the cache in the mpcot_reg
	void extend(block* ot_output, MpcotReg<T> *mpfss, OTPre<T> *preot, 
			SsdF2<T> *ssd_f2, block *ot_input, block seed = zero_block);

	void extend_f2k(block *ot_buffer);

	void extend_f2k();

	int64_t silent_ot_left();

	void write_pre_data128_to_file(void* loc, __uint128_t delta, std::string filename);

	__uint128_t read_pre_data128_from_file(void* pre_loc, std::string filename);
};

#include "emp-ot/ferret/ferret_cot.hpp"
}
#endif// _VOLE_H_

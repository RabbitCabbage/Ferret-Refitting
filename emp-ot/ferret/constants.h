#ifndef EMP_FERRET_CONSTANTS_H__
#define EMP_FERRET_CONSTANTS_H__

namespace emp { 
static std::string PRE_OT_DATA_REG_SEND_FILE = "./data/pre_ot_data_reg_send";
static std::string PRE_OT_DATA_REG_RECV_FILE = "./data/pre_ot_data_reg_recv";


// ferret has two scale of extension
// 1. small extension after initialization(_pre)
// 2. large extension in bootstrapping

class PrimalLPNParameter { public:
	int64_t n, t, k, log_bin_sz, n_pre, t_pre, k_pre, log_bin_sz_pre;
	PrimalLPNParameter() {}
	PrimalLPNParameter(int64_t n, int64_t t, int64_t k, int64_t log_bin_sz, int64_t n_pre, int64_t t_pre, int64_t k_pre, int64_t log_bin_sz_pre)
		: n(n), t(t), k(k), log_bin_sz(log_bin_sz),
		n_pre(n_pre), t_pre(t_pre), k_pre(k_pre), log_bin_sz_pre(log_bin_sz_pre) {

		if(n != t * (1<<log_bin_sz) ||
			n_pre != t_pre * (1<< log_bin_sz_pre) ||
			n_pre < k + t * log_bin_sz + 128 ) {
			error("LPN parameter not matched \n");	
		}
	}
	int64_t buf_sz() const {
		return n - t * log_bin_sz - k - 128;
	}
};

class SyndromeDecodingParameter { public:
	int64_t n, t, k, log_bin_sz, n_pre, t_pre, k_pre, log_bin_sz_pre;
	// dscomment: n = t * (1<<log_bin_sz), log_bin_sz is regular param
	vector<int64_t> stationary;
	SyndromeDecodingParameter() {}
	SyndromeDecodingParameter(int64_t n, int64_t t, int64_t k, int64_t log_bin_sz, int64_t n_pre, int64_t t_pre, int64_t k_pre, int64_t log_bin_sz_pre)
		: n(n), t(t), k(k), log_bin_sz(log_bin_sz), n_pre(n_pre), t_pre(t_pre), k_pre(k_pre), log_bin_sz_pre(log_bin_sz_pre) {
		// dstodo: why the third condition is needed?
		if(k != t * (1<<log_bin_sz) || 
		k_pre != t_pre * (1<< log_bin_sz_pre) ||
		n_pre < k + t * log_bin_sz + 128) {
			std::cout << "n, t, k, log_bin_sz: " << n << ", " << t << ", " << k << ", " << log_bin_sz << std::endl;
			std::cout << "n_pre, t_pre, k_pre, log_bin_sz_pre: " << n_pre << ", " << t_pre << ", " << k_pre << ", " << log_bin_sz_pre << std::endl;
			error("SD parameter not matched");
		}
	}
};

const static PrimalLPNParameter ferret_b13 = PrimalLPNParameter(10485760, 1280, 452000, 13, 470016, 918, 32768, 9);
const static PrimalLPNParameter ferret_b12 = PrimalLPNParameter(10268672, 2507, 238000, 12, 268800, 1050, 17384, 8);
const static PrimalLPNParameter ferret_b11 = PrimalLPNParameter(10180608, 4971, 124000, 11, 178944, 699, 17384, 8);

// static params sets for syndrome decoding, dual LPN
// dstodo: consider the security of current params choice.
// for primal LPN, the noise is gen by ggm tree, so LPN n need to be 2^log_bin_sz*t, but for dual LPN, k is the length of noise, we should have k = 2^log_bin_sz*t
// const static SyndromeDecodingParameter ssd_b13 = SyndromeDecodingParameter(10485760, 1280, 452000, 13, 470016, 918, 32768, 9);
// const static SyndromeDecodingParameter ssd_b9 = SyndromeDecodingParameter(10485760, 1280, 655360, 9, 470016, 1024, 32768, 5);
const static SyndromeDecodingParameter ssd_b8 = SyndromeDecodingParameter(10485760, 1280, 327680, 8, 470016, 1024, 32768, 5);


}//namespace
#endif //EMP_FERRET_CONSTANTS_H__

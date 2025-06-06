template<typename T>
FerretCOT<T>::FerretCOT(int party, int threads, T **ios,
		bool malicious, bool run_setup, SyndromeDecodingParameter param, std::string pre_file) {
	this->party = party;
	this->threads = threads;
	io = ios[0];
	this->ios = ios;
	// quietot is not malicious-secure
	this->is_malicious = false;
	one = makeBlock(0xFFFFFFFFFFFFFFFFLL,0xFFFFFFFFFFFFFFFELL);
	ch[0] = zero_block;
	base_cot = new BaseCotQuiet<T>(party, io, malicious);
	pool = new ThreadPool(threads);
	this->param = param;

	this->extend_initialized = false;

	if(run_setup) {
		if(party == ALICE) {
			PRG prg;
			prg.random_block(&Delta);
			Delta = Delta & one;
			Delta = Delta ^ 0x1;
			setup(Delta, pre_file);
		} else setup(pre_file);
	}
}

template<typename T>
FerretCOT<T>::~FerretCOT() {
	if (ot_pre_data != nullptr) {
		if(party == ALICE) write_pre_data128_to_file((void*)ot_pre_data, (__uint128_t)Delta, pre_ot_filename);
		else write_pre_data128_to_file((void*)ot_pre_data, (__uint128_t)0, pre_ot_filename);
		delete[] ot_pre_data;
	}
	if (ot_data != nullptr) delete[] ot_data;
	if(pre_ot != nullptr) delete pre_ot;
	delete base_cot;
	delete pool;
	// if(lpn_f2 != nullptr) delete lpn_f2;
	if(ssd_f2 != nullptr) delete ssd_f2;
	if(mpcot != nullptr) delete mpcot;
}

template<typename T>
void FerretCOT<T>::extend_initialization() {
	// lpn_f2 = new LpnF2<T, 10>(party, param.n, param.k, pool, io, pool->size());
	ssd_f2 = new SsdF2<T>(party, param.n, param.k, pool, io, pool->size());
	mpcot = new MpcotReg<T>(party, threads, param.n, param.t, param.log_bin_sz, pool, ios);
	if(is_malicious) mpcot->set_malicious();

	pre_ot = new OTPre<T>(io, mpcot->tree_height-1, mpcot->tree_n);
	M = param.k + pre_ot->n + mpcot->consist_check_cot_num;
	ot_limit = param.n - M;
	ot_used = ot_limit;
	extend_initialized = true;
}

// extend f2k in detail
template<typename T>
void FerretCOT<T>::extend(block* ot_output, MpcotReg<T> *mpcot, OTPre<T> *preot, 
		// LpnF2<T, 10> *lpn, block *ot_input, block seed) {
		SsdF2<T> *ssd, block *ot_input, block seed) {
	block *mpcot_output = nullptr;
	if(mpcot->mpcot_ran == false) {
		mpcot_output = new block[mpcot->idx_max];
		if(party == ALICE) mpcot->sender_init(Delta);
		else mpcot->recver_init();
		// for stationary SD assumption, we only need to run mpcot once, then ssd extend the same noise vector gen by mpcot
		mpcot->mpcot(mpcot_output, preot, ot_input);
	}
	// else {
	// 	// use the same mpcot output as the first extend
	// 	mpcot->fetch_cache(mpcot_output);
	// }
	// lpn->compute(ot_output, ot_input+mpcot->consist_check_cot_num, seed);
	ssd->compute(ot_output, mpcot_output, seed);
	if(mpcot_output != nullptr) {
		delete[] mpcot_output;
	}
}

// extend f2k (customized location)
template<typename T>
void FerretCOT<T>::extend_f2k(block *ot_buffer) {
	if(party == ALICE)
	    pre_ot->send_pre(ot_pre_data, Delta);
	else pre_ot->recv_pre(ot_pre_data);
	// extend(ot_buffer, mpcot, pre_ot, lpn_f2, ot_pre_data);
	extend(ot_buffer, mpcot, pre_ot, ssd_f2, ot_pre_data);
	memcpy(ot_pre_data, ot_buffer+ot_limit, M*sizeof(block));
	ot_used = 0;
}

// extend f2k
template<typename T>
void FerretCOT<T>::extend_f2k() {
	extend_f2k(ot_data);
}

template<typename T>
void FerretCOT<T>::setup(block Deltain, std::string pre_file, bool *choice, block seed) {
	this->Delta = Deltain;
	if(this->is_malicious) seed = zero_block;
	setup(pre_file, choice, seed);
	ch[1] = Delta;
}

template<typename T>
void FerretCOT<T>::setup(std::string pre_file, bool *choice, block seed) {
	if(pre_file != "") pre_ot_filename = pre_file;
	else {
		pre_ot_filename=(party==ALICE?PRE_OT_DATA_REG_SEND_FILE:PRE_OT_DATA_REG_RECV_FILE);
	}

	ThreadPool pool2(1);
	auto fut = pool2.enqueue([this](){
		extend_initialization();
	});

	ot_pre_data = new block[param.n_pre];
	bool hasfile = file_exists(pre_ot_filename), hasfile2;
	if(party == ALICE) {
		io->send_data(&hasfile, sizeof(bool));
		io->flush();
		io->recv_data(&hasfile2, sizeof(bool));
	} else {
		io->recv_data(&hasfile2, sizeof(bool));
		io->send_data(&hasfile, sizeof(bool));
		io->flush();
	}
	if(hasfile & hasfile2 & false) { // dstodo for setup debugging so & false, need to be removed
		Delta = (block)read_pre_data128_from_file((void*)ot_pre_data, pre_ot_filename);
	} else {
		// std::cout << "Malicious: " << this->is_malicious << std::endl;
		// send delta as initialization of pre_ot
		if(party == BOB) base_cot->cot_gen_pre();
		else base_cot->cot_gen_pre(Delta);

		// tmp mpcot_init and lpn for small extension, using _pre params
		// MpcotReg<T> mpcot_ini(party, threads, param.n_pre, param.t_pre, param.log_bin_sz_pre, pool, ios);
		MpcotReg<T> mpcot_ini(party, threads, param.k_pre, param.t_pre, param.log_bin_sz_pre, pool, ios);
		if(is_malicious) mpcot_ini.set_malicious();
		OTPre<T> pre_ot_ini(ios[0], mpcot_ini.tree_height-1, mpcot_ini.tree_n);
		// LpnF2<T, 10> lpn(party, param.n_pre, param.k_pre, pool, io, pool->size());
		SsdF2<T> ssd_init(party, param.n_pre, param.k_pre, pool, io, pool->size());

		// the output of pre_data is used for lpn secret
		// for ssd, no need to gen so many ot data
		// block *pre_data_ini = new block[param.k_pre+mpcot_ini.consist_check_cot_num];
		block *pre_data_ini = new block[mpcot_ini.consist_check_cot_num];
		memset(this->ot_pre_data, 0, param.n_pre*16);
		if(this->is_malicious){
			seed = zero_block;
			choice = nullptr;
		}
		if(choice){
            base_cot->cot_gen(&pre_ot_ini, pre_ot_ini.n, choice);
            // base_cot->cot_gen(pre_data_ini, param.k_pre + mpcot_ini.consist_check_cot_num, choice+pre_ot_ini.n);
            base_cot->cot_gen(pre_data_ini, mpcot_ini.consist_check_cot_num, choice+pre_ot_ini.n);
        }else {
            base_cot->cot_gen(&pre_ot_ini, pre_ot_ini.n); 
            // base_cot->cot_gen(pre_data_ini, param.k_pre + mpcot_ini.consist_check_cot_num);
            base_cot->cot_gen(pre_data_ini, mpcot_ini.consist_check_cot_num);
        }
		// extend(ot_pre_data, &mpcot_ini, &pre_ot_ini, &lpn, pre_data_ini, seed);
		extend(ot_pre_data, &mpcot_ini, &pre_ot_ini, &ssd_init, pre_data_ini, seed);
		delete[] pre_data_ini;
	}

	fut.get();
}

template<typename T>
void FerretCOT<T>::rcot(block *data, int64_t num) {
	if(ot_data == nullptr) {
		ot_data = new block[param.n];
		memset(ot_data, 0, param.n*sizeof(block));
	}
	if(extend_initialized == false) 
		error("Run setup before extending");
	if(num <= silent_ot_left()) {
		memcpy(data, ot_data+ot_used, num*sizeof(block));
		ot_used += num;
		return;
	}
	block *pt = data;
	int64_t gened = silent_ot_left();
	if(gened > 0) {
		memcpy(pt, ot_data+ot_used, gened*sizeof(block));
		pt += gened;
	}
	int64_t round_inplace = (num-gened-M) / ot_limit;
	int64_t last_round_ot = num-gened-round_inplace*ot_limit;
	bool round_memcpy = last_round_ot>ot_limit?true:false;
	if(round_memcpy) last_round_ot -= ot_limit;
	for(int64_t i = 0; i < round_inplace; ++i) {
		extend_f2k(pt);
		ot_used = ot_limit;
		pt += ot_limit;
	}
	if(round_memcpy) {
		extend_f2k();
		memcpy(pt, ot_data, ot_limit*sizeof(block));
		pt += ot_limit;
	}
	if(last_round_ot > 0) {
		extend_f2k();
		memcpy(pt, ot_data, last_round_ot*sizeof(block));
		ot_used = last_round_ot;
	}
}

template<typename T>
int64_t FerretCOT<T>::silent_ot_left() {
	return ot_limit-ot_used;
}

template<typename T>
void FerretCOT<T>::write_pre_data128_to_file(void* loc, __uint128_t delta, std::string filename) {
	std::ofstream outfile(filename);
	if(outfile.is_open()) outfile.close();
	else error("create a directory to store pre-OT data");
	FileIO fio(filename.c_str(), false);
	fio.send_data(&party, sizeof(int64_t));
	if(party == ALICE) fio.send_data(&delta, 16);
	fio.send_data(&param.n, sizeof(int64_t));
	fio.send_data(&param.t, sizeof(int64_t));
	fio.send_data(&param.k, sizeof(int64_t));
	fio.send_data(loc, param.n_pre*16);
}

template<typename T>
__uint128_t FerretCOT<T>::read_pre_data128_from_file(void* pre_loc, std::string filename) {
	FileIO fio(filename.c_str(), true);
	int in_party;
	fio.recv_data(&in_party, sizeof(int64_t));
	if(in_party != party) error("wrong party");
	__uint128_t delta = 0;
	if(party == ALICE) fio.recv_data(&delta, 16);
	int64_t nin, tin, kin;
	fio.recv_data(&nin, sizeof(int64_t));
	fio.recv_data(&tin, sizeof(int64_t));
	fio.recv_data(&kin, sizeof(int64_t));
	if(nin != param.n || tin != param.t || kin != param.k)
		error("wrong parameters");
	fio.recv_data(pre_loc, param.n_pre*16);
	std::remove(filename.c_str());
	return delta;
}

template<typename T>
int64_t FerretCOT<T>::byte_memory_need_inplace(int64_t ot_need) {
	int64_t round = (ot_need - 1) / ot_limit;
	return round * ot_limit + param.n;
}

// extend f2k (benchmark)
// parameter "length" should be the return of "byte_memory_need_inplace"
// output the number of COTs that can be used
template<typename T>
int64_t FerretCOT<T>::rcot_inplace(block *ot_buffer, int64_t byte_space, block seed) {
	if(byte_space < param.n) error("space not enough");
	if((byte_space - M) % ot_limit != 0) error("call byte_memory_need_inplace \
			to get the correct length of memory space");
	int64_t ot_output_n = byte_space - M;
	int64_t round = ot_output_n / ot_limit;
	block *pt = ot_buffer;
	for(int64_t i = 0; i < round; ++i) {
		if(party == ALICE)
		    pre_ot->send_pre(ot_pre_data, Delta);
		else pre_ot->recv_pre(ot_pre_data);
		if(this->is_malicious) seed = zero_block;
		// extend(pt, mpcot, pre_ot, lpn_f2, ot_pre_data, seed);
		extend(pt, mpcot, pre_ot, ssd_f2, ot_pre_data, seed);
		pt += ot_limit;
		memcpy(ot_pre_data, pt, M*sizeof(block));
	}
	return ot_output_n;
}

template<typename T>
void FerretCOT<T>::online_sender(block *data, int64_t length) {
	bool *bo = new bool[length];
	io->recv_bool(bo, length*sizeof(bool));
	for(int64_t i = 0; i < length; ++i) {
		data[i] = data[i] ^ ch[bo[i]];
	}
	delete[] bo;
}

template<typename T>
void FerretCOT<T>::online_recver(block *data, const bool *b, int64_t length) {
	bool *bo = new bool[length];
	for(int64_t i = 0; i < length; ++i) {
		bo[i] = b[i] ^ getLSB(data[i]);
	}
	io->send_bool(bo, length*sizeof(bool));
	delete[] bo;
}

template<typename T>
void FerretCOT<T>::send_cot(block * data, int64_t length) {
	rcot(data, length);
	online_sender(data, length);
}

template<typename T>
void FerretCOT<T>::recv_cot(block* data, const bool * b, int64_t length) {
	rcot(data, length);
	online_recver(data, b, length);
}

template<typename T>
void FerretCOT<T>::assemble_state(void * data, int64_t size) {
	unsigned char * array = (unsigned char * )data;
	int64_t party_tmp = party;
	memcpy(array, &party_tmp, sizeof(int64_t));
	memcpy(array + sizeof(int64_t), &param.n, sizeof(int64_t));
	memcpy(array + sizeof(int64_t) * 2, &param.t, sizeof(int64_t));
	memcpy(array + sizeof(int64_t) * 3, &param.k, sizeof(int64_t));
	memcpy(array + sizeof(int64_t) * 4, &Delta, sizeof(block));	
	memcpy(array + sizeof(int64_t) * 4 + sizeof(block), ot_pre_data, sizeof(block)*param.n_pre);
	if (ot_pre_data!= nullptr)
		delete[] ot_pre_data;
	ot_pre_data = nullptr;
}

template<typename T>
int FerretCOT<T>::disassemble_state(const void * data, int64_t size) {
	const unsigned char * array = (const unsigned char * )data;
	int64_t n2 = 0, t2 = 0, k2 = 0, party2 = 0;
	ot_pre_data = new block[param.n_pre];
	memcpy(&party2, array, sizeof(int64_t));
	memcpy(&n2, array + sizeof(int64_t), sizeof(int64_t));
	memcpy(&t2, array + sizeof(int64_t) * 2, sizeof(int64_t));
	memcpy(&k2, array + sizeof(int64_t) * 3, sizeof(int64_t));
	if(party2 != party or n2 != param.n or t2 != param.t or k2 != param.k) {
		return -1;
	}
	memcpy(&Delta, array + sizeof(int64_t) * 4, sizeof(block));	
	memcpy(ot_pre_data, array + sizeof(int64_t) * 4 + sizeof(block), sizeof(block)*param.n_pre);

	extend_initialization();
	ch[1] = Delta;
	return 0;
}

template<typename T>
int64_t FerretCOT<T>::state_size() {
	return sizeof(int64_t) * 4 + sizeof(block) + sizeof(block)*param.n_pre;
}


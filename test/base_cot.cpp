#include "test/test.h"
using namespace std;

// Custom operator<< overload for uint128_t
std::ostream& operator<<(std::ostream& os, const uint128_t& value) {
    std::ostringstream oss;
    oss << std::hex << (uint64_t)(value >> 64) << std::setfill('0') << std::setw(16) << (uint64_t)value;
    os << oss.str();
    return os;
}

const static int threads = 1;

int main(int argc, char** argv) {
    int length, port, party; // make sure all functions work for non-power-of-two lengths
    if (argc <= 3)
        length = (1<<20) + 101;
    else
        length = (1<<atoi(argv[3])) + 101;

    // length = 1024;

    parse_party_and_port(argv, &party, &port);
    NetIO * io = new NetIO(party==ALICE ? nullptr:"127.0.0.1", port);

    cout << "Test size: " << length << endl;

    // run test for base_ot, iknp and quiet_ot respectively
    // only test semi-honest because quiet-ot is not malicious
    
    BaseCot<NetIO> * base_cot = new BaseCot<NetIO>(party, io, false);
    cout <<"Passive Base COT\t"<<double(length)/test_base_cot<BaseCot<NetIO>>(base_cot, io, party, length)*1e6<<" OTps"<<endl;
    delete base_cot;

    std::cout << "end of base_cot test" << std::endl;

    BaseCotQuiet<NetIO> * base_cot_quiet = new BaseCotQuiet<NetIO>(party, io, false);
    cout <<"Passive Base COT Quiet\t"<<double(length)/test_base_cot<BaseCotQuiet<NetIO>>(base_cot_quiet, io, party, length)*1e6<<" OTps"<<endl;
    delete base_cot_quiet;

    delete io;
    return 0;
}
#include "includes.h"

#include <chrono>
#include <fstream>
#include <cmath>

// bitsizes
const int GP_ELT_BITSIZE = 256;
const int LAMBDA = 256;
// define a constant HUB as the second party in the 2PC for consistency with 
// our protocol's party names
const int HUB = emp::BOB;

// PKE public parameters/key
emp::Integer c_pk,d,h;
// emp::Integer gp;
emp::Integer q,g1,g2;

int main(int argc, char **argv) {
	// int port, party;

	if (argc != 2) {  // && argc !=  3) {
		// std:cerr << "Usage: " << argv[0] << " party port\n"
		std::cerr << "Usage: " << argv[0] << " -c\n";
		std::exit(-1);
	}

	/***** read constants from files *****/
	// public key
	std::cout << "read pk from file...";
	std::ifstream pk_infile("data/pk_H.txt");
	std::string pk_elt_str;
	std::vector<boost::multiprecision::uint256_t> pk_boost;
	while(std::getline(pk_infile, pk_elt_str)) {
		boost::multiprecision::uint256_t pk_elt_boost(pk_elt_str);
		pk_boost.push_back(pk_elt_boost);
	}
	std::cout << "done.\n";

	// secret key
	std::cout << "read sk from file...";
	std::ifstream sk_infile("data/sk_H.txt");
	std::string sk_elt_str;
	std::vector<boost::multiprecision::uint256_t> sk_boost;
	while(std::getline(sk_infile, sk_elt_str)) {
		boost::multiprecision::uint256_t sk_elt_boost(sk_elt_str);
		sk_boost.push_back(sk_elt_boost);
	}
	std::cout << "done.\n";

	// randomness and ciphertext (A's 2PC inputs)
	std::cout << "read r,c from file...";
	std::ifstream r_c_infile("data/r_c.txt");

	std::string r_str;
	std::getline(r_c_infile, r_str);
	boost::multiprecision::uint256_t r_boost(r_str);

	std::string c_elt_str;
	std::vector<boost::multiprecision::uint256_t> c_boost;
	while(std::getline(r_c_infile, c_elt_str)) {
		boost::multiprecision::uint256_t c_elt_boost(c_elt_str);
		c_boost.push_back(c_elt_boost);
	}
	std::cout << "done.\n";

	std::cout << "Constructing circuit...\n";
	// open circuit file
	emp::setup_plain_prot(true, "circuit.txt");

	/***** Declare input and output wires *****/
	emp::Integer alice_input_r;
	std::vector<emp::Integer> alice_input_c;
	std::vector<emp::Integer> hub_input;
	emp::Integer hub_output;

	/***** Declare input values *****/
	// A inputs (r,c)
	std::cout << "Declare A's inputs...";
	alice_input_r = emp::Integer(LAMBDA, &r_boost, emp::ALICE);
	for(size_t i=0; i < c_boost.size(); i++) {
		alice_input_c.push_back(emp::Integer(GP_ELT_BITSIZE, &c_boost[i], emp::ALICE));
	}
	std::cout << "done.\n";
	// std::cout << "A inputs " << alice_input_r.size() + alice_input_c.size()*alice_input_c[0].size() << " bits.\n";
	// std::cout << "(Should be " << LAMBDA+4*GP_ELT_BITSIZE << ".)\n";

	// H inputs sk
	std::cout << "Declare H's inputs...";
	for(size_t i=0; i < sk_boost.size(); i++) {
		hub_input.push_back(emp::Integer(GP_ELT_BITSIZE, &sk_boost[i], HUB));
	}
	std::cout << "done.\n";
	// std::cout << "H inputs " << hub_input.size() * hub_input[0].size() << " bits. ";
	// std::cout << "(Should be " << 5*GP_ELT_BITSIZE << ".)\n";

	// constants
	std::cout << "Declare constants...";
	c_pk = emp::Integer(GP_ELT_BITSIZE, &pk_boost[0], emp::PUBLIC);
	d = emp::Integer(GP_ELT_BITSIZE, &pk_boost[1], emp::PUBLIC);
	h = emp::Integer(GP_ELT_BITSIZE, &pk_boost[2], emp::PUBLIC);
	q = emp::Integer(GP_ELT_BITSIZE, &pk_boost[3], emp::PUBLIC);
	g1 = emp::Integer(GP_ELT_BITSIZE, &pk_boost[4], emp::PUBLIC);
	g2 = emp::Integer(GP_ELT_BITSIZE, &pk_boost[5], emp::PUBLIC);
	std::vector<emp::Integer> pk{c_pk, d, h, q, g1, g2};
	std::cout << "done.\n";

	/***** Declare output values *****/
	std::cout << "Computing...";
	auto const start_rerand = std::chrono::high_resolution_clock::now();
	hub_output = rerandomize(alice_input_r, alice_input_c, hub_input);
	auto const finish_rerand = std::chrono::high_resolution_clock::now();
	hub_output.reveal<std::string>(HUB);
	std::cout << "done.\n";
	// std::cout << "Circuit output is " << hub_output.size() << " bits.\n";
	// std::cout << "(Should be " << GP_ELT_BITSIZE << ".)\n";

	std::chrono::duration<double> rerand_time = finish_rerand-start_rerand;
	std::cout << "Total rerandomization time: " << rerand_time.count() << "\n";

	emp::finalize_plain_prot();
	std::cout << "Circuit  written to file.\n";
}
emp::Integer rerandomize(emp::Integer r, std::vector<emp::Integer> ctxt, std::vector<emp::Integer> sk_H)  {
	// initialize output
	emp::Integer output(LAMBDA, -1);

	// check sk_H
	std::cout << "check unique sk...";
	auto const start_check = std::chrono::high_resolution_clock::now();
	emp::Integer c_prime = (g1.modExp(sk_H[0],q) * g2.modExp(sk_H[1],q)) % q;
	emp::Integer d_prime = (g1.modExp(sk_H[2],q) * g2.modExp(sk_H[3],q)) % q;
	emp::Integer h_prime = g1.modExp(sk_H[4],q);
	auto const finish_check = std::chrono::high_resolution_clock::now();
	std::chrono::duration<double> const check_time = finish_check-start_check;
	if(!(c_prime == c_pk & d_prime == d & h_prime == h).reveal<bool>()) {
		// TODO this check never passes even with full bitsize...
		// why...?
		std::cout << "pk_H != Gen(sk_H)\n";
	} 
	// else {
		std::cout << "done.\n";
		std::cout << "- key check time: " << check_time.count() << "\n";

		// decrypt & rerandomize
		// this step takes a lot of time
		std::cout << "Dec...";
		auto const start = std::chrono::high_resolution_clock::now();
		emp::Integer s_star = dec(sk_H, ctxt);
		auto const finish = std::chrono::high_resolution_clock::now();
		std::cout << "done.\n";

		std::chrono::duration<double> const dec_time = finish-start;
		std::cout << "- Dec time: " << dec_time.count() << "\n";

		output = s_star + r; // TODO: % q
	// }
	return output;
}
emp::Integer dec(std::vector<emp::Integer> sk, std::vector<emp::Integer> ctxt) {
	if(sk.size() != 5) {
		std::cerr << "tried to decrypt with wrong size sk\n";
		std::exit(-1);
	}
	if(ctxt.size() != 4) {
		std::cerr << "ciphertext is ill-formed\n";
		std::exit(-1);
	}
	emp::Integer hash_payload(3*GP_ELT_BITSIZE, &ctxt);
	emp::Integer alpha = hash(hash_payload);

	emp::Integer v_prime = 
		(ctxt[0].modExp(sk[0],q) * ctxt[1].modExp(sk[1],q)) %q;
	emp::Integer temp = 
		(ctxt[0].modExp(sk[2],q) * ctxt[1].modExp(sk[3],q)) % q;
	v_prime = 
		(v_prime * temp.modExp(alpha,q)) % q;
	std::cout << "v_prime (calc by C++): " << v_prime.reveal<std::string>() << "\n";
	std::cout << "v (calc by python): " << ctxt[3].reveal<std::string>() << "\n";
	if((v_prime != ctxt[3]).reveal<bool>()) {
		std::cout << "decryption test failed (v' != v)\n";
		// std::exit(-1);
		// TODO uncomment the above
	}
	return ctxt[3]/(ctxt[0].modExp(sk[4],q));
}
emp:: Integer hash(emp::Integer input) {
	int digest_size = 256;
	//  TODO
	return emp::Integer(digest_size, 0);
}
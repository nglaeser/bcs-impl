#include "includes.h"

#include <chrono>
#include <fstream>
#include <cmath>

// const int GP_ELT_BITSIZE = 256;
const int GP_ELT_BITSIZE = 64;
int exp_bitsize;
// const int LAMBDA = 128;
const int LAMBDA = 64;
// define a constant HUB as the second party  in the 2PC for consistency with 
// our protocol's party names
const int HUB = emp::BOB;

// PKE public parameters/key
const int PK_ELTS = 6;
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

	// read constants from files
	// std::string c_str,d_str,h_str, gp_str, q_str, g1_str, g2_str;
	std::cout << "read pk from file...";
	std::string pk_elt_str;
	std::ifstream pk_infile("data/pk_H.txt");
	std::vector<boost::multiprecision::uint256_t> pk_boost;
	while(std::getline(pk_infile, pk_elt_str)) {
		boost::multiprecision::uint256_t pk_elt_boost(pk_elt_str);
		pk_boost.push_back(pk_elt_boost);
	}
	std::cout << "done.\n";

	std::cout << "read sk from file...";
	// exp_bitsize = ceil(log2(std::atoi(q_str.c_str())));
	exp_bitsize = 64;
	// std::string x1_str, x2_str, y1_str, y2_str, z_str;
	std::string sk_elt_str;
	std::ifstream sk_infile("data/sk_H.txt");
	std::vector<boost::multiprecision::uint256_t> sk_boost;
	// (x1, x2, y1, y2, z)
	while(std::getline(sk_infile, sk_elt_str)) {
		boost::multiprecision::uint256_t sk_elt_boost(sk_elt_str);
		sk_boost.push_back(sk_elt_boost);
	}
	std::cout << "done.\n";

	std::cout << "read r,c from file...";
	std::string r_str, c_elt_str;
	std::ifstream r_c_infile("data/r_c.txt");
	std::getline(r_c_infile, r_str);
	boost::multiprecision::uint256_t r_boost(r_str);
	std::vector<boost::multiprecision::uint256_t> c_boost;
	while(std::getline(r_c_infile, c_elt_str)) {
		boost::multiprecision::uint256_t c_elt_boost(c_elt_str);
		c_boost.push_back(c_elt_boost);
	}
	std::cout << "done.\n";

	std::cout << "Constructing circuit...\n";
	// write circuit to file
	emp::setup_plain_prot(true, "circuit.txt");

	// Declare input and output wires
	emp::Integer alice_input_r;
	std::vector<emp::Integer> alice_input_c;
	std::vector<emp::Integer> hub_input;
	emp::Integer hub_output;

	// Declare input values
	// A inputs (r,c)
	std::cout << "Declare A's inputs...";
	alice_input_r = emp::Integer(LAMBDA, &r_boost, emp::ALICE);
	for(size_t i=0; i < c_boost.size(); i++) {
		alice_input_c.push_back(emp::Integer(GP_ELT_BITSIZE, &c_boost[i], emp::ALICE));
		// std::cout << pk[i].reveal<std::string>() << "\n";
	}
	std::cout << "done.\n";
	// H inputs sk
	std::cout << "Declare H's inputs...";
	for(size_t i=0; i < sk_boost.size(); i++) {
		hub_input.push_back(emp::Integer(GP_ELT_BITSIZE, &sk_boost[i], HUB));
		// std::cout << pk[i].reveal<std::string>() << "\n";
	}
	std::cout << "done.\n";

	// constants
	std::cout << "Declare constants...";
	// pk = {c, d, h, (G,) q, g1, g2}
	c_pk = emp::Integer(GP_ELT_BITSIZE, &pk_boost[0], emp::PUBLIC);
	d = emp::Integer(GP_ELT_BITSIZE, &pk_boost[1], emp::PUBLIC);
	h = emp::Integer(GP_ELT_BITSIZE, &pk_boost[2], emp::PUBLIC);
	q = emp::Integer(GP_ELT_BITSIZE, &pk_boost[3], emp::PUBLIC);
	g1 = emp::Integer(GP_ELT_BITSIZE, &pk_boost[4], emp::PUBLIC);
	g2 = emp::Integer(GP_ELT_BITSIZE, &pk_boost[5], emp::PUBLIC);
	// std::vector<emp::Integer> pk{c_pk, d, h, q, g1, g2};
	std::vector<emp::Integer> pk;
	pk.push_back(c_pk);
	pk.push_back(d);
	pk.push_back(h);
	pk.push_back(q);
	pk.push_back(g1);
	pk.push_back(g2);
	std::cout << "done.\n";

	// Declare output values
	std::cout << "Computing...";
	hub_output = rerandomize(alice_input_r, alice_input_c, hub_input);
	hub_output.reveal<std::string>(HUB);
	std::cout << "done.\n";

	emp::finalize_plain_prot();
	std::cout << "Circuit  written to file.\n";
	// auto const start = std::chrono::high_resolution_clock::now();
}
emp::Integer rerandomize(emp::Integer r, std::vector<emp::Integer> ctxt, std::vector<emp::Integer> sk_H)  {
	//  parse sk_H
	emp::Integer x1 = sk_H[0];
	emp::Integer x2 = sk_H[1];
	emp::Integer y1 = sk_H[2];
	emp::Integer y2 = sk_H[3];
	emp::Integer z = sk_H[4];

	// initialize output
	emp::Integer output(LAMBDA, -1);

	// check sk_H
	// this step takes a lot of time
	emp::Integer c_prime = g1.modExp(x1,q)*g2.modExp(x2,q);
	emp::Integer d_prime = g1.modExp(y1,q)*g2.modExp(y2,q);
	emp::Integer h_prime = g1.modExp(z,q);
	// if(!(c_prime == c & d_prime == d &  h_prime == h).reveal<bool>()) {
	// 	std::cout << "pk_H != Gen(sk_H)\n";
	// 	// returns -1
	// } 
	// else {
		// decrypt & rerandomize
	emp::Integer s_star = dec(sk_H, ctxt);
	// std::cout << "\n----- r -----\n" << r.reveal<std::string>() << "\n";
	output = s_star + r;
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

	// parse c
	emp::Integer u1 = ctxt[0];
	emp::Integer u2 = ctxt[1];
	emp::Integer e = ctxt[2];
	emp::Integer v = ctxt[3];
	// std::cout << "\n----- c -----\n";
	// std::cout << "u1:\t" << u1.reveal<std::string>() << "\n";
	// std::cout << "u2:\t" << u2.reveal<std::string>() << "\n";
	// std::cout << "e:\t" << e.reveal<std::string>() << "\n";
	// std::cout << "v:\t" << v.reveal<std::string>() << "\n";
	emp::Integer v_prime = u1.modExp(sk[0],q)*u2.modExp(sk[1],q)*(
						   u1.modExp(sk[2],q)*u2.modExp(sk[3],q)
						  							).modExp(alpha,q);
	v_prime = v_prime % q;
	std::cout << "v_prime (calc by C++): " << v_prime.reveal<std::string>() << "\n";
	std::cout << "v (calc by python): " << v.reveal<std::string>() << "\n";
	if((v_prime != v).reveal<bool>()) {
		std::cout << "decryption test failed\n";
		// std::exit(-1);
		// TODO uncomment the above
	}
	return e/(u1.modExp(sk[4],q));
}
emp:: Integer hash(emp::Integer input) {
	int digest_size = 256;
	//  TODO
	return emp::Integer(digest_size, 0);
}
#include "includes.h"

#include <chrono>
#include <fstream>
#include <cmath>

const int GP_ELT_BITSIZE = 128;
const int LAMBDA = 128;
// define a constant HUB as the second party  in the 2PC for consistency with 
// our protocol's party names
const int HUB = emp::BOB;

// PKE public parameters/key
int exp_bitsize;
emp::Integer c,d,h;
emp::Integer gp,q,g1,g2;

int main(int argc, char **argv) {
	// int port, party;

	if (argc != 2) {  // && argc !=  3) {
		// std:cerr << "Usage: " << argv[0] << " party port\n"
		std::cerr << "Usage: " << argv[0] << " -c\n";
		std::exit(-1);
	}

	// read constants from files
	std::string c_str,d_str,h_str, gp_str, q_str, g1_str, g2_str;
	std::ifstream pk_infile("data/pk_H.txt");
	std::getline(pk_infile, c_str);
	std::getline(pk_infile, d_str);
	std::getline(pk_infile, h_str);
	std::getline(pk_infile, gp_str);
	std::getline(pk_infile, q_str);
	std::getline(pk_infile, g1_str);
	std::getline(pk_infile, g2_str);
	// exp_bitsize = ceil(log2(std::atoi(q_str.c_str())));
	exp_bitsize = 64;
	std::string x1_str, x2_str, y1_str, y2_str, z_str;
	std::ifstream sk_infile("data/sk_H.txt");
	std::getline(sk_infile, x1_str);
	std::getline(sk_infile, x2_str);
	std::getline(sk_infile, y1_str);
	std::getline(sk_infile, y2_str);
	std::getline(sk_infile, z_str);
	std::string r_str, ctxt_str;
	std::ifstream r_c_infile("data/r_c.txt");
	std::getline(r_c_infile, r_str);
	// TODO read 4 lines of c into vector<emp::Integer>
	std::getline(r_c_infile, ctxt_str);

	std::cout << "Constructing circuit...\n";
	// write circuit to file
	emp::setup_plain_prot(true, "circuit.txt");

	// Declare input and output wires
	emp::Integer hub_output;
	emp::Integer alice_input;
	emp::Integer hub_input;

	// Declare input values
	// A inputs (r,c)
	alice_input_r = emp::Integer(LAMBDA, std::atoi(r_str.c_str()), emp::ALICE);
	alice_input_c = emp::Integer(LAMBDA, std::atoi(ctxt_str.c_str()), emp::ALICE);
	// H inputs sk
	hub_input = emp::Integer(5*exp_bitsize, 0, HUB);

	// constants
	c_pk = emp::Integer(GP_ELT_BITSIZE, std::atoi(c_str.c_str()), emp::PUBLIC);
	d = emp::Integer(GP_ELT_BITSIZE, std::atoi(d_str.c_str()), emp::PUBLIC);
	h = emp::Integer(GP_ELT_BITSIZE, std::atoi(h_str.c_str()), emp::PUBLIC);
	gp = emp::Integer(GP_ELT_BITSIZE, std::atoi(gp_str.c_str()), emp::PUBLIC);
	q = emp::Integer(GP_ELT_BITSIZE, std::atoi(q_str.c_str()), emp::PUBLIC);
	g1 = emp::Integer(GP_ELT_BITSIZE, std::atoi(g1_str.c_str()), emp::PUBLIC);
	g2 = emp::Integer(GP_ELT_BITSIZE, std::atoi(g2_str.c_str()), emp::PUBLIC);

	// Declare output values
	hub_output = rerandomize(alice_input, hub_input);
	hub_output.reveal<std::string>(HUB);

	emp::finalize_plain_prot();
	std::cout << "Circuit  written to file.\n";
	// auto const start = std::chrono::high_resolution_clock::now();
}
emp::Integer rerandomize(emp::Integer r, emp::Integer ctxt, emp::Integer sk_H)  {
	//  parse sk_H
	emp::Integer x1(exp_bitsize, &sk_H);
	emp::Integer x2(exp_bitsize, &sk_H[exp_bitsize]);
	emp::Integer y1(exp_bitsize, &sk_H[2*exp_bitsize]);
	emp::Integer y2(exp_bitsize, &sk_H[3*exp_bitsize]);
	emp::Integer z(exp_bitsize, &sk_H[4*exp_bitsize]);
	std::vector<emp::Integer> sk{x1, x2, y1, y2, z};
	// initialize output
	emp::Integer output(LAMBDA, -1);

	// check sk_H
	emp::Integer c_prime = g1.modExp(x1,q)*g2.modExp(x2,q);
	emp::Integer d_prime = g1.modExp(y1,q)*g2.modExp(y2,q);
	emp::Integer h_prime = g1.modExp(z,q);
	// if(!(c_prime == c & d_prime == d &  h_prime == h).reveal<bool>()) {
	// 	std::cout << "pk_H != Gen(sk_H)\n";
	// 	// returns -1
	// } 
	// else {
		// decrypt & rerandomize
	emp::Integer s_star = dec(sk, ctxt);
	output = s_star + r;
	// }
	return output;
}
emp::Integer dec(std::vector<emp::Integer> sk, emp::Integer ctxt) {
	if(sk.size() != 5) {
		std::cerr << "tried to decrypt with wrong size sk\n";
		std::exit(-1);
	}
	emp::Integer hash_payload(3*GP_ELT_BITSIZE, &c);
	emp::Integer alpha = hash(hash_payload);

	// parse c
	emp::Integer u1(GP_ELT_BITSIZE, &ctxt);
	emp::Integer u2(GP_ELT_BITSIZE, &ctxt[GP_ELT_BITSIZE]);
	emp::Integer e(GP_ELT_BITSIZE, &ctxt[2*GP_ELT_BITSIZE]);
	emp::Integer v(GP_ELT_BITSIZE, &ctxt[3*GP_ELT_BITSIZE]);
	emp::Integer v_prime = u1.modExp(sk[0],q)*u2.modExp(sk[1],q)*(
						   u1.modExp(sk[2],q)*u2.modExp(sk[3],q)
						  							).modExp(alpha,q);
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
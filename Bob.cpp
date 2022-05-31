//Bob Code
#include <tomcrypt.h>
#include <string>
#include <iostream>
#include <cstdlib>
#include <iomanip>
#include <fstream>
#include <math.h>
#include <chrono>
#include <thread>
#include "zmq.hpp"
#include "methodsHW5.cpp"
extern ltc_math_descriptor ltc_mp;
extern const ltc_math_descriptor ltm_desc;
using namespace std;
using namespace std::chrono_literals;

prng_state Make_PRNG(prng_state *prng){
    int err;
    //PRNG
    std::string seed = "a totally secure and random string";
    if (register_prng(&fortuna_desc) == -1) {
            printf("Error registering Fortuna \n");
            exit(-1);
    }
 /* setup the PRNG */
    if ((err = rng_make_prng(128, find_prng("fortuna"), prng, NULL)) != CRYPT_OK) {
            printf("Error setting up PRNG, %s\n", error_to_string(err));
            exit(-1);
    }
    fortuna_add_entropy((const unsigned char*)seed.c_str(), seed.size(), prng);

    if (register_hash(&sha256_desc) == -1) {
            printf("Error registering sha256");
            exit(-1);
    }
    return *prng;
}


int main()
{
ltc_mp = ltm_desc;
prng_state prng;
prng=Make_PRNG(&prng);

//Read Message from AlicePrivateKey.txt
    ifstream b_private_file("BobPrivateKey.txt");
    string b_private_hex((istreambuf_iterator<char>(b_private_file)),istreambuf_iterator<char>());
    string b_private = "";
    for (size_t i = 0; i < b_private_hex.length(); i += 2)
    {
        char ch = stoul(b_private_hex.substr(i, 2), nullptr, 16);
        b_private += ch;
    }
    unsigned long b_private_len = (unsigned long) b_private.length();
  
  
//Read Message from AlicePublicKey.txt
    ifstream a_public_file("AlicePublicKey.txt");
    string a_public_hex((istreambuf_iterator<char>(a_public_file)),istreambuf_iterator<char>());
    string a_public = "";
    for (size_t i = 0; i < a_public_hex.length(); i += 2)
    {
        char ch = stoul(a_public_hex.substr(i, 2), nullptr, 16);
        a_public += ch;
    }
    unsigned long a_public_len = (unsigned long) a_public.length();

    
//Read Message from BobPublicKey.txt
    ifstream b_public_file("BobPublicKey.txt");
    string b_public_hex((istreambuf_iterator<char>(b_public_file)),istreambuf_iterator<char>());  
    string b_public = "";
    for (size_t i = 0; i < b_public_hex.length(); i += 2)
    {
        char ch = stoul(b_public_hex.substr(i, 2), nullptr, 16);
        b_public += ch;
    }
    unsigned long b_public_len = (unsigned long) b_public.length();
	
// import alice public key	
    rsa_key a_key = Import_Key((unsigned char *)a_public.c_str(), a_public_len, &a_key);
    
// import bob private key
    rsa_key b_key = Import_Key((unsigned char *)b_private.c_str(), b_private_len , &b_key);


// Prepare our context and socket
    zmq::context_t context (2);
    zmq::socket_t socket (context, zmq::socket_type::rep);
    socket.bind ("tcp://*:5555");
    zmq::message_t request;


// Wait for next request from client
//receive ciphertext
    socket.recv (request, zmq::recv_flags::none);
    string rpl = string(static_cast<char*>(request.data()), request.size());
    string cipher_hex=rpl;
    
//convert hex to normal
    string cipher = "";
    for (size_t i = 0; i < cipher_hex.length(); i += 2)
    {
        char ch = stoul(cipher_hex.substr(i, 2), nullptr, 16);
        cipher+= ch;
    }
    unsigned long cipher_len = (unsigned long) cipher.length();	
	
//receive signature	
    zmq::message_t request2;
    socket.recv (request2, zmq::recv_flags::none);
    string rpl2 = string(static_cast<char*>(request2.data()), request2.size());
    string sign_hex=rpl2;
    
//convert hex to normal   
    string sign = "";
    for (size_t i = 0; i < sign_hex.length(); i += 2)
    {
        char ch = stoul(sign_hex.substr(i, 2), nullptr, 16);
        sign+= ch;
    }
    unsigned long sign_len = (unsigned long) sign.length();

	
//Verification of signature
    int* stat=new int();
    stat=Do_RSA_Verify((unsigned char *)sign.c_str(),sign_len,(unsigned char *)cipher.c_str(), (unsigned long)cipher.length(),stat, &a_key);

        
    if(*stat==0){
    	cout<<"Invalid Signature"<<endl;
    }
    else{
        cout<<"Verification Successful"<<endl;
        
        //Decrypt
        unsigned char plain[4096];
        unsigned long plain_len=4096;
        Do_RSA_Decryption((unsigned char *)cipher.c_str(),(unsigned long)cipher.length(),plain,&plain_len,&b_key);       
        string plaintext="";
        for(int i=0;i<plain_len;i++) 
       {
 	  plaintext+=plain[i];       
      	}
      	
      	//write cipher's hex to "Plaintext.txt"
        ofstream fout1;
	string fname_plain="Plaintext.txt";
	fout1.open(fname_plain, ios::out);
	fout1<<plaintext;
	fout1.close(); 
        
   }
   return 0;
}

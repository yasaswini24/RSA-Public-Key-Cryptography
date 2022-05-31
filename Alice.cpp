//Alice Code
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
/****************************************************************************
                                    PRNG for Alice
*****************************************************************************/
/*
This is the first function you use before importing the keys
*/
//=====Use this function=====
prng_state Make_PRNG(prng_state *prng){
    int err;
    //PRNG
    std::string seed = "This is another string for creating prng";
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
    ifstream a_private_file("AlicePrivateKey.txt");
    string a_private_hex((istreambuf_iterator<char>(a_private_file)),istreambuf_iterator<char>());
    string a_private = "";
    for (size_t i = 0; i < a_private_hex.length(); i += 2)
    {
   
        char ch = stoul(a_private_hex.substr(i, 2), nullptr, 16);
        a_private += ch;
    }
    unsigned long a_private_len = (unsigned long) a_private.length();
 


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
	
// import alice private key	 
    rsa_key a_key = Import_Key((unsigned char *)a_private.c_str(), a_private_len, &a_key);
    
// import bob public key
    rsa_key b_key = Import_Key((unsigned char *)b_public.c_str(), b_public_len , &b_key);

//Read Message from Message.txt
    ifstream msg_file("Message.txt");
    string message((istreambuf_iterator<char>(msg_file)),istreambuf_iterator<char>());
    int n_message=message.length();
    char message_array[n_message];
    strcpy(message_array,message.c_str());
    unsigned long message_len = (unsigned long) message.length();
    
//Encrypt
    unsigned long cipher_len=4096;
    unsigned char cipher[4096];
    Do_RSA_Encryption((unsigned char*)message_array, message_len ,cipher,&cipher_len, &prng, &b_key);
    
// convert cipher to hex 
    string cipher_hex="";
    for(int i=0;i<cipher_len;i++){
    stringstream ss;
    char temp_ch;
    ss<<hex<<setw(2)<<setfill('0')<<(int)cipher[i];
    cipher_hex+=ss.str();
    }

//write cipher's hex to "Ciphertext.txt"
    ofstream fout1;
    string fname_cipher="Ciphertext.txt";
    fout1.open(fname_cipher, ios::out);
    fout1<<cipher_hex;
    fout1.close();
    
//Signature
    unsigned long sign_len=4096;
    unsigned char sign[4096];
    Do_RSA_Sign(cipher,cipher_len,sign,&sign_len,&prng,&a_key);
    
// convert signature to hex     
    string sign_hex="";
    for(int i=0;i<sign_len;i++){
    stringstream ss1;
    char temp_ch_sign;
    ss1<<hex<<setw(2)<<setfill('0')<<(int)sign[i];
    sign_hex+=ss1.str();
    }

   	
//write signature's hex to "Signature.txt"
    ofstream fout2;
    string fname_sign="Signature.txt";
    fout2.open(fname_sign, ios::out);
    fout2<<sign_hex;
    fout2.close(); 
   
    // ------ ZeroMQ ------

// Prepare our context and socket
	zmq::context_t context (1);
	zmq::socket_t socket (context, zmq::socket_type::req);
	cout << "Connecting to server..." << std::endl;
	socket.connect ("tcp://localhost:5555");
	
	size_t zmq_cipher_len=cipher_hex.length();
	zmq::message_t zmq_cipher (zmq_cipher_len);
	memcpy (zmq_cipher.data(),cipher_hex.c_str(), zmq_cipher_len);
	cout << "Sending Ciphertext..." << endl;
	socket.send(zmq_cipher, ZMQ_SNDMORE);

	size_t zmq_sign_len=sign_hex.length();
	zmq::message_t zmq_sign(zmq_sign_len);
	memcpy(zmq_sign.data(), sign_hex.c_str(), zmq_sign_len);
	cout << "Sending Signature..." << endl;
	socket.send(zmq_sign, zmq::send_flags::none);
    
return 0;
}

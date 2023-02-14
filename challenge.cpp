#include <stdio.h>
#include <iostream>
#include <string>
#include <fstream> 
#include <vector>
#include <sstream>

#include <libcryptosec/MessageDigest.h>
#include <libcryptosec/RSAKeyPair.h>
#include <libcryptosec/certificate/CertificateBuilder.h>
#include <libcryptosec/Pkcs12Builder.h>
#include <libcryptosec/Pkcs12Factory.h>
#include <libcryptosec/Signer.h>
#include <libcryptosec/Pkcs7SignedDataBuilder.h>

#include <sys/stat.h>


void createKeysAndCertificate(){	
	MessageDigest::loadMessageDigestAlgorithms();
	SymmetricCipher::loadSymmetricCiphersAlgorithms();

	RSAKeyPair key_pair(2048); 
	RSAPublicKey *pubKey = (RSAPublicKey*) key_pair.getPublicKey();
	RSAPrivateKey *privKey = (RSAPrivateKey*) key_pair.getPrivateKey();
	
	CertificateBuilder certBuilder = CertificateBuilder();
	certBuilder.setVersion(1);
	certBuilder.setSerialNumber(0);

	string in = "";

	cout << "Certificate Creation: " << endl;
	cout << "Country (Two Letters): ";
	getline(cin, in);
	
	RDNSequence rdnSubject;
	rdnSubject.addEntry(RDNSequence::COUNTRY, in);
	in.clear();
	cout << "State: ";
	getline(cin, in);
	rdnSubject.addEntry(RDNSequence::STATE_OR_PROVINCE, in);
	in.clear();
	cout << "Email: ";
	getline(cin, in);
	rdnSubject.addEntry(RDNSequence::EMAIL, in);
	in.clear();
	cout << "Title: ";
	getline(cin, in);
	rdnSubject.addEntry(RDNSequence::TITLE, in);
	in.clear();
	cout << "Full Name: ";
	getline(cin, in);
	string name = in;
	in.clear();
	rdnSubject.addEntry(RDNSequence::COMMON_NAME, name);

	certBuilder.setSubject(rdnSubject);
	certBuilder.setPublicKey(*pubKey);

	time_t now = time(0);
	DateTime dateTimeNow(now);
	DateTime dateTimeExpire(now+60*60*24*365);

	certBuilder.setNotBefore(dateTimeNow);
	certBuilder.setNotAfter(dateTimeExpire);


	Certificate *cert = certBuilder.sign(*privKey, MessageDigest::SHA256);

	for (size_t i = 0; i < name.size(); i++)
	{
		name.at(i) = tolower(name.at(i));
		if (name.at(i) == ' ')
		{
			name.at(i) = '_';
		}
	}

	Pkcs12Builder pkcs12Builder = Pkcs12Builder();
	pkcs12Builder.setKeyAndCertificate(privKey, cert, name);
	pkcs12Builder.addAdditionalCert(cert);

	cout << "Password: ";
	cin >> in;
	
	Pkcs12 *pkcs12 = pkcs12Builder.doFinal(in);
	in.clear();

	ofstream pkcs12_file;
	pkcs12_file.open(string("./certificates/"+name+".p12").c_str());
	for (size_t i = 0; i < pkcs12->getDerEncoded().size(); i++)
	{
		pkcs12_file << pkcs12->getDerEncoded().at(i);
	}
	pkcs12_file.close();


	delete (cert);
	delete (pubKey);
	delete (privKey);
	delete (pkcs12);
}

void signDocument(){
	MessageDigest::loadMessageDigestAlgorithms();
	SymmetricCipher::loadSymmetricCiphersAlgorithms();
	
	cout << "File Path: ";
	string in;
	getline(cin, in);

	string path = in;
	

	ifstream file(in.c_str(), ios::binary);
	if(!file){
		cout << "File not found" << endl;
		return;
	}

	// Get the length of the file
    file.seekg(0, file.end);
    int length = file.tellg();
    file.seekg(0, file.beg);

    // Read the contents of the file into a buffer
    unsigned char* buffer = new unsigned char[length];
    file.read ((char*)buffer, length);
	file.close();


	MessageDigest teste(MessageDigest::SHA256);
	ByteArray b(buffer, length);
	delete[] buffer;
	ByteArray hash = teste.doFinal(b);

	cout << "Signer complete name: ";
	getline(cin, in);

	for (size_t i = 0; i < in.size(); i++)
	{
		in.at(i) = tolower(in.at(i));
		if (in.at(i) == ' ')
		{
			in.at(i) = '_';
		}
	}

	ifstream file2(string("./certificates/" + in + ".p12").c_str(), ios::binary);
	if(!file2){
		cout << "Certificate not found!" << endl << "Please check your speel or create certificate" << endl;
		return;
	}

	// Get the length of the file2
    file2.seekg(0, file2.end);
    length = file2.tellg();
    file2.seekg(0, file2.beg);

    // Read the contents of the file2 into a buffer2
    unsigned char* buffer2 = new unsigned char[length];
    file2.read ((char*)buffer2, length);
	file2.close();
	ByteArray c(buffer2, length);
	delete[] buffer2;

	Pkcs12 p12 = *Pkcs12Factory().fromDerEncoded(c);

	cout << "Signer password: ";
	getline(cin, in);

	Signer sig;
	ByteArray signiture;
	try{
		signiture = sig.sign(*p12.getPrivKey(in), hash, MessageDigest::SHA256);
	}
	catch(Pkcs12Exception){
		cout << "Incorrect Password" << endl;
	}
	if(uncaught_exception()){
		cout << signiture.toHex() << endl;	
	}

	cout << endl<< "Do you: " << endl;
	cout << "1-Agree: " << endl;
	cout << "2-Disagree: " << endl;
	cout << "0-Quit: " << endl;
	getline(cin, in);
	bool accept;

	

	if (in == "1")
	{
		accept = true;
	}
	else if(in == "2"){
		accept = false;
	}
	else if(in == "0"){
		cout << "Ok, think about it" << endl;
	}
	else{
		cout << "Not an option, please choose a number" << endl;
	}
	
	ostringstream  out;
	out << "Decision:" << endl << accept << endl;
	cout << out.str() << endl;
	out << "Signature: " << endl << signiture.toString();

	cout << out.str() << endl;

	ByteArray outf(&out);
	
	int pos = path.find_last_of("/");
	string fileName = path.substr(pos+1);
	pos = fileName.find_last_of(".");
	fileName.erase(pos, fileName.size());

	ofstream out_file;
	out_file.open(string(path+".txt").c_str());
	out_file << out;
	out_file.close();

}

void creatingMemoryFile(){

}

void updateMemoryFile(){

}

void openMemoryFile(){

}

void includeDocument(){

}

int main(int argc, char **argv) {
	MessageDigest::loadMessageDigestAlgorithms();
	SymmetricCipher::loadSymmetricCiphersAlgorithms();

	struct stat st;
	if (stat("./certificates", &st) == -1) {
		mkdir("./certificates", 0700);
	}
	if (stat("./documents", &st) == -1) {
		mkdir("./documents", 0700);
	}

	// while (true)
	// {
	// 	cout << "Functions: " << endl;
	// 	cout << "1-Create Certificate" << endl;
	// 	cout << "2-Import p12 file" << endl;
	// 	cout << "3-Include Document" << endl;
	// 	cout << "4-Sign Document" << endl;
	// 	cout << "5-Verify Document" << endl;
	// 	cout << "Type function number ->";
	// 	string in;
	// 	cin >> in;


	// 	if(in == "1"){
	// 		createKeysAndCertificate();
	// 	}
	// 	else if(in == "2"){

	// 	}
	// 	else if(in == "3"){

	// 	}
	// 	else if(in == "4"){
	// 		signDocument();
	// 	}
	// 	else if(in == "5"){
	// 		signDocument();
	// 	}
	// 	else{
	// 		cout << "Type function number ->";
	// 	}
	// }

	return 0;
}
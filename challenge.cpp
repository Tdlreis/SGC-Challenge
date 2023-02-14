#include <stdio.h>
#include <iostream>
#include <string>
#include <fstream> 
#include <libcryptosec/MessageDigest.h>
#include <libcryptosec/RSAKeyPair.h>
#include <libcryptosec/certificate/CertificateBuilder.h>
#include <libcryptosec/Pkcs12Builder.h>
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
}

void signDocument(){
	MessageDigest::loadMessageDigestAlgorithms();
	SymmetricCipher::loadSymmetricCiphersAlgorithms();

	ifstream file("CURRICULO_ENGENHARIA_DE_COMPUTAÇÃO_[CAMPUS_ARARANGUÁ]_20201.pdf.PDF", ios::binary);

	// Get the length of the file
    file.seekg(0, file.end);
    int length = file.tellg();
    file.seekg(0, file.beg);

    // Read the contents of the file into a buffer
    unsigned char* buffer = new unsigned char[length];
    file.read ((char*)buffer, length);
	file.close();

	// string pdf = buffer;


	MessageDigest teste(MessageDigest::SHA256);
	ByteArray b(buffer, length);
	delete[] buffer;
	ByteArray hex = teste.doFinal(b);


	cout << hex.toHex() << endl;
}

int main(int argc, char **argv) {
	MessageDigest::loadMessageDigestAlgorithms();
	SymmetricCipher::loadSymmetricCiphersAlgorithms();

	struct stat st;
	if (stat("./certificates", &st) == -1) {
		mkdir("./certificates", 0700);
	}

	signDocument();

	// while (true)
	// {
	// 	cout << "Functions: " << endl;
	// 	cout << "1-Create Certificate" << endl;
	// 	cout << "2-Import p12 file" << endl;
	// 	cout << "3-Include Document" << endl;
	// 	cout << "4-Sign Document" << endl;
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
	// 	else{
	// 		cout << "Type function number ->";
	// 	}
	// }

	return 0;
}
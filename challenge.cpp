#include <stdio.h>
#include <iostream>
#include <string>
#include <fstream>
#include <libcryptosec/MessageDigest.h>
#include <libcryptosec/RSAKeyPair.h>
#include <libcryptosec/certificate/CertificateBuilder.h>
#include <libcryptosec/certificate/CertificateRequestFactory.h>
#include <functional>




int main(int argc, char **argv) {
	// printf("Hello There!\n");
	
	// MessageDigest::loadMessageDigestAlgorithms();

	// RSAKeyPair key_pair(2048);
	// RSAPublicKey *pubKey = (RSAPublicKey*) key_pair.getPublicKey();
	// RSAPrivateKey *privKey = (RSAPrivateKey*) key_pair.getPrivateKey();


	// std::ofstream public_key_file("public_key.pem");
	// public_key_file << pubKey->getPemEncoded();
	// public_key_file.close();

	// std::ofstream private_key_file("private_key.pem");
	// private_key_file << privKey->getPemEncoded();
	// private_key_file.close();
	

	// CertificateBuilder cert = CertificateBuilder();
	// cert.setVersion(1);
	// cert.setSerialNumber(0);
	
	// RDNSequence rdnSubject;
	// rdnSubject.addEntry(RDNSequence::COUNTRY, "CO");
	// rdnSubject.addEntry(RDNSequence::ORGANIZATION, "organization");
	// rdnSubject.addEntry(RDNSequence::ORGANIZATION_UNIT, "oUnit");
	// rdnSubject.addEntry(RDNSequence::COMMON_NAME, "common_name");
	
	// cert.setSubject(rdnSubject);
	
	// cert.setPublicKey(*pubKey);

	// std::ofstream certificate_file("certificate_file.pem");
	// certificate_file << cert.getPemEncoded();
	// certificate_file.close();

	// ifstream inFile;
	// inFile.open("certificate_file.pem");
	// std::string pem((istreambuf_iterator<char>(inFile)), istreambuf_iterator<char>());
	// inFile.close();

	// X509 *teste2 =  cert.getX509();

	// Certificate newCert(teste2);

	// std::cout << newCert.getPublicKey()->getPemEncoded() << std::endl;
	// for (size_t i = 0; i < newCert.getSubject().getEntries().size(); i++)
	// {
	// 	std::cout << i << newCert.getSubject().getEntries().at(i).first.getName() << std::endl;
	// 	std::cout << newCert.getSubject().getEntries().at(i).second << std::endl;
	// }

	// if(newCert.getPublicKey() == cert.getPublicKey()){
	// 	std::cout << "Yey 1" << std::endl;
	// }
	// else{
	// 	std::cout << "KillMe 2" << std::endl;
	// }

	// if(cert.verify(*pubKey)){
	// 	std::cout << "Yey" << std::endl;
	// }
	// else{
	// 	std::cout << "KillMe" << std::endl;
	// }
	// // std::cout << << std::endl;
	// // std::cout << << std::endl;
	// // std::cout << << std::endl;



	// return 0;
	MessageDigest::loadMessageDigestAlgorithms();

	CertificateBuilder *certBuilder = new CertificateBuilder();

	RSAKeyPair key_pair(2048);

	RSAPublicKey *pubKey = (RSAPublicKey*) key_pair.getPublicKey();
	RSAPrivateKey *privKey = (RSAPrivateKey*) key_pair.getPrivateKey();

	certBuilder->setPublicKey(*pubKey);
	// certBuilder->includeEcdsaParameters();

	Certificate *cert = certBuilder->sign(*privKey, MessageDigest::SHA1);
	std::string pem = cert->getPemEncoded();

	std::ofstream certificate_file("certificate_file.pem");
	certificate_file << cert->getPemEncoded();
	certificate_file.close();

	if(pem.size() > 0){
		std::cout << "Pem Criado" << std::endl;
	}
	if(cert->verify(*pubKey)){
		std::cout << "Chave correta" << std::endl;
	}
	

}

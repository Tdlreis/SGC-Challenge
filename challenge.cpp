#include <stdio.h>
#include <iostream>
#include <string>
#include <fstream> 
#include <vector>
#include <sstream>
#include <algorithm>

#include <libcryptosec/MessageDigest.h>
#include <libcryptosec/RSAKeyPair.h>
#include <libcryptosec/certificate/CertificateBuilder.h>
#include <libcryptosec/Pkcs12Builder.h>
#include <libcryptosec/Pkcs12Factory.h>
#include <libcryptosec/Signer.h>
#include <libcryptosec/Pkcs7SignedDataBuilder.h>
#include <libcryptosec/AsymmetricCipher.h>

#include <sys/stat.h>

string pemPub = "-----BEGIN PUBLIC KEY-----" "\n"
				"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxA3ipLf2DHVxiJ2zVnvR" "\n"
				"XsrVDKNjjp9orDsIzXSxi1Q4SoKjx/+s6C+2elHM7KEutoWINn8U/0t9ZvTk6S3G" "\n"
				"MPLpdpLefWuwvT2lxP5sNSLYcsQdJ34A8T79HLudzPkWj/psru5pcWZaD1YNeNZM" "\n"
				"0ehiBweqPcOZ6MNu5mkcF156zgnJkTAdlwUjf5yBIeIQMg+MiumGiYfwa83ja0jK" "\n"
				"f5misoLF/fuCman9nvX4mjyRuxQq8Gs/DYC+B3ywJrEVsG5p1tsTy0RmLgccILW/" "\n"
				"wvm4RFXDrv2akLLxwQPNk3FHiUKCQH6cIf+V9WsdxUh39noVs6RnMkAEOshQRbQ+" "\n"
				"KwIDAQAB" "\n"
				"-----END PUBLIC KEY-----" "\n";
RSAPublicKey sysPubKey(pemPub);
string pemPriv = "-----BEGIN RSA PRIVATE KEY-----" "\n"
				"MIIEpAIBAAKCAQEArvD+/OxAsAls+rBzeMhwiuWl3jt1M6CHd6W4vFZ4spHIrIPG" "\n"
				"hvLUNhma18um5Kf0YHO6JEjWjRTrxiCy8UEOJyiavf9YE6MG9wNHW5wZiC0tUb1u" "\n"
				"D6I045O8H3rMSrwiVlrankuQWayTAOq3x0sggkVGKbicFD+T2C3iQ274QDWeElut" "\n"
				"UfqqFjJhwz/atpmo82ZF6U0iIpd2evXX/BNJOZYRuF0uXA6PwqoSbhaXib0RdGEn" "\n"
				"bVuIhHCMLlV4WdicqGlcip/77g1u8OyRdedNSSNCGWMC9+VH6Nf82TbkkPHFO0K+" "\n"
				"53mJVq4GB7OHKDPM5zIEEuFMf8h2Ip1Yl1svNQIDAQABAoIBAHmcQkWkHhvBkaZ7" "\n"
				"Puo5vDJyDen8vy6Sa1l7NH6IRgMsYKm8OSfaajbpecCFa5EMSE88Y6uRjsQoRPZI" "\n"
				"CNy48pO6IEfv11RfQho4h0RhsUX+0cA+xOHNSqLhMidX/+f7/Iq3Qb5EnSYZV1+N" "\n"
				"yw+ZZBHrAilCkg1pXOcsjlt+KsjG1phfgAzNmcAhOOho4EhpvZbw1QITVRBqXqSI" "\n"
				"pfpDMMBGesX77LBha2fpgGBDArlG8aSmOik8asZB7iiRDJFZE1lydhzAc5MWAyJh" "\n"
				"V8oBHbokuGFlCZHq/CDGsrb576iLCir7sLPzTybsjjbBaoukYb6tb1KZtxIKC5pq" "\n"
				"llBdnwkCgYEA2+iYrX/jOCDS7/b2ySs9ekSuTbgywazcXPqm3CeyktHfARc1gRHt" "\n"
				"FCCwz/ATlss6ebMBCNT5prEs7lvHA62FKlJk9QZp/tJ3Zuz0AA4XAtlum1MlZ9Ec" "\n"
				"fBtQs6efi/kxB2HA3KnbB/9kdZVCdHW0nPCRPK6AeCKCtrHtczO18AcCgYEAy6cd" "\n"
				"UfMIijZnc6HFjXl1B84SSwCsvVXrBolzCKAC7BU0+W5JNWV5J7JarDmBeXz4Mpyj" "\n"
				"RpiGc69XmJgFHam+Pc3/6VX77d79pfglPWEnyIv9gdgir0NN6joCH+2Vdzb8dWU5" "\n"
				"Zc+YToIeXlx74IjDa1R8Fd6rPbE0uT7GtLi1n+MCgYEAzcufTga3iihVntG8Y8h+" "\n"
				"cPTjNcJiZZMyaiT7kF3qJLIZAvlITfCLsGFjdkUS3/RyVb+qASzmMRPvm2TyGsQB" "\n"
				"MfkHl7IX8avep8iqE38cE8ONWfh2sfAkuxQI8we0LJbYRjM5/IdMffCIf+1d0oTw" "\n"
				"sEoFcQdRHJwXPYfHUh8bbXMCgYEApxTMMVe7QemwpmWqto9XPLgMugwrrIq47/wE" "\n"
				"rKbavuYHOD0LQwulgrQJQBNN7mZhGuT38AtjA7Zvn3nZeKSyt/IyazVoI5g3cdtM" "\n"
				"cjcrdJWlvsmcaz5Exk4hQCCj59Ls/UO2+5h91KtcTv6Bg42xBnWh+C9fPpYMM48V" "\n"
				"Z1/DYxECgYBFEKeIeYCiurwPYeI2z6Rh2joxyg5HFuV7yN/LsH8niqmTaAaKJ2BA" "\n"
				"pv73f8LgIIAtYAkQsjoRBIVcVxvXBbrbY4ziqTbYdlLTyRK9K7zWP8g2vX7b5F/v" "\n"
				"TXf2csdG9XxDuUJCI9jWY+l0soZAdkkYhGxCnXZt57h8rjWgXsbbPQ==" "\n"
				"-----END RSA PRIVATE KEY-----" "\n";
RSAPrivateKey sysPrivKey(pemPriv);


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
	setenv("TZ", "America/Sao_Paulo", 1);
	struct tm* t = localtime(&now);

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

string getFileName(string path){
	int pos = path.find_last_of("/");
	string fileName = path.substr(pos+1);
	pos = fileName.find_last_of(".");
	fileName.erase(pos, fileName.size());
	return fileName;
}

ByteArray fileReader(string path){
	ifstream file(path.c_str(), ios::binary);
	if(!file){
		throw runtime_error("File not found");
	}

	ostringstream buffer;
    buffer << file.rdbuf();
	file.close();

	return ByteArray(&buffer);
}

// void fileWriter(ByteArray out, string name){
// 	ofstream outputFile(string(name + ".bin").c_str(), ios::binary);
// 	for (size_t i = 0; i <out.size(); i++)
// 	{
// 		outputFile << out.at(i);
// 	}
// 	outputFile.close();
// }

void creatingMemoryFile(ByteArray out, string name){
	MessageDigest::loadMessageDigestAlgorithms();
	SymmetricCipher::loadSymmetricCiphersAlgorithms();

	AsymmetricCipher protectedMemory;
	ByteArray encryptedOut = protectedMemory.encrypt(sysPubKey, out, AsymmetricCipher::PKCS1_OAEP);
	// fileWriter(encryptedOut, name);

	ofstream outputFile(string("./documents/inprocess" + name + ".bin").c_str(), ios::binary);
	for (size_t i = 0; i <out.size(); i++)
	{
		outputFile << out.at(i);
	}
	outputFile.close();
}

void upgradeMemoryFile(string name){
	ifstream inprocessFile(string("./documents/inprocess"+name+".bin").c_str(), ios::binary);
    ofstream finalFile(string("./documents/final"+name+".bin").c_str(), ios::binary);

	finalFile << inprocessFile.rdbuf();
	inprocessFile.close();
    finalFile.close();

    remove(string("./documents/inprocess"+name+".bin").c_str());
}

ByteArray openMemoryFile(string name, int place){
	ByteArray fileData;
	if(place == 1){
		fileData = fileReader(string("./documents/inprocess"+name+".bin"));
	}
	else if(place == 2){
		fileData = fileReader(string("./documents/final"+name+".bin"));
	}
	AsymmetricCipher protectedMemory;
	ByteArray decryptedData = protectedMemory.decrypt(sysPrivKey, fileData, AsymmetricCipher::PKCS1_OAEP);
	return decryptedData;
}

string lowerCase(string word){
	for (size_t i = 0; i < word.size(); i++)
	{
		word.at(i) = tolower(word.at(i));
	}
	return word;
}

void includeDocument(){
	string in, path;
	ostringstream fileBuilder;

	system("clear");	

	//Crating PDF hash to inser in memory file
	MessageDigest hashCreator(MessageDigest::SHA256);
	ByteArray pdf;

	while(true){
		cout << "Type ESC to quit" << endl;
		cout << "Provide PDF file path: ";
		getline(cin, in); 
		if(lowerCase(in) == "esc" || lowerCase(in) == "quit" || in.find(27) != string::npos){
			return;
		}
		try
		{	
			pdf = fileReader(in);
			path = in;
			break;		
		}
		catch(runtime_error)
		{
			cout << "File not Found." << endl;
		}
	}

	ByteArray hash = hashCreator.doFinal(pdf);

	fileBuilder << "Hash:" << endl << hash.toString() << endl;

	vector<string> names;
	pair<vector<string>, vector<int> > titleCount;	
	int freeSigners = 0;
	bool approval = false;


	while (true)
	{
		system("clear");
		if (!names.empty())
		{
			cout << "Names already on the list: " << endl;
			for (size_t i = 0; i < names.size(); i++)
			{
				cout << "\t" << names.at(i) << endl;
			}
		}
		if(!titleCount.first.empty()){
			cout << "Titles already on the list: " << endl;
			for (size_t i = 0; i < titleCount.first.size(); i++)
			{
				cout << "\t" << titleCount.second.at(i) << " of " << titleCount.first.at(i) << endl;
			}
		}
		if (freeSigners > 0)
		{
			cout << "There are " << freeSigners << " signature fields that anyone can sign" << endl;
		}
		if (!names.empty() || !titleCount.first.empty() || freeSigners > 0)
		{
			cout << endl;
		}
		
		
		cout << "Type ESC to quit" << endl;
		cout << "Specifi Signer by" << endl << "1-Full Name" << endl <<"2-Title" << endl << "3-Not Specific" << endl << "4-Finish and Save" << endl << "->";
		getline(cin, in);
		if(lowerCase(in) == "esc" || lowerCase(in) == "quit" || in.find(27) != string::npos){
			return;
		}
		if (in == "1")
		{
			while (true)
			{
				cout << "Full Name: ";
				getline(cin, in);
				if(!in.empty()){
					string name = in;
					if(find(names.begin(), names.end(), name) != names.end() && !names.empty()){
						cout << "Name already on the list" << endl << "Press enter to continue" << endl;
						getline(cin, in);
					}
					else{
						while (true)
						{
							cout << "You typed: " << name << endl << "Are you shure (y or n)? ";
							getline(cin, in);
							if(lowerCase(in) == "y" || lowerCase(in) == "yes"){
								names.push_back(name);
								break;
							}
							else if(lowerCase(in) == "n" || lowerCase(in) == "no"){
								cout << "Type the correct name: ";
								getline(cin, name);
								if(find(names.begin(), names.end(), name) != names.end() && !names.empty()){
									cout << "Name already on the list" << endl << "Press enter to continue" << endl;
									getline(cin, in);
									break;
								}
							}
							else{
								cout << "Not an Option. The name is correct (y or n)?" << endl;
							}
						}
					}
					break;									
				}
				else{
					cout << "Please type the person's Full Name" << endl;
				}
			}			
		}
		else if(in == "2"){
			while (true)
			{
				cout << "Job Title: ";
				getline(cin, in);
				if(!in.empty()){
					string title = in;
					while (true)
					{
						cout << "You typed: " << title << endl << "Are you shure (y or n)? ";
						getline(cin, in);
						if(lowerCase(in) == "y" || lowerCase(in) == "yes"){
							while (true)
							{
								cout << "How many of this title has to sign de document?" << endl << "-> ";
								getline(cin, in);

								istringstream converter(in);
								int number;
								converter >> number;

								if(converter.fail()){
									cout << "Not a number" << endl;			
								}
								else if(number <= 0){
									cout << "Plese type a number bigger than 0" << endl;
								}
								else{
									while (true)
									{
										cout << number << " " << title << " are needed to sign this document (y or n)? ";
										getline(cin, in);
										if(lowerCase(in) == "y" || lowerCase(in) == "yes"){
											titleCount.first.push_back(title);
											titleCount.second.push_back(number);
											break;
										}
										else if(lowerCase(in) == "n" || lowerCase(in) == "no"){
											while (true)
											{
												cout << "Type the correct quantity: ";
												getline(cin, in);
												istringstream converterCorrection(in);
												int correctNumber;
												converterCorrection >> correctNumber;					
												if(converterCorrection.fail()){
													cout << "Not a number" << endl;			
												}
												else{
													number = correctNumber;
													break;
												}											
											}											
										}
										else{
											cout << "Not an Option. The name is correct (y or n)?" << endl;
										}
									}
									break;						
								}
							}
							break;												
						}
						else if(lowerCase(in) == "n" || lowerCase(in) == "no"){
							cout << "Type the correct job title: ";
							getline(cin, title);
						}
						else{
							cout << "Not an Option. The job title is correct (y or n)?" << endl;
						}						
					}					
					break;
				}
				else{
					cout << "Please type the person's Job Title" << endl;
				}
			}
		}
		else if(in == "3"){			
			while (true)
			{
				cout << "How many signature spaces could have anyone's signature?" << endl << "-> ";
				getline(cin, in);

				istringstream converterFree(in);
				int numberFree;
				converterFree >> numberFree;

				if(converterFree.fail()){
					cout << "Not a number" << endl;			
				}
				else if(numberFree <= 0){
					cout << "Plese type a number bigger than 0" << endl;
				}
				else{
					while (true)
					{
						cout << numberFree << " signature spaces are free for anyone to sign(y or n)? ";
						getline(cin, in);
						if(lowerCase(in) == "y" || lowerCase(in) == "yes"){
							freeSigners += numberFree;
							break;
						}
						else if(lowerCase(in) == "n" || lowerCase(in) == "no"){
							while (true)
							{
								cout << "Type the correct quantity: ";
								getline(cin, in);
								istringstream freeCorrection(in);
								int freeCorrectNumber;
								freeCorrection >> freeCorrectNumber;					
								if(freeCorrection.fail()){
									cout << "Not a number" << endl;			
								}
								else{
									numberFree = freeCorrectNumber;
									break;
								}											
							}											
						}
						else{
							cout << "Not an Option. The name is correct (y or n)?" << endl;
						}
					}
					break;						
				}
			}
		}
		else if(in == "4"){
			while (true)
			{
				cout << "Are you sure you want to finish (y or n)? ";
				getline(cin, in);
				if(lowerCase(in) == "y" || lowerCase(in) == "yes"){
					while(true){
						cout << "This document needs approval or only signatures: " << endl << "1-Approval" << endl << "2-Signatures" << endl << "-> ";
						getline(cin, in);
						if(in == "1"){
							approval = true;
							break;
						}  
						else if(in == "2"){
							approval = false;
							break;
						}
						else{
							cout << "Not a option, please chose a number" << endl;
						}
					}
					break;
				}
				else if(lowerCase(in) == "n" || lowerCase(in) == "no"){
					break;
				}
				else{
					cout << "Not an option (y or n)" << endl;
				}
			}
			if (lowerCase(in) == "y" || lowerCase(in) == "yes" || in == "1" || in == "2")
			{
				break;
			}
		}
		else{
			cout << "Not an option, please chose a number" << endl << "Press enter to continue" << endl;
			getline(cin, in);
		}				
	}

	fileBuilder << "nSigners:" << names.size()+titleCount.first.size()+freeSigners << endl;

	if (!names.empty())
	{
		fileBuilder << "nameSigners:" << names.size() << endl;
		for (size_t i = 0; i < names.size(); i++)
		{
			fileBuilder << names.at(i) << endl;
		}
	}

	if(!titleCount.first.empty()){
		fileBuilder << "titleSigners:" << titleCount.first.size() << endl;
		for (size_t i = 0; i < titleCount.first.size(); i++)
		{
			fileBuilder << titleCount.second.at(i) << "\t" << titleCount.first.at(i) << endl;
		}
	}

	if(freeSigners > 0){
		fileBuilder << "freeSigners:" << freeSigners << endl;
	}

	fileBuilder << "needApproval:" << approval << endl;

	ByteArray out(&fileBuilder);

	creatingMemoryFile(out, hash.toHex());
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
	if (stat("./documents/inprocess", &st) == -1) {
		mkdir("./documents/inprocess", 0700);
	}
	if (stat("./documents/final", &st) == -1) {
		mkdir("./documents/final", 0700);
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
	//
	// 	}
	// 	else if(in == "3"){
	//		 includeDocument();
	// 	}
	// 	else if(in == "4"){
	// 		signDocument();
	// 	}
	// 	else if(in == "5"){
	// 		
	// 	}
	// 	else{
	// 		cout << "Type function number ->";
	// 	}
	// }

	return 0;
}
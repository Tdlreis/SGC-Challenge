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
				"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnW/a1EB0LmwogOb59IabbQBdwIya/Ky6KmNfXoT3tbOlFPuCo9pt95obvI7+ydUtv3veLIIIDHNTpcjIIEIk38YFeYQkD+1Y7MVljZt0JqGFFNYuOrwKH024i8DtroKAwQKSmR3ZqbhkPH5GA7c+OM2fN2sbTTakS7FZh60NLhr4YAq5YE9d+CkDveXr2lvu9d1bR6X0NHTKNQZe9wN2Jy7ZUuj73Y/DCtjSuS/mYtLPacdYlYDfxv9x2Y8CcyQvT3r4DMFiJP03YcdmaSQA3EZ0HTuw8XsPexJiFtZdRnpuCTnBqZ/jH4oVBJGXJIDHtuICcdUrj9IQafiRljbfzQIDAQAB" "\n"
				"-----END PUBLIC KEY-----" "\n";
RSAPublicKey sysPubKey(pemPub);
string pemPriv = "-----BEGIN RSA PRIVATE KEY-----" "\n"
				"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCdb9rUQHQubCiA5vn0hpttAF3AjJr8rLoqY19ehPe1s6UU+4Kj2m33mhu8jv7J1S2/e94sgggMc1OlyMggQiTfxgV5hCQP7VjsxWWNm3QmoYUU1i46vAofTbiLwO2ugoDBApKZHdmpuGQ8fkYDtz44zZ83axtNNqRLsVmHrQ0uGvhgCrlgT134KQO95evaW+713VtHpfQ0dMo1Bl73A3YnLtlS6Pvdj8MK2NK5L+Zi0s9px1iVgN/G/3HZjwJzJC9PevgMwWIk/Tdhx2ZpJADcRnQdO7Dxew97EmIW1l1Gem4JOcGpn+MfihUEkZckgMe24gJx1SuP0hBp+JGWNt/NAgMBAAECggEALMENTeT8oe2xHeOLDo3tRPEjtYbC0C0xxrb092OJHyfwN6S/oGCJfida1yE3IJzvIk3N/I0CSLfIAYqwCSuEW/BowgBkV/q6mqQKmFSmkgy8Tg4Mmjm2DuwDGAdCCaejfjqC/e/UXkDCjce/k3LVx0P8jL5vxmVQEwxZTQ5OftpNYLCmn51JORTs0/GpDUqYryEtgkbX37N4KS3OVTgAiayJDmlYXO1lEdmGV5zykgZQeXX+7KZ9MJ1F5YFDTRwRtb+vMv5P2lFLTFB7YUvld9b9GUCKpKrvmOisu9LtlQ7JmNnAD8i8JbTKoxoXGt4rIGN8D6wzgtNGgUy4OGO0wQKBgQDY/jSEm91uVZ+q3EetNGyX+V6ZelHU74YOxJa8sWDiwD3fx21BQ860u/g55B/NKgsU7nIn7/95e8V9orSn74sJcOwiy3MD3yMYQm4Sg7sz349yNRQdCtQ9TJkFVoULDOUTT4UIi+QChGDANaL4F2jXGgMFfew5BqA4XzlS2AR25QKBgQC5vPDmr48/mqWgw4SeBuz6BD9DeOW4/8ujjEa/HVdN7kArYpx6O5Mh8OgDwFLEyDMRhajlhx4pitCNJN0JKRtZWMDyvAzIgwMvj/m4WRDfn7wwUlMcjhvPhJK7znnPp8+Ut/S+s5XXqw+aVzVGrnsm6SByAzbRE1a1DH02CxEOyQKBgQCe0L7jZ6iTPnvT89FKBZqNSGhicFJAROabHGsuw6wjiYw/ophmMhix0vmEdWCJKoJd2X8Xl+Ilqd8LavBKEVpzmIBbnwgZB1GKSeSCDIQRHUjBz/NepjRcgRll/ML3KYLntUWq0agZ54VgaGFUrt1+wX0Aof8oZZ8SYy9zYMMzuQKBgAndkEogfxJYy31bhTrDkWjCOv4BeOo3pABe3g8eptl70yq6xSb07R67Zgd0+rB7FcNTfyIZ6C86sVMd5yOqbEp1nWIHPQKVeuDW2+O/z1ahbGSAqut0XOPL3eNd1ziBaFQ05SoP7eCTtHN1OF41vFLXxSJpK0s1pMBfFnN9aP2JAoGBAKqDlBBZ9gsVp7wEmuMP/3LqeG1npdwkGjtIp0GeuEaKFB8HlCGYh0YldFtWih4xGYI8u5DEUxSBR1cXX9qXvxal7f9O6MzZjhC/QLSMw+vCUZ0wjhb6ojWIdvidxs8JjDH+R4m0pgFp9ZOaH5LHRo7Chr1ijEhn5HZ+Is5hQRJr" "\n"
				"-----END RSA PRIVATE KEY-----" "\n";
RSAPrivateKey sysPrivKey(pemPriv);

//Utility Functions
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

	ofstream debugFile(string("./documents/inprocess/" + name + ".txt").c_str());
	debugFile << out.toString();
	debugFile.close();

	AsymmetricCipher protectedMemory;
	ByteArray encryptedOut = protectedMemory.encrypt(sysPubKey, out, AsymmetricCipher::PKCS1_OAEP);
	// fileWriter(encryptedOut, name);	

	ofstream outputFile(string("./documents/inprocess/" + name + ".bin").c_str(), ios::binary);
	for (size_t i = 0; i <encryptedOut.size(); i++)
	{
		outputFile << encryptedOut.at(i);
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
		fileData = fileReader(string("./documents/inprocess/"+name+".bin"));
	}
	else if(place == 2){
		fileData = fileReader(string("./documents/final/"+name+".bin"));
	}
	AsymmetricCipher protectedMemory;
	ByteArray decryptedData = protectedMemory.decrypt(sysPrivKey, fileData, AsymmetricCipher::PKCS1_OAEP);
	return decryptedData;
}

string lowerCase(string word, int spaces = 0){
	for (size_t i = 0; i < word.size(); i++)
	{
		word.at(i) = tolower(word.at(i));
		if (word.at(i) == ' ' && spaces > 0)
		{	
			if(spaces == 1){
				word.at(i) = '_';
			}
			else if(spaces == 2){
				word.erase(i, 1);
				i--;
			}
		}
	}
	return word;
}

//Menu Functions
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

	//Creating PDF hash to insert in memory file
	MessageDigest hashCreator(MessageDigest::SHA256);
	ByteArray pdf;
	string in, path;

	while(true){
		cout << "Type ESC to quit" << endl;
		cout << "Provide original PDF file path: ";
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
			cout << "File not Found" << endl;
		}
	}

	ByteArray hash = hashCreator.doFinal(pdf);
	ByteArray memoryFile;
	try
	{	
		memoryFile = openMemoryFile(hash.toHex(), 1);
	}
	catch(runtime_error)
	{
		cout << "Document not registered"  << endl << "Press enter to continue" << endl;
		getline(cin, in);
		return;
	}

	ostringstream fileBuilder;
	fileBuilder << memoryFile.toString();

	
	while (true)
	{
		vector<string> names;
		pair<vector<string>, vector<int> > titleCount;
		int posStart, posTerm, posSeparator, posEnd, number, freeSigners;
		bool approval = false;

		posTerm = fileBuilder.str().find("nameSigners:");
		posSeparator = fileBuilder.str().find(":", posTerm+1);
		posEnd = fileBuilder.str().find("\n", posSeparator);
		number = atoi(fileBuilder.str().substr(posSeparator+1, posEnd-posSeparator-1).c_str());


		for (int i = 0; i < number; i++)
		{
			posStart = posEnd+1;
			posEnd = fileBuilder.str().find("\n", posStart);
			names.push_back(fileBuilder.str().substr(posStart, posEnd-posStart));
		}

		posTerm = fileBuilder.str().find("titleSigners:");
		posSeparator = fileBuilder.str().find(":", posTerm+1);
		posEnd = fileBuilder.str().find("\n", posSeparator);
		number = atoi(fileBuilder.str().substr(posSeparator+1, posEnd-posSeparator-1).c_str());

		for (int i = 0; i < number; i++)
		{
			posStart = posEnd+1;
			posEnd = fileBuilder.str().find("\t", posStart);
			titleCount.first.push_back(fileBuilder.str().substr(posStart, posEnd-posStart).c_str());

			posStart = posEnd+1;
			posEnd = fileBuilder.str().find("\n", posStart);
			titleCount.second.push_back(atoi(fileBuilder.str().substr(posStart, posEnd-posStart).c_str()));
		}

		posTerm = fileBuilder.str().find("freeSigners:");
		posSeparator = fileBuilder.str().find(":", posTerm+1);
		posEnd = fileBuilder.str().find("\n", posSeparator);
		freeSigners = atoi(fileBuilder.str().substr(posSeparator+1, posEnd-posSeparator-1).c_str());

		posTerm = fileBuilder.str().find("needApproval:");
		posSeparator = fileBuilder.str().find(":", posTerm+1);
		posEnd = fileBuilder.str().find("\n", posSeparator);
		number = atoi(fileBuilder.str().substr(posSeparator+1, posEnd-posSeparator-1).c_str());
		approval = (number != 0);


		system("clear");
		cout  << "This document needs to be sign by: " << endl;
		if (!names.empty())
		{
			for (size_t i = 0; i < names.size(); i++)
			{
				cout << "\t" << names.at(i) << endl;
			}
		}
		if(!titleCount.first.empty()){
			cout << "Anyone with the title: " << endl;
			for (size_t i = 0; i < titleCount.first.size(); i++)
			{
				cout << "\t" << titleCount.second.at(i) << " people with the title: " << titleCount.first.at(i) << endl;
			}
		}
		if (freeSigners > 0)
		{
			cout << "And " << freeSigners << " people in the organization" << endl;
		}
		if (!names.empty() || !titleCount.first.empty() || freeSigners > 0)
		{
			cout << endl;
		}

		cout << "Type ESC to quit" << endl;
		cout << "Type your full name: ";
		getline(cin, in);
		if(lowerCase(in) == "esc" || lowerCase(in) == "quit" || in.find(27) != string::npos){
			return;
		}
		
		string certificateName = lowerCase(in, 1);
		ByteArray certFile, signature;

		try
		{	
			certFile = fileReader(string("./certificates/" + certificateName + ".p12").c_str());
			Pkcs12 p12 = *Pkcs12Factory().fromDerEncoded(certFile);
			string name, title, password;
			ByteArray pubKeyDer;

			while (true)
			{
				cout << "Signer password: ";
				getline(cin, in);
				Signer signatureCretor;
				try{
					signature = signatureCretor.sign(*p12.getPrivKey(in), hash, MessageDigest::SHA256);
					name = p12.getCertificate(in)->getSubject().getEntries(RDNSequence::COMMON_NAME).at(0);
					title = p12.getCertificate(in)->getSubject().getEntries(RDNSequence::TITLE).at(0);
					pubKeyDer =  p12.getCertificate(in)->getPublicKey()->getDerEncoded();

					int category = 0;
					if(find(names.begin(), names.end(), name) != names.end() && !names.empty()){
						category = 1;
					}
					else if(find(titleCount.first.begin(), titleCount.first.end(), title) != titleCount.first.end() && !titleCount.first.empty()){
						category = 2;
					}
					else if(freeSigners > 0){
						category = 3;
					}
					else{
						cout << "You are can't sign this document" << endl;
						break;
					}
					if(approval){
						while (true)
						{
							cout << "Type ESC to quit" << endl;
							cout << endl<< "Do you: " << endl;
							cout << "1-Agree: " << endl;
							cout << "2-Disagree: " << endl;
							getline(cin, in);
							bool accept;
							if(lowerCase(in) == "esc" || lowerCase(in) == "quit" || in.find(27) != string::npos){
								cout << "Ok, think about it and come back" << endl << "Your signature was not finalized" << endl << "Press enter to continue" << endl;
								getline(cin, in);
								return;
							}
							if (in == "1")
							{
								cout << fileBuilder.str() << endl;
								accept = true;
								if(category == 1){
									string editor = fileBuilder.str();
									posTerm = editor.find("nameSigners:");
									posSeparator = editor.find(":", posTerm+1);
									posEnd = editor.find("\n", posSeparator);
									int editNumber = atoi(editor.substr(posSeparator+1, posEnd-posSeparator-1).c_str());
									editNumber--;
									stringstream intToString;
									intToString << editNumber;
									editor.replace(posSeparator+1, posEnd-posSeparator-1, intToString.str());
									int posStartName = editor.find(name);
									int posEndName = editor.find("\n", posStartName);							
									editor.erase(posStartName, posEndName-posStartName+1);
									fileBuilder.str("");
									fileBuilder << editor;
								}
								else if(category == 2){	
									string editor = fileBuilder.str();

									posTerm = editor.find("titleSigners:");
									posSeparator = editor.find(":", posTerm+1);
									posEnd = editor.find("\n", posSeparator);
									int editNumber = atoi(editor.substr(posSeparator+1, posEnd-posSeparator-1).c_str());
									editNumber--;
									stringstream intToString;
									intToString << editNumber;
									editor.replace(posSeparator+1, posEnd-posSeparator-1, intToString.str());

									int posStartTitle = editor.find(title);
									int posEndTitle = editor.find("\t", posStartTitle);

									posStart = posEndTitle+1;
									posEnd = editor.find("\n", posStart);
									int titleNumber = atoi(editor.substr(posStart, posEnd-posStart).c_str());
									titleNumber--;
									if(titleNumber == 0){
										editor.erase(posStartTitle-1, posEnd-posStartTitle+1);
									}
									else{
										intToString.str("");
										intToString << editNumber;
										editor.replace(posStart, posEnd-posStart, intToString.str());
									}
									fileBuilder.str("");
									fileBuilder << editor;
								}
								else{
									string editor = fileBuilder.str();
									posTerm = editor.find("freeSigners:");
									posSeparator = editor.find(":", posTerm+1);
									posEnd = editor.find("\n", posSeparator);
									freeSigners = atoi(editor.substr(posSeparator+1, posEnd-posSeparator-1).c_str());
									freeSigners--;
									stringstream intToString;
									intToString << freeSigners;
									editor.replace(posSeparator+1, posEnd-posSeparator-1, intToString.str());
									fileBuilder.str("");
									fileBuilder << editor;
								}
								fileBuilder << name << "\t" << title << "\t" << signature.toStream() << "\t" << accept << "\t" << pubKeyDer.toStream() << "\t" << "day" << endl;

								cout << fileBuilder.str() << endl;

								ByteArray out(&fileBuilder);
								creatingMemoryFile(out, hash.toHex());
								break;
							}
							else if(in == "2"){
								accept = false;
								if(category == 1){
									string editor = fileBuilder.str();
									posTerm = editor.find("nameSigners:");
									posSeparator = editor.find(":", posTerm+1);
									posEnd = editor.find("\n", posSeparator);
									int editNumber = atoi(editor.substr(posSeparator+1, posEnd-posSeparator-1).c_str());
									editNumber--;
									stringstream intToString;
									intToString << editNumber;
									editor.replace(posSeparator+1, posEnd-posSeparator-1, intToString.str());
									int posStartName = editor.find(name);
									int posEndName = editor.find("\n", posStartName);							
									editor.erase(posStartName, posEndName-posStartName+1);
									fileBuilder.str("");
									fileBuilder << editor;
								}
								else if(category == 2){	
									string editor = fileBuilder.str();
									int posStartTitle = editor.find(title);
									int posEndTitle = editor.find("\t", posStartTitle);

									posStart = posEndTitle+1;
									posEnd = editor.find("\n", posStart);
									int titleNumber = atoi(editor.substr(posStart, posEnd-posStart).c_str());
									titleNumber--;
									if(titleNumber == 0){
										editor.erase(posStartTitle, posEnd);
									}
									else{
										editor.replace(posStart, posEnd-posStart, string("" + titleNumber).c_str());
									}
									fileBuilder.str("");
									fileBuilder << editor;
								}
								else{
									string editor = fileBuilder.str();
									posTerm = editor.find("freeSigners:");
									posSeparator = editor.find(":", posTerm+1);
									posEnd = editor.find("\n", posSeparator);
									freeSigners = atoi(editor.substr(posSeparator+1, posEnd-posSeparator-1).c_str());
									freeSigners--;
									stringstream intToString;
									intToString << freeSigners;
									editor.replace(posSeparator+1, posEnd-posSeparator-1, intToString.str());
									fileBuilder.str("");
									fileBuilder << editor;
								}
								fileBuilder << name << "\t" << title << "\t" << signature.toString() << "\t" << accept << "\t" << pubKeyDer.toStream() << "\t" << "day" << endl;
								ByteArray out(&fileBuilder);
								creatingMemoryFile(out, hash.toHex());
								break;
							}
							else{
								cout << "Not an option, please choose a number" << endl;
							}
						}
					}
					else{
						if(category == 1){
									string editor = fileBuilder.str();
									posTerm = editor.find("nameSigners:");
									posSeparator = editor.find(":", posTerm+1);
									posEnd = editor.find("\n", posSeparator);
									int editNumber = atoi(editor.substr(posSeparator+1, posEnd-posSeparator-1).c_str());
									editNumber--;
									stringstream intToString;
									intToString << editNumber;
									editor.replace(posSeparator+1, posEnd-posSeparator-1, intToString.str());
									int posStartName = editor.find(name);
									int posEndName = editor.find("\n", posStartName);							
									editor.erase(posStartName, posEndName-posStartName+1);
									fileBuilder.str("");
									fileBuilder << editor;
								}
								else if(category == 2){	
									string editor = fileBuilder.str();
									int posStartTitle = editor.find(title);
									int posEndTitle = editor.find("\t", posStartTitle);

									posStart = posEndTitle+1;
									posEnd = editor.find("\n", posStart);
									int titleNumber = atoi(editor.substr(posStart, posEnd-posStart).c_str());
									titleNumber--;
									if(titleNumber == 0){
										editor.erase(posStartTitle, posEnd);
									}
									else{
										editor.replace(posStart, posEnd-posStart, string("" + titleNumber).c_str());
									}
									fileBuilder.str("");
									fileBuilder << editor;
								}
								else{
									string editor = fileBuilder.str();
									posTerm = editor.find("freeSigners:");
									posSeparator = editor.find(":", posTerm+1);
									posEnd = editor.find("\n", posSeparator);
									freeSigners = atoi(editor.substr(posSeparator+1, posEnd-posSeparator-1).c_str());
									freeSigners--;
									stringstream intToString;
									intToString << freeSigners;
									editor.replace(posSeparator+1, posEnd-posSeparator-1, intToString.str());
									fileBuilder.str("");
									fileBuilder << editor;
								}
						fileBuilder << name << "\t" << title << "\t" << signature.toString() << "\t" << "n/a" << "\t" << pubKeyDer.toStream() << "\t" << "day" << endl;

						ByteArray out(&fileBuilder);
						creatingMemoryFile(out, hash.toHex());
						break;
					}
					break;
				}
				catch(Pkcs12Exception){
					cout << "Incorrect Password" << endl << "Press enter to continue" << endl;
					getline(cin, in);					
				}		
			}
			
		}
		catch(runtime_error)
		{
			cout << "Certificate not found!" << endl << "Please check your speel or create certificate" << endl << "Press enter to continue" << endl;
			getline(cin, in);;
		}
	}
}

void includeDocument(){
	string in, path;
	ostringstream fileBuilder;

	system("clear");	

	//Creating PDF hash to insert in memory file
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
		cout << "Specify Signer by" << endl << "1-Full Name" << endl <<"2-Title" << endl << "3-Not Specific" << endl << "4-Finish and Save" << endl << "->";
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
							cout << "You typed: " << name << endl << "Are you sure (y or n)? ";
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
						cout << "You typed: " << title << endl << "Are you sure (y or n)? ";
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
									cout << "Please type a number bigger than 0" << endl;
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
					cout << "Please type a number bigger than 0" << endl;
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

	fileBuilder << "nameSigners:" << names.size() << endl;
	if(!names.empty()){
		for (size_t i = 0; i < names.size(); i++)
		{
			fileBuilder << names.at(i) << endl;
		}
	}

	fileBuilder << "titleSigners:" << titleCount.first.size() << endl;
	if(!titleCount.first.empty()){
		for (size_t i = 0; i < titleCount.first.size(); i++)
		{
			fileBuilder << titleCount.first.at(i) << "\t" << titleCount.second.at(i) << endl;
		}
	}

	fileBuilder << "freeSigners:" << freeSigners << endl;

	fileBuilder << "needApproval:" << approval << endl;

	fileBuilder << "signatures:" << endl;

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

	while (true)
	{
		system("clear");
		cout << "Functions: " << endl;
		cout << "1-Create Certificate" << endl;
		cout << "2-Include Document" << endl;
		cout << "3-Sign Document" << endl;
		cout << "4-Verify Document" << endl;
		cout << "Type function number ->";
		string in;
		cin >> in;

		cin.ignore();


		if(in == "1"){
			createKeysAndCertificate();
		}
		else if(in == "2"){
			 includeDocument();
		}
		else if(in == "3"){
			signDocument();
		}
		else if(in == "4"){
			
		}
		else{
			cout << "Type function number ->";
		}
	}

	return 0;
}
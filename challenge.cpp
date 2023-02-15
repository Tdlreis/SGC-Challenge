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

void creatingMemoryFile(ByteArray out){
	return;
}

void updateMemoryFile(){

}

void openMemoryFile(){

}

ByteArray fileReader(string path){
	ifstream file(path.c_str(), ios::binary);
	if(!file){
		throw runtime_error("File not found");
	}

	std::ostringstream buffer;
    buffer << file.rdbuf();
	file.close();

	return ByteArray(&buffer);
}

string lowerCase(string word){
	for (size_t i = 0; i < word.size(); i++)
	{
		word.at(i) = tolower(word.at(i));
	}
	return word;
}

void includeDocument(){
	string in;
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
			break;		
		}
		catch(runtime_error)
		{
			cout << "File not Found." << endl;
		}
	}

	ByteArray hash = hashCreator.doFinal(pdf);

	fileBuilder << "Hash:" << endl << hash.toString() << endl;

	int count;
	while (true)
	{
		cout << endl << "Type ESC to quit" << endl;
		cout << "How many signers:";
		getline(cin, in);
		if(lowerCase(in) == "esc" || lowerCase(in) == "quit" || in.find(27) != string::npos){
			return;
		}

		istringstream converter(in);
		converter >> count;

		if(converter.fail()){
			cout << "Not a number" << endl;			
		}
		else{
			break;
		}
	}
	
	vector<string> names;
	pair<vector<string>, vector<int> > titleCount;
	int freeSigners = 0;


	for (int i = 0; i < count; i++)
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
		cout << "Slots Remaining: " << count-i << endl;
		cout << "Type ESC to quit" << endl;
		cout << "Specifi Signer by" << endl << "1-Full Name" << endl <<"2-Title" << endl << "3-Not Specific" << endl << "->";
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
						i--;
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
									i--;
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
									cout << "Plese type a number biggeur than 0" << endl;
								}
								else{
									while (true)
									{
										cout << number << " " << title << " are needed to sign this document (y or n)? ";
										getline(cin, in);
										if(lowerCase(in) == "y" || lowerCase(in) == "yes"){
											titleCount.first.push_back(title);
											titleCount.second.push_back(number);
											i += number-1;
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
				cout << "All the remaining " << count-i << " signers will be free to anyone to sign" << endl << "Are you shure (y or n)? ";
				getline(cin, in);
				if(lowerCase(in) == "y" || lowerCase(in) == "yes"){
					freeSigners = count-1;
					break;
				}
				else if(lowerCase(in) == "n" || lowerCase(in) == "no"){
					i--;
					break;
				}
				else{
					cout << "Not an Option. The rest are free signers (y or n)?" << endl;
				}						
			}
			if(lowerCase(in) == "y" || lowerCase(in) == "yes"){
					break;
			}
		}
		else{
			cout << "Not an option, please chose a number" << endl << "Press enter to continue" << endl;
			getline(cin, in);
			i--;
		}				
	}

	fileBuilder << "nSigners:" << count << endl;

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

	ByteArray out(&fileBuilder);
		
	creatingMemoryFile(out);
	cout << out.toString() << endl;
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


	includeDocument();

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
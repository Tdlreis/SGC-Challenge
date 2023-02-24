#include <stdio.h>
#include <iostream>
#include <string>
#include <fstream> 
#include <vector>
#include <sstream>
#include <algorithm>
#include <ctime>

#include <libcryptosec/MessageDigest.h>
#include <libcryptosec/RSAKeyPair.h>
#include <libcryptosec/certificate/CertificateBuilder.h>
#include <libcryptosec/Pkcs12Builder.h>
#include <libcryptosec/Pkcs12Factory.h>
#include <libcryptosec/Signer.h>
#include <libcryptosec/SymmetricKey.h>

#include <sys/stat.h>

#include <openssl/evp.h>

//Define AES_256 key for encryption of internal data
string sysKeyString = "q3t6w9z$C&F)J@NcQfTjWnZr4u7x!A%D";
ByteArray sysKeyBa(sysKeyString);
SymmetricKey sysKey = SymmetricKey(sysKeyBa, SymmetricKey::AES_256);


//Utility Functions
//Gets file name without its extention 
string getFileName(string path){
	int pos = path.find_last_of("/");
	string fileName = path.substr(pos+1);
	pos = fileName.find_last_of(".");
	fileName.erase(pos, fileName.size());
	return fileName;
}

//Read file and return Byte Array
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

//Creates system encrypted memory file
void creatingMemoryFile(ByteArray out, string name){
	// Load message digest and symmetric cipher algorithms
	MessageDigest::loadMessageDigestAlgorithms();
	SymmetricCipher::loadSymmetricCiphersAlgorithms();

	// Generate encryption key and initialization vector using sysKey
    unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
    EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), NULL, reinterpret_cast<const unsigned char*>(sysKey.getEncoded().toString().c_str()), sysKey.getEncoded().toString().size(), 1, key, iv);

	// Initialize cipher context with the encryption key and initialization vector
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

	// Encrypt the data in the ByteArray object using the cipher context and write the encrypted data to ostringstream variable
    int out_len = out.toString().size();
    unsigned char outbuf[out_len];
    EVP_EncryptUpdate(ctx, outbuf, &out_len, reinterpret_cast<const unsigned char*>(out.toString().c_str()), out.toString().size());
	ostringstream outStream;
    outStream.write(reinterpret_cast<const char*>(outbuf), out_len);

	// Write any remaining data to the binary file
    EVP_EncryptFinal_ex(ctx, outbuf, &out_len);
    outStream.write(reinterpret_cast<const char*>(outbuf), out_len);

	// Free the cipher context
    EVP_CIPHER_CTX_free(ctx);

	// Write the encrypted data to a binary file in the "inprocess" directory
	ofstream outputFile(string("./documents/inprocess/" + name + ".bin").c_str(), ios::binary);
	for (size_t i = 0; i < outStream.str().size(); i++)
	{
		outputFile << outStream.str().c_str()[i];
	}
	outputFile.close();
}

//Changes directory of the internal file when document is fully signed
void upgradeMemoryFile(string name){
	ifstream inprocessFile(string("./documents/inprocess/"+name+".bin").c_str(), ios::binary);
    ofstream finalFile(string("./documents/final/"+name+".bin").c_str(), ios::binary);

	finalFile << inprocessFile.rdbuf();
	inprocessFile.close();
    finalFile.close();

    remove(string("./documents/inprocess/"+name+".bin").c_str());
}

//Opens and decrypt memory file and returns a ByteArray
ByteArray openMemoryFile(string name, int place){
	string path;

	// Determine the file path based on the location flag
	if(place == 1){
		path = "./documents/inprocess/"+name+".bin";
	}
	else if(place == 2){
		path = "./documents/final/"+name+".bin";
	}

	// Open the file at the given path in binary mode
	ifstream file(path.c_str(), ios::binary);
	// Throw an exception if the file can't be opened
	if(!file){
		throw runtime_error("File not found");
	}

	// Read the contents of the file into a stringstream
	ostringstream fileData;
    fileData << file.rdbuf();
	file.close();

	// Generate encryption key and initialization vector using sysKey
    unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
	EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), NULL, reinterpret_cast<const unsigned char*>(sysKey.getEncoded().toString().c_str()), sysKey.getEncoded().toString().size(), 1, key, iv);

	// Initialize cipher context with the encryption key and initialization vector
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

	// Decrypt the data from the stringstream and store it in out_buf
    unsigned char out_buf[fileData.str().size() + EVP_MAX_BLOCK_LENGTH];
    int out_len;
    
    if (!EVP_DecryptUpdate(ctx, out_buf, &out_len, reinterpret_cast<const unsigned char*>(fileData.str().c_str()),  fileData.str().size())) {
        EVP_CIPHER_CTX_cleanup(ctx);
		// If an error occurs during decryption, throw an exception
        throw runtime_error("Error Decrypting");
    }

	// Write the decrypted data to an output stringstream
	ostringstream out;
	out.write(reinterpret_cast<const char*>(out_buf), out_len);

	// Finalize the decryption and write any remaining data to the output stringstream
    if (EVP_DecryptFinal_ex(ctx, out_buf, &out_len)) {
    	out.write(reinterpret_cast<const char*>(out_buf), out_len);
    }

	// Clean up the encryption context
    EVP_CIPHER_CTX_cleanup(ctx);

	// Return the decrypted data as a ByteArray object
	return ByteArray(&out);
}

//Transform the string into lowercase and remove/replace spaces
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

//Converts hexadecimal to characters
string hexToChar(const string &hex) {
    string result;
    for (size_t i = 0; i < hex.length(); i += 2) {
        string hexByte = hex.substr(i, 2);
        char c = (char) (int) strtol(hexByte.c_str(), NULL, 16);
        result += c;
    }
    return result;
}

//Compare strings to function sort
bool comparePairs(const pair<string, int>& a, const pair<string, int>& b) {
	return a.first < b.first;
}

//Menu Functions
//Certificate creation process
void createKeysAndCertificate(){
	// Load message digest and symmetric cipher algorithms	
	MessageDigest::loadMessageDigestAlgorithms();
	SymmetricCipher::loadSymmetricCiphersAlgorithms();

	// Generate RSA key pair
	RSAKeyPair key_pair(2048); 
	RSAPublicKey *pubKey = (RSAPublicKey*) key_pair.getPublicKey();
	RSAPrivateKey *privKey = (RSAPrivateKey*) key_pair.getPrivateKey();
	
	// Create a certificate builder
	CertificateBuilder certBuilder = CertificateBuilder();

	// Set the version number and serial number of the certificate
	certBuilder.setVersion(1);
	certBuilder.setSerialNumber(0);

	string in = "";

	// Set the subject of the certificate
	RDNSequence rdnSubject;
	system("clear"); // Clear the console screen
	cout << "Type ESC to quit" << endl;
	cout << "Certificate Creation: " << endl;
	cout << "Full Name: ";
	getline(cin, in);
	// If the input is "esc" or "quit" or contains the ESC key, return
	if(lowerCase(in) == "esc" || lowerCase(in) == "quit" || in.find(27) != string::npos){
		return;
	}
	string name = in;
	in.clear();
	rdnSubject.addEntry(RDNSequence::COMMON_NAME, name);
	cout << "Title: ";
	getline(cin, in);
	// If the input is "esc" or "quit" or contains the ESC key, return
	if(lowerCase(in) == "esc" || lowerCase(in) == "quit" || in.find(27) != string::npos){
		return;
	}

	rdnSubject.addEntry(RDNSequence::TITLE, in);
	in.clear();	

	// Set the subject of the certificate
	certBuilder.setSubject(rdnSubject);

	// Set the public key of the certificate
	certBuilder.setPublicKey(*pubKey);

	time_t now = time(0);
	tm* brasilia_time = gmtime(&now);
	brasilia_time->tm_hour -= 3;
	time_t brasilia_time_t = mktime(brasilia_time);
	
	// Set the start and end dates of the certificate
	DateTime dateTimeNow(brasilia_time_t);
	DateTime dateTimeExpire(brasilia_time_t+60*60*24*365);
	certBuilder.setNotBefore(dateTimeNow);
	certBuilder.setNotAfter(dateTimeExpire);

	// Sign the certificate with the private key
	Certificate *cert = certBuilder.sign(*privKey, MessageDigest::SHA256);

	// Get name in lower case, without spaces
	name = lowerCase(name, 1);

	// Create a PKCS#12 builder
	Pkcs12Builder pkcs12Builder = Pkcs12Builder();

	// Set the private key and certificate of the PKCS#12 builder
	pkcs12Builder.setKeyAndCertificate(privKey, cert, name);
	pkcs12Builder.addAdditionalCert(cert);

	cout << "Password: ";
	getline(cin, in);
	// If the input is "esc" or "quit" or contains the ESC key, return
	if(lowerCase(in) == "esc" || lowerCase(in) == "quit" || in.find(27) != string::npos){
		return;
	}
	
	// Create a PKCS12 object with the entered password
	Pkcs12 *pkcs12 = pkcs12Builder.doFinal(in);
	in.clear();

	// Write the PKCS12 object to a file
	ofstream pkcs12_file;
	pkcs12_file.open(string("./certificates/"+name+".p12").c_str());
	for (size_t i = 0; i < pkcs12->getDerEncoded().size(); i++)
	{
		pkcs12_file << pkcs12->getDerEncoded().at(i);
	}
	pkcs12_file.close();

	// Inform the user that the certificate was created successfully
	cout << "Certificate created" << endl << "Press enter to continue" << endl;
	getline(cin, in);

	// Free up memory allocated for the certificate, public key, private key, and PKCS12 objects
	delete (cert);
	delete (pubKey);
	delete (privKey);
	delete (pkcs12);
}

//Include Document and create signature requirements
void includeDocument(){	
	string in, path;
	ostringstream fileBuilder;

	// Clears the terminal screen
	system("clear");	

	// Creates a SHA256 MessageDigest object
	MessageDigest hashCreator(MessageDigest::SHA256);
	ByteArray pdf;

	// Loops until a valid PDF file path is entered
	while(true){
		// Asks for PDF file path
		cout << "Type ESC to quit" << endl;
		cout << "Provide PDF file path: ";
		getline(cin, in); 
		// If the input is "esc" or "quit" or contains the ESC key, return
		if(lowerCase(in) == "esc" || lowerCase(in) == "quit" || in.find(27) != string::npos){
			return;
		}
		// Try to read the file at the provided path
		try
		{	
			pdf = fileReader(in);
			path = in;
			break;		
		}
		// If file not found, display an error message
		catch(runtime_error)
		{
			cout << "File not Found." << endl;
		}
	}

	// Creates a hash of the PDF using the SHA256 MessageDigest object
	ByteArray hash = hashCreator.doFinal(pdf);

	// Variables to store information about signers
	vector<string> names;
	pair<vector<string>, vector<int> > titleCount;
	int freeSigners = 0;
	int approval  = 0;

	// Loops until the user chooses to finish and save the document
	while (true)
	{
		// Clears the terminal screen
		system("clear");

		// Display already inserted Signers
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
		// If the input is "esc" or "quit" or contains the ESC key, return
		if(lowerCase(in) == "esc" || lowerCase(in) == "quit" || in.find(27) != string::npos){
			return;
		}
		// Name registration
		if (in == "1"){
			while (true)
			{	
				cout << "Type ESC to quit" << endl;
				cout << "Full Name: ";
				getline(cin, in);
				// If the input is "esc" or "quit" or contains the ESC key, return
				if(lowerCase(in) == "esc" || lowerCase(in) == "quit" || in.find(27) != string::npos){
					break;
				}
				// Checks if the input is not empty
				if(!in.empty()){
					string name = in;	
					// Search the name in the list of registered names to block duplicates		
					if(find(names.begin(), names.end(), name) != names.end() && !names.empty()){
						cout << "Name already on the list" << endl << "Press enter to continue" << endl;
						getline(cin, in);
					}
					else{
						while (true)
						{
							// Confirm name with the user
							cout << "Type ESC to quit" << endl;
							cout << "You typed: " << name << endl << "Are you sure (y or n)? ";
							getline(cin, in);
							// If the input is "esc" or "quit" or contains the ESC key, return
							if(lowerCase(in) == "esc" || lowerCase(in) == "quit" || in.find(27) != string::npos){
								break;
							}
							// If name is correct add name to register
							if(lowerCase(in) == "y" || lowerCase(in) == "yes"){
								names.push_back(name);
								break;
							}
							// If name is incorrect asks for the name again
							else if(lowerCase(in) == "n" || lowerCase(in) == "no"){
								cout << "Type ESC to quit" << endl;
								cout << "Type the correct name: ";
								getline(cin, name);
								// If the input is "esc" or "quit" or contains the ESC key, return
								if(lowerCase(name) == "esc" || lowerCase(name) == "quit" || name.find(27) != string::npos){
									break;
								}
								// Search the name in the list of registered names to block duplicates	
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
		// Title Registration
		else if(in == "2"){
			while (true)
			{
				cout << "Type ESC to quit" << endl;
				cout << "Job Title: ";
				getline(cin, in);
				// If the input is "esc" or "quit" or contains the ESC key, return
				if(lowerCase(in) == "esc" || lowerCase(in) == "quit" || in.find(27) != string::npos){
					break;
				}
				// Checks if the input is not empty
				if(!in.empty()){
					string title = in;
					while (true)
					{
						//Confirm Title with the user
						cout << "Type ESC to quit" << endl;
						cout << "You typed: " << title << endl << "Are you sure (y or n)? ";
						getline(cin, in);
						// If the input is "esc" or "quit" or contains the ESC key, return
						if(lowerCase(in) == "esc" || lowerCase(in) == "quit" || in.find(27) != string::npos){
							break;
						}
						// If is correct gets the quantity of signers with the title
						if(lowerCase(in) == "y" || lowerCase(in) == "yes"){
							while (true)
							{	
								// Gets the quantity of signers with the title
								cout << "Type ESC to quit" << endl;
								cout << "How many of this title has to sign de document?" << endl << "-> ";
								getline(cin, in);
								// If the input is "esc" or "quit" or contains the ESC key, return
								if(lowerCase(in) == "esc" || lowerCase(in) == "quit" || in.find(27) != string::npos){
									break;
								}

								// Converts input string to number
								istringstream converter(in);
								int number;
								converter >> number;

								// If input isn't a numer ask for a number
								if(converter.fail()){
									cout << "Not a number" << endl;			
								}
								// If input zero or less, ask for a valid number
								else if(number <= 0){
									cout << "Please type a number bigger than 0" << endl;
								}
								else{
									while (true)
									{
										//Confirm title number with user 
										cout << "Type ESC to quit" << endl;
										cout << number << " " << title << " are needed to sign this document (y or n)? ";
										getline(cin, in);
										// If the input is "esc" or "quit" or contains the ESC key, return
										if(lowerCase(in) == "esc" || lowerCase(in) == "quit" || in.find(27) != string::npos){
											break;
										}
										// If its correct include title and its quantity to register
										if(lowerCase(in) == "y" || lowerCase(in) == "yes"){
											titleCount.first.push_back(title);
											titleCount.second.push_back(number);
											break;
										}
										// If number isn't correct get correct number
										else if(lowerCase(in) == "n" || lowerCase(in) == "no"){
											bool exitMenu = false;
											while (true)
											{
												cout << "Type ESC to quit" << endl;
												cout << "Type the correct quantity: ";
												getline(cin, in);
												// If the input is "esc" or "quit" or contains the ESC key, return
												if(lowerCase(in) == "esc" || lowerCase(in) == "quit" || in.find(27) != string::npos){
													exitMenu = true;
													break;
												}
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
											if(exitMenu){
												break;										
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
						// If is incorrect gets the correct title
						else if(lowerCase(in) == "n" || lowerCase(in) == "no"){
							cout << "Type ESC to quit" << endl;
							cout << "Type the correct job title: ";
							getline(cin, title);
							if(lowerCase(title) == "esc" || lowerCase(title) == "quit" || title.find(27) != string::npos){
								break;
							}
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
		// Free Registration 
		else if(in == "3"){			
			while (true)
			{
				cout << "Type ESC to quit" << endl;
				cout << "How many signature spaces could have anyone's signature?" << endl << "-> ";
				getline(cin, in);
				// If the input is "esc" or "quit" or contains the ESC key, return
				if(lowerCase(in) == "esc" || lowerCase(in) == "quit" || in.find(27) != string::npos){
					break;
				}
				
				// Converts input string to number
				istringstream converterFree(in);
				int numberFree;
				converterFree >> numberFree;

				// If input isn't a numer ask for a number
				if(converterFree.fail()){
					cout << "Not a number" << endl;			
				}
				// If input zero or less, ask for a valid number
				else if(numberFree <= 0){
					cout << "Please type a number bigger than 0" << endl;
				}
				else{
					while (true)
					{
						//Confirm quantity with user 
						cout << "Type ESC to quit" << endl;
						cout << numberFree << " signature spaces are free for anyone to sign (y or n)? ";
						getline(cin, in);
						// If the input is "esc" or "quit" or contains the ESC key, return
						if(lowerCase(in) == "esc" || lowerCase(in) == "quit" || in.find(27) != string::npos){
							break;
						}
						// If its correct include quantity to register
						if(lowerCase(in) == "y" || lowerCase(in) == "yes"){
							freeSigners += numberFree;
							break;
						}
						// If number isn't correct get correct number
						else if(lowerCase(in) == "n" || lowerCase(in) == "no"){
							bool exitMenu = false;
							while (true)
							{
								cout << "Type ESC to quit" << endl;
								cout << "Type the correct quantity: ";
								getline(cin, in);
								// If the input is "esc" or "quit" or contains the ESC key, return
								if(lowerCase(in) == "esc" || lowerCase(in) == "quit" || in.find(27) != string::npos){
									exitMenu = true;
									break;
								}
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
							if(exitMenu){
								break;
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
		// Finalize document registry
		else if(in == "4"){
			while (true)
			{
				// Confirm decision to finish document
				cout << "Are you sure you want to finish (y or n)? ";
				getline(cin, in);
				// If the user is certain get number of approval necessary 
				if(lowerCase(in) == "y" || lowerCase(in) == "yes"){
					// If nothing was registered do nothing
					if (names.empty() && titleCount.first.empty() && freeSigners == 0){
						return;
					}					
					while(true){
						// Get number of registered signers
						int sigNum = names.size() + freeSigners;
						for (size_t i = 0; i < titleCount.second.size(); i++)
						{
							sigNum += titleCount.second.at(i);
						}

						// Clears the terminal screen
						system("clear");
						cout << "Type ESC to quit" << endl;
						cout << "How many of the signers have to agree with the document for it to be validated?" << endl << "Type a number between 0 and " << sigNum << endl << "If the number is 0 the document will need a signature, but wont ask for approval" << endl << "->";

						getline(cin, in);
						// If the input is "esc" or "quit" or contains the ESC key, return
						if(lowerCase(in) == "esc" || lowerCase(in) == "quit" || in.find(27) != string::npos){
							break;
						}

						// Converts input string to number
						istringstream converter(in);
						converter >> approval;

						// If input isn't a numer ask for a number
						if(converter.fail()){
							cout << "Not a number" << endl;			
						}
						// If input less then zero or bigger then the number of registered signers, ask for a valid number
						else if(approval < 0 || approval > sigNum){
							cout << "Please type a number between 0 and " << sigNum << endl << "Press enter to continue" << endl;
							getline(cin, in);
							approval = 0;
						}
						else{
							//Confirm typed number
							cout << approval << " people need to approve the document (y or n)?";
							getline(cin, in);
							// If no, get number
							if(lowerCase(in) == "n" || lowerCase(in) == "no" || in.find(27) != string::npos){
								continue;
							}
							// If yes, save number 
							else if(lowerCase(in) == "y" || lowerCase(in) == "yes"){
								break;
							}
							else{
								cout << "Not an option, please chose a number" << endl << "Press enter to continue" << endl;
								getline(cin, in);
							}
						}
					}
					break;
				}
				// If the input is "n" or "no" or contains the ESC key, return
				else if(lowerCase(in) == "n" || lowerCase(in) == "no" || in.find(27) != string::npos){
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

	// Input registered signers and category in a ostringstream 
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

	fileBuilder << "signatures:0" << endl;

	// Convert ostringstream to ByteArray
	ByteArray out(&fileBuilder);

	// Create memory file, with the hash as its name
	creatingMemoryFile(out, hash.toHex());
}

//Let users sign documents
void signDocument(){
	// Load message digest and symmetric cipher algorithms	
	MessageDigest::loadMessageDigestAlgorithms();
	SymmetricCipher::loadSymmetricCiphersAlgorithms();

	//Creating PDF hash to insert in memory file
	MessageDigest hashCreator(MessageDigest::SHA256);
	ByteArray pdf;
	string in, path;

	// Loops until a valid PDF file path is entered
	while(true){
		// Asks for PDF file path
		cout << "Type ESC to quit" << endl;
		cout << "Provide original PDF file path: ";
		getline(cin, in); 
		// If the input is "esc" or "quit" or contains the ESC key, return
		if(lowerCase(in) == "esc" || lowerCase(in) == "quit" || in.find(27) != string::npos){
			return;
		}
		// Try to read the file at the provided path
		try
		{	
			pdf = fileReader(in);
			path = in;
			break;		
		}
		// If file not found, display an error message
		catch(runtime_error)
		{
			cout << "File not Found" << endl;
		}
	}

	// Creates a hash of the PDF using the SHA256 MessageDigest object
	ByteArray hash = hashCreator.doFinal(pdf);
	ByteArray memoryFile;
	// Try to open Memory File
	try
	{	
		memoryFile = openMemoryFile(hash.toHex(), 1);
	}
	// If file not found, display an error message
	catch(runtime_error)
	{
		cout << "Document not registered"  << endl << "Press enter to continue" << endl;
		getline(cin, in);
		return;
	}

	// Transfer memory file data to a ostringstream that is easier to edit/read
	ostringstream fileBuilder;
	fileBuilder << memoryFile.toString();
	
	while (true)
	{
		// Read memory file data and transfer useful data to vectors and variables 
		vector<string> names, signatures;
		pair<vector<string>, vector<int> > titleCount;
		int posStart, posTerm, posSeparator, posEnd, number, freeSigners;
		int approval;

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
		approval = atoi(fileBuilder.str().substr(posSeparator+1, posEnd-posSeparator-1).c_str());

		posTerm = fileBuilder.str().find("signatures:");
		posSeparator = fileBuilder.str().find(":", posTerm+1);
		posEnd = fileBuilder.str().find("\n", posSeparator);
		number = atoi(fileBuilder.str().substr(posSeparator+1, posEnd-posSeparator-1).c_str());

		for (int i = 0; i < number; i++)
		{
			posStart = posEnd+1;
			posEnd = fileBuilder.str().find("\t", posStart);
			signatures.push_back(fileBuilder.str().substr(posStart, posEnd-posStart));
			posEnd = fileBuilder.str().find("\n", posStart);
		}
	
		system("clear");
		// If all vectors are empty and the freeSigners variable is zero the file has been fully signed
		if(names.empty() && titleCount.first.empty() && freeSigners == 0){
			// Change Memory file directory and let the use know
			upgradeMemoryFile(hash.toHex());
			cout << "Document fully signed" << endl << "Press enter to continue" << endl;
			getline(cin, in);
			break;
		}
		// Show necessary name signers, titles and free signers to complete the document signature
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
		
		// Gets user Full Name
		cout << "Type ESC to quit" << endl;
		cout << "Type your full name: ";
		getline(cin, in);

		// If the input is "esc" or "quit" or contains the ESC key, return
		if(lowerCase(in) == "esc" || lowerCase(in) == "quit" || in.find(27) != string::npos){
			return;
		}
		
		// Transform input to lowercase without spaces
		string certificateName = lowerCase(in, 1);
		ByteArray certFile, signature;

		// Try to open certificate with the name of the signer
		try
		{	//Read Certificate File
			certFile = fileReader(string("./certificates/" + certificateName + ".p12").c_str());
			//Create Pkcs12 object from DER encoded
			Pkcs12 p12 = *Pkcs12Factory().fromDerEncoded(certFile);

			string name, title, password;
			ByteArray pubKeyDer;

			while (true)
			{
				// Get User password
				cout << "Signer password: ";
				getline(cin, in);
				// If the input is "esc" or "quit" or contains the ESC key, return
				if(lowerCase(in) == "esc" || lowerCase(in) == "quit" || in.find(27) != string::npos){
					break;
				}
				Signer signatureCretor;
				//Try to use user password to get p12 informations
				try{
					// Create signature from user's Private Key and PDF hash
					signature = signatureCretor.sign(*p12.getPrivKey(in), hash, MessageDigest::SHA256);
					// Get user name, title and Public Key from user
					name = p12.getCertificate(in)->getSubject().getEntries(RDNSequence::COMMON_NAME).at(0);
					title = p12.getCertificate(in)->getSubject().getEntries(RDNSequence::TITLE).at(0);
					pubKeyDer =  p12.getCertificate(in)->getPublicKey()->getDerEncoded();

					// Find how that user is supposed to sign document (name, title oy free) and set a variable
					int category = 0;
					//If user already signed the document he can't sign again
					if(find(signatures.begin(), signatures.end(), name) != signatures.end()){
						cout << "You have already signed this document" << endl << "Press enter to continue" << endl;
						getline(cin, in);
						break;
					}
					// Find how that user is supposed to sign document (name, title oy free) and set a variable
					else if(find(names.begin(), names.end(), name) != names.end() && !names.empty()){
						category = 1;
					}
					else if(find(titleCount.first.begin(), titleCount.first.end(), title) != titleCount.first.end() && !titleCount.first.empty()){
						category = 2;
					}
					else if(freeSigners > 0){
						category = 3;
					}
					else{
						cout << "You can't sign this document" << endl<< "Press enter to continue" << endl;
						getline(cin, in);
						break;
					}
					bool accept = NULL;

					//If the document needs approval ask for the signer
					if(approval > 0){
						bool exitMenu = false;
						while (true)
						{	
							cout << "Type ESC to quit" << endl;
							cout << "Do you: " << endl;
							cout << "1-Agree" << endl;
							cout << "2-Disagree" << endl;
							getline(cin, in);							
							// If the input is "esc" or "quit" or contains the ESC key, return
							if(lowerCase(in) == "esc" || lowerCase(in) == "quit" || in.find(27) != string::npos){
								system("clear"),
								cout << "Ok, think about it and come back" << endl << "Your signature was not finalized" << endl << "Press enter to continue" << endl;
								getline(cin, in);
								exitMenu = true;
								break;
							}
							if (in == "1")
							{
								accept = true;
								break;
							}
							else if(in == "2"){
								accept = false;
								break;
							}
							else{
								cout << "Not an option, please choose a number" << endl;
							}
						}
						if(exitMenu){
							break;
						}
					}
					//If signer is listed by name, delete his registry from the list 
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
					//If signer is listed by title, delete his registry from the list
					else if(category == 2){	
						string editor = fileBuilder.str();									

						int posStartTitle = editor.find(title);
						int posEndTitle = editor.find("\t", posStartTitle);

						posStart = posEndTitle+1;
						posEnd = editor.find("\n", posStart);
						int titleNumber = atoi(editor.substr(posStart, posEnd-posStart).c_str());
						titleNumber--;
						if(titleNumber == 0){
							editor.erase(posStartTitle-1, posEnd-posStartTitle+1);
							posTerm = editor.find("titleSigners:");
							posSeparator = editor.find(":", posTerm+1);
							posEnd = editor.find("\n", posSeparator);
							int editNumber = atoi(editor.substr(posSeparator+1, posEnd-posSeparator-1).c_str());
							editNumber--;
							stringstream intToString;
							intToString << editNumber;
							editor.replace(posSeparator+1, posEnd-posSeparator-1, intToString.str());
						}
						else{
							stringstream intToString;
							intToString << titleNumber;
							editor.replace(posStart, posEnd-posStart, intToString.str());
						}
						fileBuilder.str("");
						fileBuilder << editor;
					}
					//If signer was not listed, a free signer is removed
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
					//Get signature time
					time_t now = time(0);
					tm* brasilia_time = gmtime(&now);
					brasilia_time->tm_hour -= 3;
					time_t brasilia_time_t = mktime(brasilia_time);

					//Update ostringstream
					fileBuilder << name << "\t" << title << "\t" << signature.toHex() << "\t" << accept << "\t" << pubKeyDer.toHex() << "\t" << brasilia_time_t << endl;

					// Add one to the signatures count and edit ostringstream
					string editor = fileBuilder.str();
					posTerm = editor.find("signatures:");
					posSeparator = editor.find(":", posTerm+1);
					posEnd = editor.find("\n", posSeparator);
					int editNumber = atoi(editor.substr(posSeparator+1, posEnd-posSeparator-1).c_str());
					editNumber++;
					stringstream intToString;
					intToString << editNumber;
					editor.replace(posSeparator+1, posEnd-posSeparator-1, intToString.str());
					fileBuilder.str("");
					fileBuilder << editor;

					// Convert ostringstream to ByteArray
					ByteArray out(&fileBuilder);
					//Update memory file
					creatingMemoryFile(out, hash.toHex());
					break;
				}
				// If password is incorrect, inform error
				catch(Pkcs12Exception){					
					cout << "Incorrect Password" << endl << "Press enter to continue" << endl;
					getline(cin, in);										
				}		
			}
			
		}
		// If file not found, display an error message
		catch(runtime_error)
		{
			cout << "Certificate not found!" << endl << "Please check your spelling or create certificate" << endl << "Press enter to continue" << endl;
			getline(cin, in);
		}
	}
}

void verify(){
	// Load message digest and symmetric cipher algorithms	
	MessageDigest::loadMessageDigestAlgorithms();
	SymmetricCipher::loadSymmetricCiphersAlgorithms();

	// Creates a SHA256 MessageDigest object
	MessageDigest hashCreator(MessageDigest::SHA256);
	ByteArray pdf;
	string in, path;

	// Loops until a valid PDF file path is entered
	while(true){
		// Asks for PDF file path
		cout << "Type ESC to quit" << endl;
		cout << "Provide original PDF file path: ";
		getline(cin, in); 
		// If the input is "esc" or "quit" or contains the ESC key, return
		if(lowerCase(in) == "esc" || lowerCase(in) == "quit" || in.find(27) != string::npos){
			return;
		}
		// Try to read the file at the provided path
		try
		{	
			pdf = fileReader(in);
			path = in;
			break;		
		}
		// If file not found, display an error message
		catch(runtime_error)
		{
			cout << "File not Found" << endl;
		}
	}

	// Creates a hash of the PDF using the SHA256 MessageDigest object
	ByteArray hash = hashCreator.doFinal(pdf);
	ByteArray memoryFile;
	// Try to open Memory File
	try
	{	
		memoryFile = openMemoryFile(hash.toHex(), 2);
	}
	// If file not found, display an error message
	catch(runtime_error)
	{
		cout << "Document not registered or not yet fully signed"  << endl << "Press enter to continue" << endl;
		getline(cin, in);
		return;
	}

	// Transfer memory file data to a ostringstream that is easier to edit/read
	ostringstream fileBuilder;
	fileBuilder << memoryFile.toString();

	// Read memory file data and transfer useful data to vectors and variables 
	vector<string> names, titles, approvals, signatures, pubKeys;
	vector<time_t> dates;

	int posStart, posTerm, posSeparator, posEnd, number, approval, approvalCount = 0;

	posTerm = fileBuilder.str().find("needApproval:");
	posSeparator = fileBuilder.str().find(":", posTerm+1);
	posEnd = fileBuilder.str().find("\n", posSeparator);
	approval = atoi(fileBuilder.str().substr(posSeparator+1, posEnd-posSeparator-1).c_str());

	posTerm = fileBuilder.str().find("signatures:");
	posSeparator = fileBuilder.str().find(":", posTerm+1);
	posEnd = fileBuilder.str().find("\n", posSeparator);
	number = atoi(fileBuilder.str().substr(posSeparator+1, posEnd-posSeparator-1).c_str());

	for (int i = 0; i < number; i++)
	{
		posStart = posEnd+1;
		posEnd = fileBuilder.str().find("\t", posStart);
		names.push_back(fileBuilder.str().substr(posStart, posEnd-posStart));

		posStart = posEnd+1;
		posEnd = fileBuilder.str().find("\t", posStart);
		titles.push_back(fileBuilder.str().substr(posStart, posEnd-posStart));

		posStart = posEnd+1;
		posEnd = fileBuilder.str().find("\t", posStart);
		signatures.push_back(hexToChar(fileBuilder.str().substr(posStart, posEnd-posStart)));

		posStart = posEnd+1;
		posEnd = fileBuilder.str().find("\t", posStart);
		approvals.push_back(fileBuilder.str().substr(posStart, posEnd-posStart));

		posStart = posEnd+1;
		posEnd = fileBuilder.str().find("\t", posStart);
		pubKeys.push_back(hexToChar(fileBuilder.str().substr(posStart, posEnd-posStart)));

		posStart = posEnd+1;
		posEnd = fileBuilder.str().find("\t", posStart);
		dates.push_back(atoi(fileBuilder.str().substr(posStart, posEnd-posStart).c_str()));

		posEnd = fileBuilder.str().find("\n", posStart);
	}

	//Create pair names with a index vector
	vector<pair<string, int> > tempVector;
	for (size_t i = 0; i < names.size(); i++) {
		tempVector.push_back(make_pair(names.at(i), i));
	}	

	//Sort vector in alphabetic order
	sort(tempVector.begin(), tempVector.end(), comparePairs);

	//Create new vectors in the correct order maintaining reference
	vector<string> namesShow, titlesShow, approvalsShow, signaturesShow, pubKeysShow;
	vector<time_t> datesShow;

	for (size_t i = 0; i < tempVector.size(); i++) {
		int originalIndex = tempVector.at(i).second;
		namesShow.push_back(names.at(originalIndex));
		titlesShow.push_back(titles.at(originalIndex));
		approvalsShow.push_back(approvals.at(originalIndex));
		signaturesShow.push_back(signatures.at(originalIndex));
		pubKeysShow.push_back(pubKeys.at(originalIndex));
		datesShow.push_back(dates.at(originalIndex));
	}

	// Shows everyone the signed the document, time, decision and verification
	cout << "The file " << getFileName(path) << " was signed by: " << endl << endl; 
	for (size_t i = 0; i < signatures.size(); i++)
	{
		// Creat formatted time
		char timeStr[80];
		strftime(timeStr, sizeof(timeStr), "%H:%M:%S %d-%m-%Y", localtime(&datesShow.at(i)));
		ostringstream formatting;
		formatting << namesShow.at(i) << "-" << titlesShow.at(i);

		//Print Name, title and time
		cout << left << setw(50) << formatting.str() << "At " << setw(20) << timeStr;				

		// Show signer decision
		if(approval > 0){
			if(approvalsShow.at(i) == "1"){
				cout << setw(39) <<"The signer approved the document";
				approvalCount++;
			}
			else if(approvalsShow.at(i) == "0"){
				cout << setw(39) << "The signer denied the document";
			}
		}

		// Get Signatures, PublicKey and convert to ByteArray
		ByteArray sigArray(signaturesShow.at(i));
		ByteArray keyArray(pubKeysShow.at(i));
		//Verify Signature with public Key
		RSAPublicKey rsaPubKey(keyArray);
		
		// Show if the signature is verified
		Signer verification;
		cout << "Signature: ";
		if(verification.verify(rsaPubKey, sigArray, hash, MessageDigest::SHA256)){
			cout << "Verified" << endl;
		}
		else{
			cout << "Invalid" << endl;
		}		
	}
	// Show if the document was validated based on validation required on document creation
	if(approval > 0){
		if(approvalCount >= approval){
			cout << endl << "\033[32m" << "Document Approved" << "\033[0m" << endl; 
		}
		else{
			cout << endl << "\033[31m" << "Document Denied" << "\033[0m" << endl;
		}
	}

	cout << endl << "Press enter to leave!" << endl;
	getline(cin, in);
}

int main(int argc, char **argv) {
	// Load message digest and symmetric cipher algorithms	
	MessageDigest::loadMessageDigestAlgorithms();
	SymmetricCipher::loadSymmetricCiphersAlgorithms();

	//Create necessary Repository 
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

	//Loops until user closes system
	while (true)
	{
		//Main menu
		system("clear");
		cout << "Functions: " << endl;
		cout << "1-Create Certificate" << endl;
		cout << "2-Include Document" << endl;
		cout << "3-Sign Document" << endl;
		cout << "4-Verify Document" << endl;
		cout << "Type function number ->";
		string in;
		getline(cin, in);

		//Send user to the wanted function
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
			verify();
		}
		else{
			cout << "Type function number"<< endl << "Press enter to continue" << endl;
			getline(cin, in);
		}
	}

	return 0;
}
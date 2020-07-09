#include <iostream>
#include <fstream>
#include <windows.h>
#include <tchar.h>
#include "accctrl.h"
#include "aclapi.h"

using namespace std;
//C:\37b73d3fbaad8b79db553b61f7b5f281\PkgInstallOrder.txt
//C:\Users\Vicky\Documents\Software\abc.txt
PACL SetPerm(LPCTSTR file, string user, char val, int perm, PACL pOldDACL)
{
	EXPLICIT_ACCESS eas[1];
    PACL pacl = 0;
    DWORD rc;
    long long int access_val;
    LPSTR use = const_cast<char *>(user.c_str());
    if(val=='R'||val=='r')
    	access_val=0x80000000;		//GENERIC_READ
    if(val=='W'||val=='w')
    	access_val=0x40000000;		//GENERIC_WRITE
    if(val=='A'||val=='a')
    	access_val=0x10000000;		//GENERIC_ALL
    if(perm==1)
    {
    	eas[0].grfAccessPermissions = access_val;
    	eas[0].grfAccessMode = GRANT_ACCESS;
    	eas[0].grfInheritance = NO_INHERITANCE;
    	eas[0].Trustee.TrusteeForm = TRUSTEE_IS_NAME;
    	eas[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    	eas[0].Trustee.ptstrName = use;
	}
    else if(perm==2)
    {
    	eas[0].grfAccessPermissions = access_val;
    	eas[0].grfAccessMode = DENY_ACCESS;
    	eas[0].grfInheritance = NO_INHERITANCE;
    	eas[0].Trustee.TrusteeForm = TRUSTEE_IS_NAME;
    	eas[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    	eas[0].Trustee.ptstrName = use;
	}
    rc = SetEntriesInAcl(1, eas, pOldDACL, &pacl);
    if (rc != ERROR_SUCCESS)
    {
        printf("SetEntriesInAcl: %u\n", rc);
        return NULL;
    }

    rc = SetNamedSecurityInfo((LPSTR)file, SE_FILE_OBJECT, 
             DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, 
             NULL, NULL, pacl, NULL);
    if (rc != ERROR_SUCCESS)
    {
        printf("SetNamedSecurityInfo: %u\n", rc);
        return NULL;
    }

    printf("---------------PERMISSION GRANTED----------------\n");
    return pacl;
}

int main() 
{
PSID pSidOwner = NULL;
BOOL bRtnBool = TRUE;
LPTSTR AcctName = NULL;
LPTSTR DomainName = NULL;
DWORD dwRtnCode = 0, dwAcctName = 1, dwDomainName = 1;
SID_NAME_USE eUse = SidTypeUnknown;
HANDLE hFile;
PSECURITY_DESCRIPTOR pSD = NULL;
PACL pOldDACL = NULL, pNewDACL = NULL;
char ch,tp;
int val,perm,i,aceNum;
string input,user;
LPSTR *users;
users = new LPSTR[10];
ofstream ofile;				//creating a fstream object
ofile.open ("text.txt");	//creating a new file text.txt

cout << "Enter the location : " << endl;
cin >> input;
LPCSTR file = input.c_str(); 
// Get the handle of the file object.
hFile = CreateFile(
                  file,
                  GENERIC_READ,
                  FILE_SHARE_READ,
                  NULL,
                  OPEN_EXISTING,
                  FILE_ATTRIBUTE_NORMAL,
                  NULL);
                  
// Check GetLastError for CreateFile error code.
if (hFile == INVALID_HANDLE_VALUE) {
          DWORD dwErrorCode = 0;
          dwErrorCode = GetLastError();
          cout << "CreateFile error = " << dwErrorCode<<". Possibly NO file exist in the given path or READ Access denied.";
          return 0;
}

// Get the SID of the file.
dwRtnCode = GetSecurityInfo(
                  hFile,
                  SE_FILE_OBJECT,
                  DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
                  &pSidOwner,
                  NULL,
                  &pOldDACL,
                  NULL,
                  &pSD);

// Check GetLastError for GetSecurityInfo error condition.
if (dwRtnCode != ERROR_SUCCESS) {
          DWORD dwErrorCode = 0;
          dwErrorCode = GetLastError();
          cout << "GetSecurityInfo error = " << dwErrorCode;
}

else if (dwRtnCode == ERROR_SUCCESS) {
		cout << "\n\nGetSecurityInfo() Success, Number of ACE: " << pOldDACL->AceCount << "\n\n";
		ofile << "\n\nGetSecurityInfo() Success, Number of ACE: " << pOldDACL->AceCount << "\n\n";
}

bRtnBool = LookupAccountSid(
                  NULL,           // local computer
                  pSidOwner,
                  AcctName,
                  (LPDWORD)&dwAcctName,
                  DomainName,
                  (LPDWORD)&dwDomainName,
                  &eUse);

	// Reallocate memory for the buffers.
	AcctName = (LPTSTR)GlobalAlloc(GMEM_FIXED,dwAcctName);
	DomainName = (LPTSTR)GlobalAlloc(GMEM_FIXED,dwDomainName);
	
    // Second call to LookupAccountSid to get the account name.
    bRtnBool = LookupAccountSid(
          NULL,                   // name of local or remote computer
          pSidOwner,              // security identifier
          AcctName,               // account name buffer
          (LPDWORD)&dwAcctName,   // size of account name buffer 
          DomainName,             // domain name
          (LPDWORD)&dwDomainName, // size of domain name buffer
          &eUse);                 // SID type
          
    // Print the account name.
    cout<<"Path\t: "<<input;
	cout<<"\nOwner\t: "<<AcctName<<endl;
	ofile<<"Path\t: "<<input;
	ofile<<"\nOwner\t: "<<AcctName<<endl;

PACL pAcl = pOldDACL;
aceNum = pOldDACL->AceCount;
cout<<"Access";
ofile<<"Access";
for (i = 0; i < aceNum; i++)
{
	PACCESS_ALLOWED_ACE AceItem;
    ACE_HEADER *aceAddr = NULL;
    if (GetAce(pOldDACL, i, (LPVOID*)&AceItem) && GetAce(pOldDACL, i, (LPVOID*)&aceAddr))
    {
    	LPTSTR AccountBuff = NULL;
        LPTSTR DomainBuff = NULL;
        DWORD AccountBufflength = 1;
        DWORD DomainBufflength = 1;
        PSID_NAME_USE peUse = new SID_NAME_USE;
        PSID Sid = &AceItem->SidStart;
        LookupAccountSid(NULL, Sid, AccountBuff, (LPDWORD)&AccountBufflength, DomainBuff, (LPDWORD)&DomainBufflength,peUse);
    	
		AccountBuff = (LPTSTR)GlobalAlloc(GMEM_FIXED,AccountBufflength);
    	DomainBuff = (LPTSTR)GlobalAlloc(GMEM_FIXED,DomainBufflength);
		
		LookupAccountSid(NULL, Sid, AccountBuff, &AccountBufflength, DomainBuff, &DomainBufflength,peUse);
        cout<<"\t: "<<DomainBuff<<"\\"<<AccountBuff<<"\t";
        ofile<<"\t: "<<DomainBuff<<"\\"<<AccountBuff<<"\t";
        ACCESS_MASK Mask = AceItem->Mask;
        if (((Mask & GENERIC_ALL) == GENERIC_ALL) || ((Mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS)){
         cout << "Full Control\n";
         ofile << "Full Control\n";
         continue;
		 }
   		if (((Mask & GENERIC_READ) == GENERIC_READ) || ((Mask & FILE_GENERIC_READ) == FILE_GENERIC_READ)){
         	cout << "Read\t";
         	ofile << "Read\t";
		 }
		if (((Mask & GENERIC_WRITE) == GENERIC_WRITE) || ((Mask & FILE_GENERIC_WRITE) == FILE_GENERIC_WRITE)){
			cout << "Write\t";
			ofile << "Write\t";
		 }
		if (((Mask & GENERIC_EXECUTE) == GENERIC_EXECUTE) || ((Mask & FILE_GENERIC_EXECUTE) == FILE_GENERIC_EXECUTE)){
			cout << "Execute\t";
			ofile << "Execute\t";
		 }
    }
    cout << endl;
}
cout << "\nDo you want to change the permission to the various users?(Y\\N)";
cin >> ch;
while(ch=='y'||ch=='Y')
	{
		cout << "TYPE the full username for which you want to change the permission.\n1.Administrator\n2.Everyone\n3.CurrentUser Name(For eg.Vicky)\n4.SYSTEM\n";
		cin >> user;
		cout << "Whether you want to DENY or GRANT the permission?\n1.GRANT\n2.DENY\n";
		cin >> perm;
		cout << "Enter the type of access you wanted to grant/deny.\na)ALL\nr)READ\nw)WRITE\n";
		cin >> tp;
		pOldDACL = SetPerm(file,user,tp,perm,pOldDACL);
		cout << "Do you want to modify more permission?(Y\\N)";
		cin  >> ch;
	}
cout << "Data written to file named as text.txt in the same directory." << endl;
ofile.close();
return 0;
}

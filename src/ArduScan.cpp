/*
 * ArduScan
 * Sept 2011 by Bill Westfield ("WestfW")
 *
 * Scan a windows system and try to figure out which COM ports
 * look like they might be Arduinos.
 *
 * This is based on the article here:
 *   http://www.codeproject.com/KB/system/serial_portsenum_fifo.aspx
 * by Vladimir Afanasyev, which explains how to use the device manager
 * API to enumerate all the COM ports on a system, and
 * these forum entries:
 *   http://www.microchip.com/forums/tm.aspx?high=&m=559736&mpage=1#560699
 *   http://www.microchip.com/forums/tm.aspx?high=&m=364903&mpage=1#365029
 * Which explain how to get the USB Vendor/Product info from the same api.
 *
 * Currently this is set up to run in a CMD or other shell window, and
 * writes its findings to stdout.
 *
 *
 * It should compile fine under cygin, including mingw versions:
 *
 *   g++ -mno-cygwin ArduScan.cpp -lsetupapi -o ArduScan.exe
 *
 *
 * Vladimir's code is distributed according to the terms of "The Code
 *  Project Open License (CPOL)"  http://www.codeproject.com/info/cpol10.aspx
 * and Bill thinks that sounds fine, and doesn't add any terms for his own code.
 */

#include <windows.h>
#include <setupapi.h>
#include <stdio.h>

/*
 * USB Vendor IDs that are somewhat likely to be Arduinos.
 */

#define VENDOR_FTDI 0x403
#define VENDOR_ARDUINO 0x2341

/*
 * Vladamir's code for enumerating COM ports.  Slightly modifed.
 */
#define MAX_NAME_PORTS 7
#define RegDisposition_OpenExisting (0x00000001) // open key only if exists

#define CM_REGISTRY_HARDWARE        (0x00000000)

typedef DWORD WINAPI
  (* CM_Open_DevNode_Key)(DWORD, DWORD, DWORD, DWORD, ::PHKEY, DWORD);

HANDLE  BeginEnumeratePorts(VOID)
{
  BOOL guidTest=FALSE;
  DWORD RequiredSize=0;
  HDEVINFO DeviceInfoSet;
  char* buf;

  guidTest=SetupDiClassGuidsFromNameA("Ports",(LPGUID)0,0,&RequiredSize);
  if(RequiredSize < 1)
    return (HANDLE) -1;

  buf=(char *)malloc(RequiredSize*sizeof(GUID));

  guidTest=SetupDiClassGuidsFromNameA(
           "Ports",(_GUID *)buf,RequiredSize*sizeof(GUID),&RequiredSize);

  if(!guidTest)
   return (HANDLE) -1;


  DeviceInfoSet=SetupDiGetClassDevs(
				    (_GUID*)buf,NULL,NULL,DIGCF_PRESENT);
  free(buf);

  if(DeviceInfoSet == INVALID_HANDLE_VALUE)
    return (HANDLE) -1;

  return DeviceInfoSet;
}

BOOL EnumeratePortsNext(HANDLE DeviceInfoSet, LPTSTR lpBuffer, int *index)
{
  static CM_Open_DevNode_Key OpenDevNodeKey=NULL;
  static HINSTANCE CfgMan;

  int res1;
  char DevName[MAX_NAME_PORTS]={0};
  static int numDev=0;
  int numport;

  SP_DEVINFO_DATA DeviceInfoData={0};
  DeviceInfoData.cbSize=sizeof(SP_DEVINFO_DATA);

  if(!DeviceInfoSet || !lpBuffer)
    return -1;
  if(!OpenDevNodeKey) {
    CfgMan=LoadLibrary("cfgmgr32");
    if(!CfgMan)
      return FALSE;
    OpenDevNodeKey=
       (CM_Open_DevNode_Key)GetProcAddress(CfgMan,"CM_Open_DevNode_Key");
    if(!OpenDevNodeKey) {
      FreeLibrary(CfgMan);
      return FALSE;
    }
  }

  while(TRUE){
    HKEY KeyDevice;
    DWORD len;
    res1=SetupDiEnumDeviceInfo(
        DeviceInfoSet,numDev,&DeviceInfoData);

    if(!res1) {
      SetupDiDestroyDeviceInfoList(DeviceInfoSet);
      FreeLibrary(CfgMan);
      OpenDevNodeKey=NULL;
      return FALSE;
    }

    res1=OpenDevNodeKey(DeviceInfoData.DevInst,KEY_QUERY_VALUE,0,
      RegDisposition_OpenExisting,&KeyDevice,CM_REGISTRY_HARDWARE);
    if(res1 != ERROR_SUCCESS)
      return FALSE;
    len=MAX_NAME_PORTS;

    res1=RegQueryValueEx(
      KeyDevice,    // handle of key to query
      "portname",    // address of name of value to query
      NULL,    // reserved
      NULL,    // address of buffer for value type
      (BYTE*)DevName,    // address of data buffer
      &len     // address of data buffer size
    );

    RegCloseKey(KeyDevice);
    if(res1 != ERROR_SUCCESS)
      return FALSE;

    /*
     * Return the index too, so we can look up other info
     */
    *index = numDev;
    numDev++;
    if(memcmp(DevName, "COM", 3))
      continue;
    numport=atoi(DevName+3);
    if(numport > 0 && numport <= 256) {
      strcpy(lpBuffer,DevName);
      return TRUE;
    }

    FreeLibrary(CfgMan);
    OpenDevNodeKey=NULL;
    return FALSE;
  }
}

BOOL  EndEnumeratePorts(HANDLE DeviceInfoSet)
{
  if(SetupDiDestroyDeviceInfoList(DeviceInfoSet))
    return TRUE;
  else return FALSE;
}
/*
 * End of Vladimir's code
 */

/*
 * Ascii HEX number to integer. Stop at invalid hex char
 */
int htoi(char *p)
{
  int n = 0;
  while (*p) {
    char c = *p;
    if (c >= '0' && c <= '9') {
      n = n * 16 + (c - '0');
    } else if (c >= 'a' && c <= 'z') {
      n = n * 16 + ((c+10) - 'a');
    } else if (c >= 'A' && c <= 'Z') {
      n = n * 16 + ((c+10) - 'A');
    } else break;
    p++;
  }
  return n;
}

/*
 * main program
 * enumerate the COM ports and split out any USB Vendor and Product info.
 * If the vendor is a likely Arduino (FTDI or Arduino), print out the info.
 */    
//int WinMain(HINSTANCE, HINSTANCE, LPSTR, int)
int main(int argc, _TCHAR* argv[])
{
  HANDLE h;
  SP_DEVINFO_DATA devInfo;
  int vendor, product;
  int deviceIndex;
  /*
   * Evil fixed-length strings; should allow variable length,
   * should allow univode.   Bad non-windows programmer!
   */
  char portname[50] = {0};
  char idstring[100] = {0};
  char infostring[100];
  char *sernostr;
  char *infop = infostring;

  h = BeginEnumeratePorts();
  /*
   * h now has handle from deviceInfoSet (SetupDiGetClassDevs)
   */
  devInfo.cbSize = sizeof(SP_DEVINFO_DATA);

  while (EnumeratePortsNext(h, portname, &deviceIndex)) {
    char *p;
    SetupDiEnumDeviceInfo(h, deviceIndex, &devInfo);

//  SetupDiGetDeviceInstanceId(h, &devInfo, NULL, 0, &di_size);
    SetupDiGetDeviceInstanceId(h, &devInfo, idstring, sizeof(idstring)-1, NULL);
    infop = infostring;

    p = strstr(idstring, "VID_");  /* See if there is a vendor ID */
    if (p) {
      vendor = htoi(p+4);
    } else {
      vendor = 0;
    }
    p = strstr(idstring, "PID_"); /* See if there is a Product ID */
    if (p) {
      product = htoi(p+4);
      sernostr = p+9;  /* The Serial number is everything past the PID */
    } else {
      product = 0;
      sernostr = NULL;
    }
    if (vendor == VENDOR_FTDI ||
	vendor == VENDOR_ARDUINO) {
//      sprintf(infop, "Possible Arduino on %s, VID 0x%04x PID 0x%04x\n     Serno %s",
//	      portname, vendor, product, sernostr);
//      MessageBox(NULL, infop, "ArduinoFinder", 0);
      printf("\nPossible Arduino on %s, VID 0x%04x PID 0x%04x\n     Serno %s",
	      portname, vendor, product, sernostr);
    }
  }
}

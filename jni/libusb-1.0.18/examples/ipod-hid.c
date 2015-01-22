/*
 * libusb example program to list devices on the bus
 * Copyright (C) 2007 Daniel Drake <dsd@gentoo.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <stdio.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <sys/ioctl.h>
#include <linux/hiddev.h>

#include "../libusb/libusb.h"

#include <unistd.h>
#define msleep(msecs) usleep(1000*msecs)

#if !defined(bool)
#define bool int
#endif
#if !defined(true)
#define true (1 == 1)
#endif
#if !defined(false)
#define false (!true)
#endif

#define usb_interface interface

#define ERR_EXIT(errcode) do { fprintf(stderr,"   %s\n", libusb_strerror((enum libusb_error)errcode)); return -1; } while (0)
#define CALL_CHECK(fcall) do { fcall; if (fcall < 0) ERR_EXIT(fcall); } while (0);

// HID Class-Specific Requests values. See section 7.2 of the HID specifications
#define HID_GET_REPORT                0x01
#define HID_GET_IDLE                  0x02
#define HID_GET_PROTOCOL              0x03
#define HID_SET_REPORT                0x09
#define HID_SET_IDLE                  0x0A
#define HID_SET_PROTOCOL              0x0B
//#define HID_REPORT_TYPE_INPUT         0x01
//#define HID_REPORT_TYPE_OUTPUT        0x02
//#define HID_REPORT_TYPE_FEATURE       0x03

///////////////////////////////////////////////////////////////////////////
//an accessory authenticates an ipod cmd define
#define IPODAUTH_ACCESSORY_GET_VERSION _IOR('H',0x120,char) //CP->AC
#define IPODAUTH_ACCESSORY_GET_DEVICEID _IOR('H',0x121,char) //CP->AC
#define IPODAUTH_ACCESSORY_GET_CERTIFICATE_LEN _IOR('H',0x122,char) //CP->AC
#define IPODAUTH_ACCESSORY_GET_CERTIFICATE_DATA _IOR('H',0x123,char) //CP->AC
#define IPODAUTH_ACCESSORY_GET_WAIT_STATUS _IOR('H',0x124,char) //CP->AC
#define IPODAUTH_ACCESSORY_GET_READ_STATUS _IOR('H',0x125,char) //CP->AC
#define IPODAUTH_ACCESSORY_GET_SIGNATURE_LEN _IOR('H',0x126,char) //CP->AC
#define IPODAUTH_ACCESSORY_GET_SIGNATURE_DATA _IOR('H',0x127,char) //CP->AC
#define IPODAUTH_ACCESSORY_GET_MAJORVERSION _IOR('H',0x128,char) //CP->AP
#define IPODAUTH_ACCESSORY_GET_MINORVERSION _IOR('H',0x129,char) //CP->AP
#define IPODAUTH_ACCESSORY_SET_CHALLENGE_LEN _IOW('H',0x12A,char) //AC->CP
#define IPODAUTH_ACCESSORY_SET_CHALLENGE_DATA _IOW('H',0x12B,char) //AC->CP
#define IPODAUTH_ACCESSORY_SET_CONTROL _IOW('H',0x12C,char) //AC->CP

//an ipod authenticates an accessory cmd define
#define IPODAUTH_IPOD_GET_VERSION _IOR('H',0x220,char) //CP->AC
#define IPODAUTH_IPOD_GET_DEVICEID _IOR('H',0x221,char) //CP->AC
#define IPODAUTH_IPOD_GET_WAIT_STATUS _IOR('H',0x222,char) //CP->AC
#define IPODAUTH_IPOD_GET_READ_STATUS _IOR('H',0x223,char) //CP->AC
#define IPODAUTH_IPOD_GET_CHALLENGE_LEN _IOR('H',0x224,char) //CP->AC
#define IPODAUTH_IPOD_GET_CHALLENGE_DATA _IOR('H',0x225,char) //CP->AC
#define IPODAUTH_IPOD_SET_CERTIFICATE_LEN _IOW('H',0x226,char) //AC->CP
#define IPODAUTH_IPOD_SET_CERTIFICATE_DATA _IOW('H',0x227,char) //AC->CP
#define IPODAUTH_IPOD_SET_CONTROL _IOW('H',0x228,char) //AC->CP
#define IPODAUTH_IPOD_SET_SIGNATURE_LEN _IOW('H',0x229,char) //AC->CP
#define IPODAUTH_IPOD_SET_SIGNATURE_DATA _IOW('H',0x22A,char) //AC->CP
#define IPODAUTH_IPOD_SET_CHALLENGE_LEN _IOW('H',0x22B,char) //AC->CP
#define IPODAUTH_IPOD_SET_CHALLENGE_DATA _IOW('H',0x22C,char) //AC->CP
///////////////////////////////////////////////////////////////////////////

static struct libusb_device_handle *devh = NULL;
static int find_open_device(int pid,int vid)
{
	devh = libusb_open_device_with_vid_pid(NULL, pid, vid);
	
	return devh ? 0 : -1;
}

static void display_buffer_hex(unsigned char *buffer, unsigned size)
{
	unsigned i, j, k;

	for (i=0; i<size; i+=16) {
		printf("\n  %08x  ", i);
		for(j=0,k=0; k<16; j++,k++) {
			if (i+j < size) {
				printf("%02x", buffer[i+j]);
			} else {
				printf("  ");
			}
			printf(" ");
		}
		printf(" ");
		for(j=0,k=0; k<16; j++,k++) {
			if (i+j < size) {
				if ((buffer[i+j] < 32) || (buffer[i+j] > 126)) {
					printf(".");
				} else {
					printf("%c", buffer[i+j]);
				}
			}
		}
	}
	printf("\n" );
}

int get_endpoint_form_desc(libusb_device_handle *handle)
{
	struct libusb_config_descriptor *conf_desc;
	libusb_device *dev;
	const struct libusb_endpoint_descriptor *endpoint;
	int r,i,j,k,iface, nb_ifaces, first_iface = -1;
	uint8_t endpoint_in = 0, endpoint_out = 0;  // default IN and OUT endpoints

	if (handle == NULL) {
        fprintf(stderr,"  Failed.\n");
        return -1;
    }

    dev = libusb_get_device(handle);
	
	printf("\nReading first configuration descriptor:\n");
    CALL_CHECK(libusb_get_config_descriptor(dev, 1, &conf_desc));
    nb_ifaces = conf_desc->bNumInterfaces;
    printf("             nb interfaces: %d\n", nb_ifaces);
    if (nb_ifaces > 0) 
        first_iface = conf_desc->usb_interface[0].altsetting[0].bInterfaceNumber;
    for (i=0; i<nb_ifaces; i++) {
        printf("              interface[%d]: id = %d\n", i,
            conf_desc->usb_interface[i].altsetting[0].bInterfaceNumber);
        for (j=0; j<conf_desc->usb_interface[i].num_altsetting; j++) {
            printf("interface[%d].altsetting[%d]: num endpoints = %d\n",
                i, j, conf_desc->usb_interface[i].altsetting[j].bNumEndpoints);
            printf("   Class.SubClass.Protocol: %02X.%02X.%02X\n",
                conf_desc->usb_interface[i].altsetting[j].bInterfaceClass,
                conf_desc->usb_interface[i].altsetting[j].bInterfaceSubClass,
                conf_desc->usb_interface[i].altsetting[j].bInterfaceProtocol);
            
				for (k=0; k<conf_desc->usb_interface[i].altsetting[j].bNumEndpoints; k++) {
                struct libusb_ss_endpoint_companion_descriptor *ep_comp = NULL;
                endpoint = &conf_desc->usb_interface[i].altsetting[j].endpoint[k];
                printf("       endpoint[%d].address: %02X\n", k, endpoint->bEndpointAddress);
                // Use the first interrupt or bulk IN/OUT endpoints as default for testing
                if ((endpoint->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK) & (LIBUSB_TRANSFER_TYPE_BULK | LIBUSB_TRANSFER_TYPE_INTERRUPT)) {
                    if (endpoint->bEndpointAddress & LIBUSB_ENDPOINT_IN) {
                        if (!endpoint_in)
						{
                            endpoint_in = endpoint->bEndpointAddress;
                			printf("               endpoint_in: %02X\n", endpoint_in);
						}
                    } else {
                        if (!endpoint_out)
						{
                            endpoint_out = endpoint->bEndpointAddress;
                			printf("              endpoint_out: %02X\n", endpoint_out);
						}
                    }    
                }    
                printf("           max packet size: %04X\n", endpoint->wMaxPacketSize);
                printf("          polling interval: %02X\n", endpoint->bInterval);
                libusb_get_ss_endpoint_companion_descriptor(NULL, endpoint, &ep_comp);
				if (ep_comp) {
                    printf("                 max burst: %02X   (USB 3.0)\n", ep_comp->bMaxBurst);
                    printf("        bytes per interval: %04X (USB 3.0)\n", ep_comp->wBytesPerInterval);
                    libusb_free_ss_endpoint_companion_descriptor(ep_comp);
                }
            }
        }
	}
    libusb_free_config_descriptor(conf_desc);

	return endpoint_in;
}

// HID
static int get_hid_record_size(uint8_t *hid_report_descriptor, int size, int type)
{
	uint8_t i, j = 0;
	uint8_t offset;
	int record_size[3] = {0, 0, 0};
	int nb_bits = 0, nb_items = 0;
	bool found_record_marker;

	found_record_marker = false;
	for (i = hid_report_descriptor[0]+1; i < size; i += offset) {
		offset = (hid_report_descriptor[i]&0x03) + 1;
		if (offset == 4)
			offset = 5;
		switch (hid_report_descriptor[i] & 0xFC) {
		case 0x74:	// bitsize
			nb_bits = hid_report_descriptor[i+1];
			break;
		case 0x94:	// count
			nb_items = 0;
			for (j=1; j<offset; j++) {
				nb_items = ((uint32_t)hid_report_descriptor[i+j]) << (8*(j-1));
			}
			break;
		case 0x80:	// input
			found_record_marker = true;
			j = 0;
			break;
		case 0x90:	// output
			found_record_marker = true;
			j = 1;
			break;
		case 0xb0:	// feature
			found_record_marker = true;
			j = 2;
			break;
		case 0xC0:	// end of collection
			nb_items = 0;
			nb_bits = 0;
			break;
		default:
			continue;
		}
		if (found_record_marker) {
			found_record_marker = false;
			record_size[j] += nb_items*nb_bits;
		}
	}
	if ((type < HID_REPORT_TYPE_INPUT) || (type > HID_REPORT_TYPE_FEATURE)) {
		return 0;
	} else {
		return (record_size[type - HID_REPORT_TYPE_INPUT]+7)/8;
	}
}

static int test_hid(libusb_device_handle *handle, uint8_t endpoint_in)
{
	int r, size, descriptor_size;
	uint8_t hid_report_descriptor[256];
	uint8_t *report_buffer;
	FILE *fd;

	printf("\nReading HID Report Descriptors:\n");
	descriptor_size = libusb_control_transfer(handle, LIBUSB_ENDPOINT_IN|LIBUSB_REQUEST_TYPE_STANDARD|LIBUSB_RECIPIENT_INTERFACE,
		LIBUSB_REQUEST_GET_DESCRIPTOR, LIBUSB_DT_REPORT<<8, 0, hid_report_descriptor, sizeof(hid_report_descriptor), 1000);
	if (descriptor_size < 0) {
		printf("   Failed\n");
		return -1;
	}
	display_buffer_hex(hid_report_descriptor, descriptor_size);
	
	if (((fd = fopen("/dev/usb/hiddev0", "w")) != NULL)) {
		if (fwrite(hid_report_descriptor, 1, descriptor_size, fd) != descriptor_size) {
			printf("   Error writing descriptor to file\n");
		}
		fclose(fd);
	}else
		printf("Error writing /dev/usb/hiddev0\n");

	size = get_hid_record_size(hid_report_descriptor, descriptor_size, HID_REPORT_TYPE_FEATURE);
	if (size <= 0) {
		printf("\nSkipping Feature Report readout (None detected)\n");
	} else {
		report_buffer = (uint8_t*) calloc(size, 1);
		if (report_buffer == NULL) {
			return -1;
		}

		printf("\nReading Feature Report (length %d)...\n", size);
		r = libusb_control_transfer(handle, LIBUSB_ENDPOINT_IN|LIBUSB_REQUEST_TYPE_CLASS|LIBUSB_RECIPIENT_INTERFACE,
			HID_GET_REPORT, (HID_REPORT_TYPE_FEATURE<<8)|0, 0, report_buffer, (uint16_t)size, 5000);
		if (r >= 0) {
			display_buffer_hex(report_buffer, size);
		} else {
			switch(r) {
			case LIBUSB_ERROR_NOT_FOUND:
				printf("   No Feature Report available for this device\n");
				break;
			case LIBUSB_ERROR_PIPE:
				printf("   Detected stall - resetting pipe...\n");
				libusb_clear_halt(handle, 0);
				break;
			default:
				printf("   Error: %s\n", libusb_strerror((enum libusb_error)r));
				break;
			}
		}
		free(report_buffer);
	}

	size = get_hid_record_size(hid_report_descriptor, descriptor_size, HID_REPORT_TYPE_INPUT);
	if (size <= 0) {
		printf("\nSkipping Input Report readout (None detected)\n");
	} else {
		report_buffer = (uint8_t*) calloc(size, 1);
		if (report_buffer == NULL) {
			return -1;
		}

		printf("\nReading Input Report (length %d)...\n", size);
		r = libusb_control_transfer(handle, LIBUSB_ENDPOINT_IN|LIBUSB_REQUEST_TYPE_CLASS|LIBUSB_RECIPIENT_INTERFACE,
			HID_GET_REPORT, (HID_REPORT_TYPE_INPUT<<8)|0x00, 0, report_buffer, (uint16_t)size, 5000);
		if (r >= 0) {
			display_buffer_hex(report_buffer, size);
		} else {
			switch(r) {
			case LIBUSB_ERROR_TIMEOUT:
				printf("   Timeout! Please make sure you act on the device within the 5 seconds allocated...\n");
				break;
			case LIBUSB_ERROR_PIPE:
				printf("   Detected stall - resetting pipe...\n");
				libusb_clear_halt(handle, 0);
				break;
			default:
				printf("   Error: %s\n", libusb_strerror((enum libusb_error)r));
				break;
			}
		}

		// Attempt a bulk read from endpoint 0 (this should just return a raw input report)
		printf("\nTesting interrupt read using endpoint %02X...\n", endpoint_in);
		r = libusb_interrupt_transfer(handle, endpoint_in, report_buffer, size, &size, 5000);
		if (r >= 0) {
			display_buffer_hex(report_buffer, size);
		} else {
			printf("   %s\n", libusb_strerror((enum libusb_error)r));
		}

		free(report_buffer);
	}
	return 0;
}

static int write_out_report(libusb_device_handle *handle)
{
    int r;
    uint8_t output_report[6];

    printf("\nWrite out Report...\n");

    memset(output_report, 0, sizeof(output_report));
    output_report[1] = sizeof(output_report);
    output_report[2] = 'a';
    output_report[3] = 'b';
    output_report[4] = 'c';
    output_report[6] = 'd';

    r = libusb_control_transfer(handle, LIBUSB_ENDPOINT_OUT|LIBUSB_REQUEST_TYPE_CLASS|LIBUSB_RECIPIENT_INTERFACE,
        HID_SET_REPORT, (HID_REPORT_TYPE_OUTPUT<<8)|0x00, 0, output_report, 06, 1000);
    printf("write_out_report---r=%d\n",r);
	fprintf(stderr, "write_out_report failed: %s\n", libusb_error_name(r));

    return 0;
}

////////////////////////////////////////////////////////////////////////
//ipod device end points
#define IN  0x83
#define INTERFACENUM 2 

static unsigned char getCheckSum(unsigned char *pucData,int nDataLen)
{
	int i;
	unsigned char ucCheckSum = 0;

	for(i= 0;i< nDataLen;i++)
	{
		ucCheckSum += pucData[i];
	}

	ucCheckSum = ~ucCheckSum + 1;

	return ucCheckSum;
}

void Recv_Ret_ipod(libusb_device_handle *handle,unsigned char *buffer_in) {
	int response,i;
	static int transferred;
	unsigned char buf[64];

	transferred = 0;	
	memset(buf,0,sizeof(buf));
	response = libusb_interrupt_transfer(handle, IN, buf, sizeof(buf), &transferred, 3000);
    //response = libusb_bulk_transfer(handle, IN, buffer_in, sizeof(buffer_in), &transferred, 1000);
    if(response < 0){
        fprintf(stderr, "---test---in---failed: response=%d,error:%s\n",response, libusb_error_name(response));
        return;
    }
    else{
        printf("---Done---in---transferred= %d bytes\n", transferred);
        printf("---Done---in---response=%d\n",response);
    }

    printf("Received:\n");

    for(i=0; i<transferred; i++) {
			buffer_in[i] = buf[i];
            printf("0x%02x ", buf[i]);
	}
        printf("\n");
}


int send_RetAccessoryInfo(libusb_device_handle *handle,unsigned char type,unsigned char typeinfo) {
	int response,i;
    static int transferred;
	unsigned char cCheckSum;

    if(NULL == handle) {
        printf("---error-----handle expire\n");
        return -1;
    }
	
	if(0x00 == type) {
		unsigned char tmp[] = {0x07,0x00,0x28,0x00,0x00,0x00,0x00,0xF3};
		cCheckSum = getCheckSum(tmp,sizeof(tmp));
		printf("-------checksum = 0x%02x\n",cCheckSum);

    	unsigned char buffer_out[12] = {0x13,0x00,0x55,0x07,0x00,0x28,0x00,0x00,0x00,0x00,0xF3};
		buffer_out[11] = cCheckSum;

    	printf("--------buffer_out len=%d\n",sizeof(buffer_out));
    	printf("--------buffer_out[]=\n");
    	for(i = 0; i < sizeof(buffer_out); i++)
        	printf("0x%02x ",buffer_out[i]);
    	printf("\n");

    	response = libusb_control_transfer(handle, LIBUSB_ENDPOINT_OUT|LIBUSB_REQUEST_TYPE_CLASS|LIBUSB_RECIPIENT_INTERFACE,
        	HID_SET_REPORT, (HID_REPORT_TYPE_OUTPUT<<8)|INTERFACENUM, INTERFACENUM, buffer_out, sizeof(buffer_out), 1000);
	}else if(0x01 == type) { //accessory name
		unsigned char tmp_1[] = {0x08,0x00,0x28,0x01,'c','a','r','i','t'};
		cCheckSum = getCheckSum(tmp_1,sizeof(tmp_1));
		printf("-------checksum_1 = 0x%02x\n",cCheckSum);

   		unsigned char buffer_out_1[14] = {0x13,0x00,0x55,0x09,0x00,0x28,0x01,'c','a','r','i','t',0x00};
		buffer_out_1[13] = cCheckSum;

    	printf("--------buffer_out_1 len=%d\n",sizeof(buffer_out_1));
    	printf("--------buffer_out_1[]=\n");
    	for(i = 0; i < sizeof(buffer_out_1); i++)
        	printf("0x%02x ",buffer_out_1[i]);
    	printf("\n");

    	response = libusb_control_transfer(handle, LIBUSB_ENDPOINT_OUT|LIBUSB_REQUEST_TYPE_CLASS|LIBUSB_RECIPIENT_INTERFACE,
        	HID_SET_REPORT, (HID_REPORT_TYPE_OUTPUT<<8)|INTERFACENUM, INTERFACENUM, buffer_out_1, sizeof(buffer_out_1), 1000);

	}

    if(response < 0){
        fprintf(stderr, "---test---out---failed: response=%d,error:%s\n",response, libusb_error_name(response));
        return -1;
    }
    else{
        printf("---Done---out---response=%d\n",response);
	}

	return 1;
}

void ipod_auth_cp_get_deviceid(unsigned char buf[],int len) {
	int fd = -1; 
    int ret = -1;

    fd = open("/dev/ipod",O_RDWR);
    if(fd == -1) 
    {   
        fprintf(stderr,"open /dev/ipod failure\n");
        return; 
    }   
	
	memset(buf,0,len);
    ret = ioctl(fd,IPODAUTH_ACCESSORY_GET_DEVICEID,buf);
	if(ret<0)
		printf("-----IPODAUTH_ACCESSORY_GET_DEVICEID---error\n");

	close(fd);
	
	return;
}

void ipod_auth_cp_get_majorversion(unsigned char buf[],int len) {
	int fd = -1; 
    int ret = -1;

    fd = open("/dev/ipod",O_RDWR);
    if(fd == -1) 
    {   
        fprintf(stderr,"open /dev/ipod failure\n");
        return; 
    }   
	
	memset(buf,0,len);
    ret = ioctl(fd,IPODAUTH_ACCESSORY_GET_MAJORVERSION,buf);
	if(ret<0)
		printf("-----IPODAUTH_ACCESSORY_GET_MAJORVERSION---error\n");

	close(fd);
	
	return;
}
void ipod_auth_cp_get_minorversion(unsigned char buf[],int len) {
	int fd = -1; 
    int ret = -1;

    fd = open("/dev/ipod",O_RDWR);
    if(fd == -1) 
    {   
        fprintf(stderr,"open /dev/ipod failure\n");
        return; 
    }   
	
	memset(buf,0,len);
    ret = ioctl(fd,IPODAUTH_ACCESSORY_GET_MINORVERSION,buf);
	if(ret<0)
		printf("-----IPODAUTH_ACCESSORY_GET_MINORVERSION---error\n");

	close(fd);
	
	return;
}
void ipod_auth_cp_get_certificate_len(unsigned char buf[],int len) {
	int fd = -1; 
    int ret = -1;

    fd = open("/dev/ipod",O_RDWR);
    if(fd == -1) 
    {   
        fprintf(stderr,"open /dev/ipod failure\n");
        return; 
    }   
	
    ret = ioctl(fd,IPODAUTH_ACCESSORY_GET_CERTIFICATE_LEN,buf);
	if(ret<0)
		printf("-----IPODAUTH_ACCESSORY_GET_CERTIFICATE_LEN---error\n");

	close(fd);
	
	return;
}

void ipod_auth_cp_get_certificate_data(unsigned char buf[],int len) {
	int fd = -1; 
    int ret = -1;

    fd = open("/dev/ipod",O_RDWR);
    if(fd == -1) 
    {   
        fprintf(stderr,"open /dev/ipod failure\n");
        return; 
    }   
	
    ret = ioctl(fd,IPODAUTH_ACCESSORY_GET_CERTIFICATE_DATA,buf);
	if(ret<0)
		printf("-----IPODAUTH_ACCESSORY_GET_CERTIFICATE_DATA---error\n");

	close(fd);
	
	return;
}

//IPODAUTH_ACCESSORY_SET_CHALLENGE_LEN
void ipod_auth_cp_set_challenge_len(unsigned char clen[],int len) {
	int fd = -1; 
    int ret = -1;

    fd = open("/dev/ipod",O_RDWR);
    if(fd == -1) 
    {   
        fprintf(stderr,"open /dev/ipod failure\n");
        return; 
    }   
	
    ret = ioctl(fd,IPODAUTH_ACCESSORY_SET_CHALLENGE_LEN,clen);
	if(ret<0)
		printf("-----IPODAUTH_ACCESSORY_SET_CHALLENGE_LEN---error\n");

	close(fd);
	
	return;
}

//IPODAUTH_ACCESSORY_SET_CHALLENGE_DATA
void ipod_auth_cp_set_challenge_data(unsigned char buf[],int len) {
	int fd = -1; 
    int ret = -1;
	
    fd = open("/dev/ipod",O_RDWR);
    if(fd == -1) 
    {   
        fprintf(stderr,"open /dev/ipod failure\n");
        return; 
    }   
	
    ret = ioctl(fd,IPODAUTH_ACCESSORY_SET_CHALLENGE_DATA,buf);
	if(ret<0)
		printf("-----IPODAUTH_ACCESSORY_SET_CHALLENGE_DATA---error\n");

	close(fd);
	
	return;
}

void ipod_auth_cp_set_control(unsigned char cControl[],int len) {
	int fd = -1; 
    int ret = -1;

    fd = open("/dev/ipod",O_RDWR);
    if(fd == -1) 
    {   
        fprintf(stderr,"open /dev/ipod failure\n");
        return; 
    }   
	
    ret = ioctl(fd,IPODAUTH_ACCESSORY_SET_CONTROL,cControl);
	if(ret<0)
		printf("-----IPODAUTH_ACCESSORY_SET_CONTROL---error\n");

	close(fd);
	
	return;
}

void ipod_auth_cp_get_read_status(unsigned char cStatus[],int len) {
	int fd = -1; 
    int ret = -1;

    fd = open("/dev/ipod",O_RDWR);
    if(fd == -1) 
    {   
        fprintf(stderr,"open /dev/ipod failure\n");
        return; 
    }   
	
    ret = ioctl(fd,IPODAUTH_ACCESSORY_GET_READ_STATUS,cStatus);
	if(ret<0)
		printf("-----IPODAUTH_ACCESSORY_GET_READ_STATUS---error\n");

	close(fd);
	
	return;
}

void ipod_auth_cp_get_signature_len(unsigned char buf[],int len) {
	int fd = -1; 
    int ret = -1;

    fd = open("/dev/ipod",O_RDWR);
    if(fd == -1) 
    {   
        fprintf(stderr,"open /dev/ipod failure\n");
        return; 
    }   
	
    ret = ioctl(fd,IPODAUTH_ACCESSORY_GET_SIGNATURE_LEN,buf);
	if(ret<0)
		printf("-----IPODAUTH_ACCESSORY_GET_SIGNATURE_LEN---error\n");

	close(fd);
	
	return;
}

void ipod_auth_cp_get_signature_data(unsigned char buf[],int len) {
	int fd = -1; 
    int ret = -1;

    fd = open("/dev/ipod",O_RDWR);
    if(fd == -1) 
    {   
        fprintf(stderr,"open /dev/ipod failure\n");
        return; 
    }   
	
    ret = ioctl(fd,IPODAUTH_ACCESSORY_GET_SIGNATURE_DATA,buf);
	if(ret<0)
		printf("-----IPODAUTH_ACCESSORY_GET_SIGNATURE_DATA---error\n");

	close(fd);
	
	return;
}

int send_RetDevAuthenticationsignature(libusb_device_handle *handle,unsigned char csig[],unsigned char siglen[]) {
	int ilen = 0,i,j;
	unsigned char clen[2];
	unsigned char cStatus[1];
	unsigned char data[128];
	unsigned char cControl[1];

	ipod_auth_cp_set_challenge_len(siglen,1);
	ipod_auth_cp_set_challenge_data(csig,20);

	memset(cControl,0,sizeof(cControl));
	cControl[0] = 0x01; //1-Start new signature-generation process
	ipod_auth_cp_set_control(cControl,1);
	
	//wait CP to finish processing
	while(1) {
		sleep(1);	
		memset(cStatus,0,sizeof(cStatus));
		ipod_auth_cp_get_read_status(cStatus,1);
		printf("--------cStatus = 0x%02x\n",cStatus[0]);
		if( 0x10 == cStatus[0])
			break;
	} //while(1)


	memset(clen,0,sizeof(clen));
	ipod_auth_cp_get_signature_len(clen,sizeof(clen));
	printf("------clen[0] = 0x%02x\n",clen[0]);
	printf("------clen[1] = 0x%02x\n",clen[1]);
	
	ilen = ((unsigned char)clen[0] << 8) | (unsigned char)clen[1];
	printf("------ilen = 0x%02x\n",ilen);

	unsigned char tmp[160];
	unsigned char buffer_out[160];
	unsigned char cCheckSum;
	unsigned char buffer_in[32];
	int n = 0,response = 0;	

first:
		memset(data,0,sizeof(data));
		data[0] = 0x12;
		ipod_auth_cp_get_signature_data(data,ilen);

		//printf("------data[%d] = \n",ilen);
		//for(j = 0; j < sizeof(data); j++)
		//	printf("0x%02x ",data[j]);
		//printf("\n-----------------------------------\n");
		
		memset(tmp,0,sizeof(tmp));
		tmp[0] = (unsigned char)(ilen + 2); 
		tmp[1] = 0x00; 
		tmp[2] = 0x18; 

		for(n = 0; n < ilen; n++)
			tmp[n+3] = data[n];

		cCheckSum = getCheckSum(tmp,(ilen + 3));
		printf("----buffer_out---checksum = 0x%02x\n",cCheckSum);
	
		memset(buffer_out,0,sizeof(buffer_out));
		buffer_out[0] = 0x15; 
		buffer_out[1] = 0x00;
		buffer_out[2] = 0x55;

		for(j = 0; j< (ilen + 3); j++)
			buffer_out[j+3] = tmp[j];

		buffer_out[ilen + 3 + 4 - 1] = cCheckSum;

	retry:
		printf("--------buffer_out len=%d\n",(ilen + 3 + 4));
		printf("--------buffer_out[]=\n");
		for(j = 0; j < (ilen + 3 + 4); j++)
			printf("0x%02x ",buffer_out[j]);
		printf("\n");

		response = libusb_control_transfer(handle, LIBUSB_ENDPOINT_OUT|LIBUSB_REQUEST_TYPE_CLASS|LIBUSB_RECIPIENT_INTERFACE,
        	HID_SET_REPORT, (HID_REPORT_TYPE_OUTPUT<<8)|INTERFACENUM, INTERFACENUM, buffer_out, (ilen + 3 + 4), 5000);
    	if(response < 0){
			fprintf(stderr, "---test---out---failed: response=%d,error:%s\n",response, libusb_error_name(response));
        	return -1;
    	}	
	    else{
			printf("---Done---out---response=%d\n",response);
    	}
		
		while(1) {	
			//Receive back device response
			sleep(1);
    		memset(buffer_in, 0x0, sizeof(buffer_in));
			Recv_Ret_ipod(handle,buffer_in);
			if( 0x02 == buffer_in[5] && 0x00 == buffer_in[6]) {
		
			}else if( 0x19 == buffer_in[5] && 0x00 == buffer_in[6]) {
				printf("---------###########-------success\n");	
				break;
			}
		}
	return 1;	
}

int send_RetDevAuthenticationInfo(libusb_device_handle *handle) {
	int ilen = 0,inum = 0,iremainder = 0,i,j;
	unsigned char clen[2];
	unsigned char data[128];

	memset(clen,0,sizeof(clen));
	ipod_auth_cp_get_certificate_len(clen,sizeof(clen));
	printf("------clen[0] = 0x%02x\n",clen[0]);
	printf("------clen[1] = 0x%02x\n",clen[1]);

	ilen = ((unsigned char)clen[0] << 8) | (unsigned char)clen[1];
	printf("------ilen = 0x%02x\n",ilen);

	inum = ilen / 128;
	printf("------inum = %d\n",inum);

	iremainder = ilen % 128;
	printf("------iremainder = %d\n",iremainder);

	unsigned char tmp[135];
	unsigned char buffer_out[139];
	unsigned char cCheckSum;
	unsigned char buffer_in[32];
	int n = 0,response = 0;	

	for(i = 0; i < inum; i++) {
first:
		memset(data,0,sizeof(data));
		data[0] = 0x31 + i;
		ipod_auth_cp_get_certificate_data(data,sizeof(data));

		//printf("------data[%d][128] = \n",i);
		//for(j = 0; j < sizeof(data); j++)
		//	printf("0x%02x ",data[j]);
		//printf("\n-----------------------------------\n");
		
		tmp[0] = 0x86; 
		tmp[1] = 0x00; 
		tmp[2] = 0x15; 
		tmp[3] = 0x02; 
		tmp[4] = 0x00; 
	
		tmp[5] = i; 
		if(iremainder > 0)
			tmp[6] = inum; 
		else
			tmp[6] = inum;

		for(n = 0; n < 128; n++)
			tmp[n+7] = data[n];

		cCheckSum = getCheckSum(tmp,sizeof(tmp));
		printf("----buffer_out---checksum = 0x%02x\n",cCheckSum);
	
		buffer_out[0] = 0x15; 
		if(0 == i) {
			buffer_out[1] = 0x02;
		} else {
			if(iremainder > 0 ) {//iremainder > 0 ->have a pack at last
				buffer_out[1] = 0x03;
			}else
				buffer_out[1] = 0x01; //last pack now
		}
		buffer_out[2] = 0x55;

		for(j = 0; j< 135; j++)
			buffer_out[j+3] = tmp[j];

		buffer_out[138] = cCheckSum;

	retry:
		printf("--------buffer_out len=%d\n",sizeof(buffer_out));
		printf("--------buffer_out[]=\n");
		for(j = 0; j < sizeof(buffer_out); j++)
			printf("0x%02x ",buffer_out[j]);
		printf("\n");

		response = libusb_control_transfer(handle, LIBUSB_ENDPOINT_OUT|LIBUSB_REQUEST_TYPE_CLASS|LIBUSB_RECIPIENT_INTERFACE,
        	HID_SET_REPORT, (HID_REPORT_TYPE_OUTPUT<<8)|INTERFACENUM, INTERFACENUM, buffer_out, sizeof(buffer_out), 5000);
    	if(response < 0){
			fprintf(stderr, "---test---out---failed: response=%d,error:%s\n",response, libusb_error_name(response));
        	return -1;
    	}	
	    else{
			printf("---Done---out---response=%d\n",response);
    	}
	
		//Receive back device response
		sleep(1);
    	memset(buffer_in, 0x0, sizeof(buffer_in));
		Recv_Ret_ipod(handle,buffer_in);
		if( 0x02 == buffer_in[5] && 0x00 == buffer_in[6]) {
		
		}else if( 0x14 == buffer_in[5]) {
	   		i = 0;
			goto first;	
		}else {
			printf("--------------wait ACK error\n");
			sleep(1);
			goto retry;
		}
	
	} //for(;;)

	if(iremainder > 0) {
		int k;
		unsigned char cremainder[128];

		printf("---------iremainder > 0-------iremainder = %d\n",iremainder);

		memset(cremainder,0,sizeof(cremainder));
		
		cremainder[0] = 0x31 + inum;
		ipod_auth_cp_get_certificate_data(cremainder,iremainder);
		//printf("------cremainder[%d] = \n",iremainder);
		//for(k = 0; k < iremainder; k++)
		//	printf("0x%02x ",cremainder[k]);
		//printf("\n-----------------------------------\n");

		unsigned char ctmp[128];
		memset(ctmp,0,sizeof(ctmp));
		ctmp[0] = (unsigned char)(iremainder + 6);
		ctmp[1] = 0x00; 
		ctmp[2] = 0x15; 
		ctmp[3] = 0x02; 
		ctmp[4] = 0x00; 
	
		ctmp[5] = inum; 
		ctmp[6] = inum; 

		for(n = 0; n < iremainder; n++)
			ctmp[n+7] = cremainder[n];

		//printf("------ctmp[%d] = \n",(iremainder + 7));
		//for(k = 0; k < (iremainder + 7); k++)
		//	printf("0x%02x ",ctmp[k]);
		//printf("\n-----------------------------------\n");
		
		cCheckSum = getCheckSum(ctmp,(iremainder + 7));
		printf("----buffer---checksum = 0x%02x\n",cCheckSum);

		unsigned char cbuffer[128];
		memset(cbuffer,0,strlen(cbuffer));
		cbuffer[0] = 0x15; 
		cbuffer[1] = 0x01; //last pack now
		cbuffer[2] = 0x55;

		for(j = 0; j< (iremainder + 7); j++)
			cbuffer[j+3] = ctmp[j];

		cbuffer[iremainder + 7 + 4 -1] = cCheckSum;

		printf("--------cbuffer---len=%d\n",(iremainder + 7 + 4));
		printf("--------cbuffer[]=\n");
		for(j = 0; j < (iremainder + 7 + 4); j++)
			printf("0x%02x ",cbuffer[j]);
		printf("\n");

		response = libusb_control_transfer(handle, LIBUSB_ENDPOINT_OUT|LIBUSB_REQUEST_TYPE_CLASS|LIBUSB_RECIPIENT_INTERFACE,
        	HID_SET_REPORT, (HID_REPORT_TYPE_OUTPUT<<8)|INTERFACENUM, INTERFACENUM, cbuffer, (iremainder + 7 + 4), 5000);
    	if(response < 0){
			fprintf(stderr, "---test---out---failed: response=%d,error:%s\n",response, libusb_error_name(response));
        	return -1;
    	}	
	    else{
			printf("---Done---out---response=%d\n",response);
    	}
	
		while(1) {
			sleep(1);
    		memset(buffer_in, 0x0, sizeof(buffer_in));
			Recv_Ret_ipod(handle,buffer_in);
			if( 0x02 == buffer_in[5] && 0x00 == buffer_in[6]) {
			
			}else if( 0x16 == buffer_in[5]) {
				if( 0x00 == buffer_in[6])
					printf("------0x16------auth info is supported\n");
				if( 0x08 == buffer_in[6])
					printf("------0x16------auth info is not supported\n");
				if( 0x0a == buffer_in[6])
					printf("------0x16------certificate is invalid\n");
				if( 0x0b == buffer_in[6])
					printf("------0x16------certificate permissions are invalid\n");
			}else if( 0x14 == buffer_in[5]) {
				printf("------------------0x14\n");
				i = 0;
				goto first;
			}else if( 0x19 == buffer_in[5]) {
				printf("------------------0x19\n");
				break;
			}else if( 0x17 == buffer_in[5]) {
				printf("------------------0x17\n");
				unsigned char csig[20];
				unsigned char csiglen[2];

				memset(csig,0,sizeof(csig));
			 	for(j = 0; j< 26; j++)ls
					
					csig[j] = buffer_in[j+6];
				printf("-------csig[20] = \n");
				for(j = 0; j< 20; j++)		
					printf("0x%02x ",csig[j]);
				printf("\n");
				
				memset(csiglen,0,sizeof(csiglen));
				csiglen[0] = 0x00;
				csiglen[1] = 0x14;
				send_RetDevAuthenticationsignature(devh,csig,csiglen);
				break;
			}
		}
	}
	
	return 1;
}
void test(libusb_device_handle *handle) {
	int response,i;
	static int transferred;
	unsigned char cCheckSum;

	if(NULL == handle) {
        printf("---error-----handle expire\n");
		return;
	}
        
	unsigned char deviceid[4];
	memset(deviceid,0,sizeof(deviceid));
	ipod_auth_cp_get_deviceid(deviceid,sizeof(deviceid));
	
	unsigned char tmp[] = {0x0E,0x00,0x13,0x00,0x00,0x00,0x05,0x00,0x00,0x00,0x06,deviceid[0],deviceid[1],deviceid[2],deviceid[3]};
	cCheckSum = getCheckSum(tmp,sizeof(tmp));
	printf("----buffer_out---checksum = 0x%02x\n",cCheckSum);
	
	unsigned char buffer_out[19]={0x13,0x00,0x55,0x0E,0x00,0x13,0x00,0x00,0x00,0x05,0x00,0x00,0x00,0x06,deviceid[0],deviceid[1],deviceid[2],deviceid[3]};
	buffer_out[18] = cCheckSum;
	printf("--------buffer_out len=%d\n",sizeof(buffer_out));
	printf("--------buffer_out[]=\n");
	for(i = 0; i < sizeof(buffer_out); i++)
		printf("0x%02x ",buffer_out[i]);
	printf("\n");
	
	response = libusb_control_transfer(handle, LIBUSB_ENDPOINT_OUT|LIBUSB_REQUEST_TYPE_CLASS|LIBUSB_RECIPIENT_INTERFACE,
        HID_SET_REPORT, (HID_REPORT_TYPE_OUTPUT<<8)|INTERFACENUM, INTERFACENUM, buffer_out, sizeof(buffer_out), 1000);

    //response = libusb_control_transfer(handle, LIBUSB_ENDPOINT_OUT|LIBUSB_REQUEST_TYPE_CLASS|LIBUSB_RECIPIENT_INTERFACE,
    //    0x09, 0x0211, 0x0002, buffer, sizeof(buffer), 1000);
	
    if(response < 0){
		fprintf(stderr, "---test---out---failed: response=%d,error:%s\n",response, libusb_error_name(response));
        //printf("---error, transferred %i bytes\n", transferred);
        return;
    }
    else{
        //printf("---Done---out---transferred= %d bytes\n", transferred);
		printf("---Done---out---response=%d\n",response);
    }
	
	sleep(2);
	//Receive back device response
	unsigned char buffer_in[64];
    
	memset(buffer_in, 0x0, sizeof(buffer_in));
	Recv_Ret_ipod(handle,buffer_in);

	sleep(2);
	memset(buffer_in, 0x0, sizeof(buffer_in));
	Recv_Ret_ipod(handle,buffer_in);

	#if 0
	while(1) {
		if( 0x27 == buffer_in[5]){
			send_RetAccessoryInfo(handle,buffer_in[6],buffer_in[7]);
		}else
			break;
	
		sleep(1);
		memset(buffer_in, 0x0, sizeof(buffer_in));
		Recv_Ret_ipod(handle,buffer_in);
	}
	#endif

	//sleep(1);
	//memset(buffer_in, 0x0, sizeof(buffer_in));
	//Recv_Ret_ipod(handle,buffer_in);

	send_RetDevAuthenticationInfo(devh);
}
////////////////////////////////////////////////////////////////////////


int main(void)
{
	int r,k;
	int *config;

	r = libusb_init(NULL);
	if (r < 0)
		return r;
	
	libusb_set_debug(NULL,LIBUSB_LOG_LEVEL_DEBUG); //set debug level
	
	k = 0;
	r = find_open_device(0x05ac,0x1266);
	if(r < 0) {
		fprintf(stderr, "Could not find or open device(vid=0x05ac,pid=0x1266)\n");
		//libusb_exit(NULL);
		//return r;
		k = 1;
	}

	if( 1 == k ) {
		r = find_open_device(0x05ac,0x12a8);
		if(r < 0) {
			fprintf(stderr, "Could not find or open device(vid=0x05ac,pid=0x12ac)\n");
			libusb_exit(NULL);
			return r;
		}
	}

	//fix bug:libusb_claim_interface failed: LIBUSB_ERROR_BUSY
	if(libusb_kernel_driver_active(devh, INTERFACENUM) == 1) //driver already active in kernel 
	{       
    	printf("------------libusb_kernel_driver_active\n");
		if(libusb_detach_kernel_driver(devh, INTERFACENUM) == 0) //need to detach the driver
		{
    		printf("------------libusb_idetach_driver\n");
		}  
	}

	r = libusb_claim_interface(devh, INTERFACENUM);
    if (r < 0) {
		fprintf(stderr, "libusb_claim_interface failed: %s\n", libusb_error_name(r));
		libusb_close(devh);
		libusb_exit(NULL);
        return r;
    }
    printf("claimed interface success\n");

	//r = get_endpoint_form_desc(devh);
    //printf("------------r=%2x\n",r);
	//test_hid(devh,r);
	
	test(devh);
	//send_RetDevAuthenticationInfo(devh);

	#if 0
	unsigned char csig[20] = {0x90,0x04,0x40,0xdd,0xef,0xc3,0xbe,0x49,0xc8,0x31,0x87,0x35,0x29,0xc4,0x2f,0x6e,0x33,0xdd,0x0b,0xff};
	unsigned char clen[2];

	memset(clen,0,sizeof(clen));
	clen[0] = 0x00;
	clen[1] = 0x14;
	send_RetDevAuthenticationsignature(devh,csig,clen);
	#endif

	#if 0
	unsigned char cmajor[1];
	unsigned char cminor[1];
	
	ipod_auth_cp_get_majorversion(cmajor,sizeof(cmajor));
	printf("--------------cmajor[0] = 0x%02x\n",cmajor[0]);
	ipod_auth_cp_get_minorversion(cminor,sizeof(cminor));
	printf("--------------cminor[0] = 0x%02x\n",cminor[0]);

	unsigned char buf[128];
	int i = 0;

	memset(buf,0,sizeof(buf));
	buf[0] = 0x31;
	ipod_auth_cp_get_certificate_data(buf,sizeof(buf));
	printf("--------------cminor[0] = 0x%02x\n",cminor[0]);
	for(i = 0 ;i < sizeof(buf); i++)
		printf("0x%02x ",buf[i]);	
	#endif

	libusb_release_interface(devh, INTERFACENUM);

	libusb_close(devh);
	libusb_exit(NULL);

	return 0;
}


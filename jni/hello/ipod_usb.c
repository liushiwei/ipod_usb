#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <assert.h>

#include<android/log.h>
#include "jni.h"

#include "CARIT_Type.h"
#include "libusb.h"
#define LOG_TAG "IPOD_USB"

#define LOGI(fmt, args...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, fmt, ##args)
#define LOGD(fmt, args...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##args)
#define LOGE(fmt, args...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, fmt, ##args)

#define USB_DEBUG
#ifdef USB_DEBUG
#define USB_Printf LOGE
#else
#define USB_Printf
#endif

#define HID_GET_REPORT                0x01
#define HID_GET_IDLE                  0x02
#define HID_GET_PROTOCOL              0x03
#define HID_SET_REPORT                0x09
#define HID_SET_IDLE                  0x0A
#define HID_SET_PROTOCOL              0x0B
#define HID_REPORT_TYPE_INPUT         0x01
#define HID_REPORT_TYPE_OUTPUT        0x02
#define HID_REPORT_TYPE_FEATURE       0x03


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

#define IPODAUTH_ACCESSORY_GET_VERSION_ 0x120 //CP->AC
#define IPODAUTH_ACCESSORY_GET_DEVICEID_ 0x121 //CP->AC
#define IPODAUTH_ACCESSORY_GET_CERTIFICATE_LEN_ 0x122 //CP->AC
#define IPODAUTH_ACCESSORY_GET_CERTIFICATE_DATA_ 0x123 //CP->AC
#define IPODAUTH_ACCESSORY_GET_WAIT_STATUS_ 0x124 //CP->AC
#define IPODAUTH_ACCESSORY_GET_READ_STATUS_ 0x125 //CP->AC
#define IPODAUTH_ACCESSORY_GET_SIGNATURE_LEN_ 0x126 //CP->AC
#define IPODAUTH_ACCESSORY_GET_SIGNATURE_DATA_ 0x127 //CP->AC
#define IPODAUTH_ACCESSORY_GET_MAJORVERSION_ 0x128 //CP->AP
#define IPODAUTH_ACCESSORY_GET_MINORVERSION_ 0x129 //CP->AP
#define IPODAUTH_ACCESSORY_SET_CHALLENGE_LEN_ 0x12A //AC->CP
#define IPODAUTH_ACCESSORY_SET_CHALLENGE_DATA_ 0x12B //AC->CP
#define IPODAUTH_ACCESSORY_SET_CONTROL_ 0x12C //AC->CP

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

#define CLASS_PATH_NAME "com/my/ipod/hardware/IpodUsb";

static struct libusb_device_handle* g_device_handle = NULL;
static int g_device_fd = -1;
static libusb_context* g_usb_ctx = NULL;
static CARIT_S32 usb_readData(CARIT_U8* pData, CARIT_S32 len)
{
	CARIT_S32 ret = 0;
	int actual_len = 0;
	if(NULL == g_device_handle)
	{
		LOGE("[%s] >> phone device not open!", __FUNCTION__);
		return CARIT_FAIL;
	}
	ret = libusb_interrupt_transfer(g_device_handle, 0x83, pData, len, &actual_len, 5000);
	if(ret < 0)
	{
		LOGE("[%s] >> read data error! ret = %d", __FUNCTION__, ret);
		return CARIT_FAIL;
	}
#if 1
	int iNum = 0;
	LOGE("[%s] >> begin. actual_len = %d", __FUNCTION__, actual_len);
	for(iNum = 0; iNum < actual_len; iNum++)
	{
		LOGE(" <[%d] = 0x%x  ", iNum, pData[iNum]);
	}
	LOGE("[%s] >> endle.", __FUNCTION__);
#endif
	return actual_len;
}

static CARIT_S32 usb_writeData(CARIT_U8* pData, CARIT_S32 len)
{
	CARIT_S32 ret = 0;
	if(NULL == g_device_handle)
	{
		LOGE("[%s] >> phone device not open", __FUNCTION__);
		return CARIT_FAIL;
	}
	#if 1
	int iNum = 0;
	LOGE("[%s] >> begin. actual_len = %d", __FUNCTION__,len);
	for(iNum = 0; iNum < len; iNum++)
	{
		LOGE(" >[%d] = 0x%x  ", iNum, pData[iNum]);
	}
	LOGE("[%s] >> endle.", __FUNCTION__);
	LOGE("[%s] >> libusb_control_transfer request type = %d .", __FUNCTION__,LIBUSB_ENDPOINT_OUT|LIBUSB_REQUEST_TYPE_CLASS|LIBUSB_RECIPIENT_INTERFACE);
	LOGE("[%s] >> libusb_control_transfer request = %d .", __FUNCTION__,HID_SET_REPORT);
	LOGE("[%s] >> libusb_control_transfer value= %d .", __FUNCTION__,(HID_REPORT_TYPE_OUTPUT<<8)|2);
	LOGE("[%s] >> libusb_control_transfer index= %d .", __FUNCTION__,2);
	#endif
	ret = libusb_control_transfer(g_device_handle, LIBUSB_ENDPOINT_OUT|LIBUSB_REQUEST_TYPE_CLASS|LIBUSB_RECIPIENT_INTERFACE,
	        HID_SET_REPORT, (HID_REPORT_TYPE_OUTPUT<<8)|2, 2, pData, len, 1000);
	if(ret < 0)
	{
		LOGE("[%s] >> send data error. ret = %d.", __FUNCTION__, ret);
		return CARIT_FAIL;
	}
	LOGE("[%s] send data success ret = %d.", __FUNCTION__, ret);
	return ret;
}

static CARIT_U8 phone_getChecksum(CARIT_U8* buffer, CARIT_S32 len)
{
	CARIT_S32 i = 0;
	CARIT_U8 checksum = 0;
	for(i = 0; i < len; i++)
	{
		checksum += buffer[i];
	}
	checksum = ~checksum + 1;
	return checksum;
}

CARIT_U8 check_sum(JNIEnv *env, jclass clazz,jbyteArray array,jint offset,jint length)
{
	CARIT_U8 buffer[256];
	(*env)->GetByteArrayRegion(env,array,offset, length, buffer);
	CARIT_U8 sum = phone_getChecksum(buffer,length);
	//LOGE("[%s] checksum = 0x%x", __FUNCTION__, sum);
	return sum;
}

CARIT_S32 open_iic(JNIEnv *env, jclass clazz)
{
	g_device_fd = open("/dev/ipod",O_RDWR);
	USB_Printf("[%s] >> open ipod device", __FUNCTION__);
	if(g_device_fd < 0)
	{
		USB_Printf("[%s] >> open ipod device fail", __FUNCTION__);
		close(g_device_fd);
		return -1;
	}
	return g_device_fd;
}

CARIT_S32 close_iic(JNIEnv *env, jclass clazz,jint file_id)
{
	
	close(file_id);
	return g_device_fd;
}


CARIT_S32 ioctl_write_(JNIEnv *env, jclass clazz,jint file_id,jint cmd,jbyteArray array,jint length)
{
	CARIT_U8 buffer[256];
	(*env)->GetByteArrayRegion(env,array,0, length, buffer);
	
	int iNum = 0;
	LOGE("[%s] >> ioctl_write. get length = %d", __FUNCTION__, length);
	for(iNum = 0; iNum < length; iNum++)
	{
		LOGE(" <[%d] = 0x%x  ", iNum, buffer[iNum]);
	}
	LOGE("[%s] >> endle.", __FUNCTION__);
	g_device_fd = file_id;
	USB_Printf("[%s] >> open ipod device", __FUNCTION__);
	if(g_device_fd < 0)
	{
		USB_Printf("[%s] >> open ipod device fail", __FUNCTION__);
		
		return -1;
	}
	
	switch(cmd){
		case IPODAUTH_ACCESSORY_SET_CHALLENGE_LEN_:
			
			if(ioctl(g_device_fd,IPODAUTH_ACCESSORY_SET_CHALLENGE_LEN,buffer) < 0)
			{
				LOGE("[%s] >> get device id error.", __FUNCTION__);
				
				return -1;
			}
			break;
		case IPODAUTH_ACCESSORY_SET_CHALLENGE_DATA_:
			//memcpy(&aSign[0], &buffer[0], 20);
			if(ioctl(g_device_fd,IPODAUTH_ACCESSORY_SET_CHALLENGE_DATA,buffer) < 0)
			{
				LOGE("[%s] >>>>> set challenge data error.", __FUNCTION__);
				
				return -1;
			}
			break;
		case IPODAUTH_ACCESSORY_SET_CONTROL_:
			
			if(ioctl(g_device_fd,IPODAUTH_ACCESSORY_SET_CONTROL,buffer) < 0)
			{
				LOGE("[%s] >>>>> set control error.", __FUNCTION__);
				
				return -1;
			}
			break;
	}

	
	return 0;
}


CARIT_S32 ioctl_write(JNIEnv *env, jclass clazz,jint cmd,jbyteArray array,jint length)
{
	CARIT_U8 buffer[256];
	(*env)->GetByteArrayRegion(env,array,0, length, buffer);
	
	//int iNum = 0;
	//LOGE("[%s] >> ioctl_write. get length = %d", __FUNCTION__, length);
	//for(iNum = 0; iNum < length; iNum++)
	//{
	//	LOGE(" <[%d] = 0x%x  ", iNum, buffer[iNum]);
	//}
	//OGE("[%s] >> endle.", __FUNCTION__);
	g_device_fd = open("/dev/ipod",O_RDWR);
	//USB_Printf("[%s] >> open ipod device", __FUNCTION__);
	if(g_device_fd < 0)
	{
		USB_Printf("[%s] >> open ipod device fail", __FUNCTION__);
		close(g_device_fd);
		return -1;
	}
	
	switch(cmd){
		case IPODAUTH_ACCESSORY_SET_CHALLENGE_LEN_:
			
			if(ioctl(g_device_fd,IPODAUTH_ACCESSORY_SET_CHALLENGE_LEN,buffer) < 0)
			{
				LOGE("[%s] >> get device id error.", __FUNCTION__);
				close(g_device_fd);
				return -1;
			}
			break;
		case IPODAUTH_ACCESSORY_SET_CHALLENGE_DATA_:
			//memcpy(&aSign[0], &buffer[0], 20);
			if(ioctl(g_device_fd,IPODAUTH_ACCESSORY_SET_CHALLENGE_DATA,buffer) < 0)
			{
				LOGE("[%s] >>>>> set challenge data error.", __FUNCTION__);
				close(g_device_fd);
				return -1;
			}
			break;
		case IPODAUTH_ACCESSORY_SET_CONTROL_:
			
			if(ioctl(g_device_fd,IPODAUTH_ACCESSORY_SET_CONTROL,buffer) < 0)
			{
				LOGE("[%s] >>>>> set control error.", __FUNCTION__);
				close(g_device_fd);
				return -1;
			}
			break;
	}

	close(g_device_fd);
	return 0;
}

JNIEXPORT jbyteArray ioctl_read(JNIEnv *env, jclass clazz,jint cmd,jbyteArray array,jint length)
{
	g_device_fd = open("/dev/ipod",O_RDWR);
	//USB_Printf("[%s] >> open ipod device", __FUNCTION__);
	if(g_device_fd < 0)
	{
		USB_Printf("[%s] >> open ipod device fail", __FUNCTION__);
		return -1;
	}
	CARIT_U8 buffer[256] = {0};
	(*env)->GetByteArrayRegion(env,array,0, length, buffer);
	switch(cmd){
		case IPODAUTH_ACCESSORY_GET_DEVICEID_:
			length = 4;
			if(ioctl(g_device_fd,IPODAUTH_ACCESSORY_GET_DEVICEID,buffer) < 0)
			{
				LOGE("[%s] >> get device id error.", __FUNCTION__);
				return -1;
			}
			break;
		case IPODAUTH_ACCESSORY_GET_CERTIFICATE_LEN_:
			length = 2;
			if(ioctl(g_device_fd,IPODAUTH_ACCESSORY_GET_CERTIFICATE_LEN,buffer) < 0)
			{
				LOGE("[%s] >> get device id error.", __FUNCTION__);
				return -1;
			}
			break;
		case IPODAUTH_ACCESSORY_GET_CERTIFICATE_DATA_:
			length = 128;
			if(ioctl(g_device_fd,IPODAUTH_ACCESSORY_GET_CERTIFICATE_DATA,buffer) < 0)
			{
				LOGE("[%s] >> get device id error.", __FUNCTION__);
				return -1;
			}
			break;
		case IPODAUTH_ACCESSORY_GET_READ_STATUS_:
			length = 1;
			if(ioctl(g_device_fd,IPODAUTH_ACCESSORY_GET_READ_STATUS,buffer) < 0)
			{
				LOGE("[%s] >> get device id error.", __FUNCTION__);
				return -1;
			}
			break;
			
		case IPODAUTH_ACCESSORY_GET_SIGNATURE_LEN_:
			length = 2;
			if(ioctl(g_device_fd,IPODAUTH_ACCESSORY_GET_SIGNATURE_LEN,buffer) < 0)
			{
				LOGE("[%s] >> get device id error.", __FUNCTION__);
				return -1;
			}
			break;
		case IPODAUTH_ACCESSORY_GET_SIGNATURE_DATA_:
			length = 128;
			if(ioctl(g_device_fd,IPODAUTH_ACCESSORY_GET_SIGNATURE_DATA,buffer) < 0)
			{
				LOGE("[%s] >> get device id error.", __FUNCTION__);
				return -1;
			}
			break;
	}
	
	//int iNum = 0;
	//LOGE("[%s] >> begin. actual_len = %d", __FUNCTION__, length);
	//for(iNum = 0; iNum < length; iNum++)
	//{
	//	LOGE(" <[%d] = 0x%x  ", iNum, buffer[iNum]);
	//	buffer[iNum];
	//}
	//LOGE("[%s] >> endle.", __FUNCTION__);
	jbyteArray array_ =  (*env)->NewByteArray(env, length);
	(*env)->SetByteArrayRegion(env,array_, 0, length, buffer);
	close(g_device_fd);
	return array_;
		
}

JNIEXPORT jbyteArray ioctl_read_(JNIEnv *env, jclass clazz,jint file_id,jint cmd,jbyteArray array,jint length)
{
	g_device_fd = file_id;
	USB_Printf("[%s] >> open ipod device", __FUNCTION__);
	if(g_device_fd < 0)
	{
		USB_Printf("[%s] >> open ipod device fail", __FUNCTION__);
		return -1;
	}
	CARIT_U8 buffer[256] = {0};
	(*env)->GetByteArrayRegion(env,array,0, length, buffer);
	switch(cmd){
		case IPODAUTH_ACCESSORY_GET_DEVICEID_:
			length = 4;
			if(ioctl(g_device_fd,IPODAUTH_ACCESSORY_GET_DEVICEID,buffer) < 0)
			{
				LOGE("[%s] >> get device id error.", __FUNCTION__);
				return -1;
			}
			break;
		case IPODAUTH_ACCESSORY_GET_CERTIFICATE_LEN_:
			length = 2;
			if(ioctl(g_device_fd,IPODAUTH_ACCESSORY_GET_CERTIFICATE_LEN,buffer) < 0)
			{
				LOGE("[%s] >> get device id error.", __FUNCTION__);
				return -1;
			}
			break;
		case IPODAUTH_ACCESSORY_GET_CERTIFICATE_DATA_:
			length = 128;
			if(ioctl(g_device_fd,IPODAUTH_ACCESSORY_GET_CERTIFICATE_DATA,buffer) < 0)
			{
				LOGE("[%s] >> get device id error.", __FUNCTION__);
				return -1;
			}
			break;
		case IPODAUTH_ACCESSORY_GET_READ_STATUS_:
			length = 1;
			if(ioctl(g_device_fd,IPODAUTH_ACCESSORY_GET_READ_STATUS,buffer) < 0)
			{
				LOGE("[%s] >> get device id error.", __FUNCTION__);
				return -1;
			}
			break;
			
		case IPODAUTH_ACCESSORY_GET_SIGNATURE_LEN_:
			length = 2;
			if(ioctl(g_device_fd,IPODAUTH_ACCESSORY_GET_SIGNATURE_LEN,buffer) < 0)
			{
				LOGE("[%s] >> get device id error.", __FUNCTION__);
				return -1;
			}
			break;
		case IPODAUTH_ACCESSORY_GET_SIGNATURE_DATA_:
			length = 128;
			if(ioctl(g_device_fd,IPODAUTH_ACCESSORY_GET_SIGNATURE_DATA,buffer) < 0)
			{
				LOGE("[%s] >> get device id error.", __FUNCTION__);
				return -1;
			}
			break;
	}
	
	int iNum = 0;
	//LOGE("[%s] >> begin. actual_len = %d", __FUNCTION__, length);
	for(iNum = 0; iNum < length; iNum++)
	{
		LOGE(" <[%d] = 0x%x  ", iNum, buffer[iNum]);
	//	buffer[iNum];
	}
	LOGE("[%s] >> endle.", __FUNCTION__);
	jbyteArray array_ =  (*env)->NewByteArray(env, length);
	(*env)->SetByteArrayRegion(env,array_, 0, length, buffer);
	return array_;
		
}


CARIT_S32 device_startAuthenticaion()
{
	CARIT_U8 deviceID[4] = {0};
	CARIT_U8 certificateBuf[2] = {0};
	CARIT_U16 certificateLen = 0;
	CARIT_U16 cerNum = 0;
	CARIT_U16 cerLeft = 0;
	CARIT_U16 iNum = 0;
	if(NULL == g_device_handle)
	{
		LOGE("[%s] >> phone device not init", __FUNCTION__);
		return CARIT_FAIL;
	}
	if(ioctl(g_device_fd,IPODAUTH_ACCESSORY_GET_DEVICEID,deviceID) < 0)
	{
		LOGE("[%s] >> get device id error.", __FUNCTION__);
		return CARIT_FAIL;
	}
	CARIT_U8 ack_buffer[64] = {0};
	CARIT_U8 buffer_dai_playload[135] = {0x86, 0x00, 0x15, 0x02, 0x00,};
	CARIT_U8 buffer_dai[139] = {0x15, 0x00, 0x55,};
	CARIT_U8 certificate_data[128] = {0};
	CARIT_U8 buffer_head_playload[] = {0x0E, 0x00, 0x13, 0x00, 0x00, 0x04, 0x15, 0x00, 0x00, 0x00, 0x06, deviceID[0], deviceID[1],deviceID[2], deviceID[3]};
	CARIT_U8 checksum = phone_getChecksum(buffer_head_playload, sizeof(buffer_head_playload));
	CARIT_U8 buffer_head[19] = {0x13, 0x00, 0x55, 0x0E, 0x00, 0x13, 0x00, 0x00, 0x04,
							0x15, 0x00, 0x00, 0x00, 0x06, deviceID[0], deviceID[1], deviceID[2], deviceID[3]};
	buffer_head[18] = checksum;
	LOGE("[%s] >> write data begin.", __FUNCTION__);
	if(usb_writeData(buffer_head, sizeof(buffer_head)) < 0)
	{
		LOGE("[%s] >> write head data error.", __FUNCTION__);
		return CARIT_FAIL;
	}
	usb_readData(ack_buffer, sizeof(ack_buffer));
	if(ioctl(g_device_fd,IPODAUTH_ACCESSORY_GET_CERTIFICATE_LEN,certificateBuf) < 0)
	{
		LOGE("[%s] >> get certificate length error.", __FUNCTION__);
		return CARIT_FAIL;
	}
	certificateLen = (CARIT_U16)(certificateBuf[0]<<8 | certificateBuf[1]);
	cerNum = certificateLen/128;
	cerLeft = certificateLen%128;
	LOGE("[%s] >> certificateLen = %d, cerNum = %d, cerLeft = %d.", __FUNCTION__, certificateLen, cerNum, cerLeft);
	for(iNum = 0; iNum < cerNum; iNum++)
	{
		certificate_data[0] = 0x31 + iNum;
		if(ioctl(g_device_fd,IPODAUTH_ACCESSORY_GET_CERTIFICATE_DATA,certificate_data) < 0)
		{
			LOGE("[%s] >>>>> get certificate data error.", __FUNCTION__);
			return CARIT_FAIL;
		}
		#if 1
		int i = 0;
		LOGE("[%s] >> endle. iNum = %d", __FUNCTION__,iNum);
		for(i = 0; i < 128; i++)
		{
			LOGE(" >[%d] = 0x%x  ", iNum, certificate_data[i]);
		}
		LOGE("[%s] >> endle.", __FUNCTION__);
		
		#endif
		buffer_dai_playload[5] = iNum;
		buffer_dai_playload[6] = cerNum;
		memcpy(&buffer_dai_playload[7], &certificate_data[0], 128);
		checksum = phone_getChecksum(buffer_dai_playload, sizeof(buffer_dai_playload));
		LOGE("[%s] >> iNum === %d cerNum = %d.", __FUNCTION__, iNum, cerNum);
		if(0 == iNum)
		{
			buffer_dai[1] = 0x02;
		}else
		{
			if(cerLeft > 0)
			{
				buffer_dai[1] = 0x03;
			}else
			{
				buffer_dai[1] = 0x01;
			}
		}
		memcpy(&buffer_dai[3], &buffer_dai_playload[0], 135);
		buffer_dai[138]	 = checksum;
		usb_writeData(buffer_dai, sizeof(buffer_dai));
		usb_readData(ack_buffer,sizeof(ack_buffer));
	}
	LOGE("[%s] send cerLef now", __FUNCTION__);
	if(cerLeft > 0)
	{
		certificate_data[0] = 0x31 + iNum;
		if(ioctl(g_device_fd,IPODAUTH_ACCESSORY_GET_CERTIFICATE_DATA,certificate_data) < 0)
		{
			LOGE("[%s] >>>>> get certificate data error.", __FUNCTION__);
			return CARIT_FAIL;
		}
		buffer_dai_playload[0] = (CARIT_U8)(cerLeft+6);
		buffer_dai_playload[5] = iNum;
		buffer_dai_playload[6] = iNum;
		memcpy(&buffer_dai_playload[7], &certificate_data[0], cerLeft);
		checksum = phone_getChecksum(buffer_dai_playload, cerLeft + 7);
		buffer_dai[1] = 0x01;
		memcpy(&buffer_dai[3], &buffer_dai_playload[0], cerLeft + 7);
		buffer_dai[cerLeft + 10] = checksum;
		usb_writeData(buffer_dai, cerLeft+11);
	}
	while(1)
	{
		usb_readData(ack_buffer, sizeof(ack_buffer));
		if(0x19 == ack_buffer[5] && 0x00 == ack_buffer[6])
		{
			LOGE("[%s] >>> Authenticaion success!", __FUNCTION__);
			break;
		}
		if(0x17 == ack_buffer[5])
		{
			CARIT_U8 aSign[20] = {0};
			CARIT_U8 aSignLen[2] = {0x00, 0x14};
			CARIT_S32 signLength = 0;
			CARIT_U8 control[1]	 = {0x01};
			CARIT_U8 status[1] = {0x00};
			CARIT_U8 signData[128] = {0x00};
			CARIT_U8 buffer_sign_playload[160] = {0x00, 0x00, 0x18,};
			CARIT_U8 buffer_sign[160] = {0x15, 0x00, 0x55, };
			memcpy(&aSign[0], &ack_buffer[6], 20);
			if(ioctl(g_device_fd,IPODAUTH_ACCESSORY_SET_CHALLENGE_LEN,aSignLen) < 0)
			{
				LOGE("[%s] >>>>> set challenge length error.", __FUNCTION__);
				return CARIT_FAIL;
			}
			if(ioctl(g_device_fd,IPODAUTH_ACCESSORY_SET_CHALLENGE_DATA,aSign) < 0)
			{
				LOGE("[%s] >>>>> set challenge data error.", __FUNCTION__);
				return CARIT_FAIL;
			}
			int iNum = 0;
			LOGE("[%s] ---------------- ", __FUNCTION__);
			for(iNum = 0; iNum < 20; iNum++)
			{
			LOGE(" <[%d] = 0x%x  ", iNum, aSign[iNum]);
			//	buffer[iNum];
			}
			if(ioctl(g_device_fd,IPODAUTH_ACCESSORY_SET_CONTROL,control) < 0)
			{
				LOGE("[%s] >>>>> set control error.", __FUNCTION__);
				return CARIT_FAIL;
			}
			while(1)
			{
				usleep(600000);
				LOGE("[%s] >>>> get read status begin", __FUNCTION__);
				if(ioctl(g_device_fd,IPODAUTH_ACCESSORY_GET_READ_STATUS,status) < 0)
				{
					LOGE("[%s] >>> get read status error", __FUNCTION__);
					//return CARIT_FAIL;
				}
				LOGE("[%s] >> read status = %d", __FUNCTION__, status[0]);
				if(0x10 == status[0])
				{
					break;
				}
			}
			LOGE("[%s] >>> get signature length .", __FUNCTION__);
			if(ioctl(g_device_fd,IPODAUTH_ACCESSORY_GET_SIGNATURE_LEN,aSignLen) < 0)
			{
				LOGE("[%s] >>> get signature length error.", __FUNCTION__);
				return CARIT_FAIL;
			}
			signLength = ((aSignLen[0] << 8) | aSignLen[1]);
			signData[0] = 0x12;
			LOGE("[%s] >>> get signature data .", __FUNCTION__);
			if(ioctl(g_device_fd, IPODAUTH_ACCESSORY_GET_SIGNATURE_DATA, signData) < 0)
			{
				LOGE("[%s] >>> get signature data error.", __FUNCTION__);
				return CARIT_FAIL;
			}
			
			buffer_sign_playload[0] = (CARIT_U8)(signLength+2);
			memcpy(&buffer_sign_playload[3], &signData[0], signLength);
			checksum = phone_getChecksum(buffer_sign_playload, signLength+3);
			memcpy(&buffer_sign[3], &buffer_sign_playload[0], signLength+3);
			buffer_sign[signLength+6] = checksum;
			usb_writeData(buffer_sign, signLength+7);
		}
	}
	return CARIT_OK;
}

CARIT_S32 phone_init()
{
	libusb_device** pDevs = NULL;
	struct libusb_device_descriptor desc;
	CARIT_U16 idVendor = 0;
	CARIT_U16 idProduct = 0;
	ssize_t cnt = 0;
	CARIT_S32 iNum = 0;
	CARIT_S32 ret = CARIT_FAIL;
	g_device_fd = open("/dev/ipod",O_RDWR);
	USB_Printf("[%s] >> open ipod device", __FUNCTION__);
	if(g_device_fd < 0)
	{
		USB_Printf("[%s] >> open ipod device fail", __FUNCTION__);
		return CARIT_FAIL;
	}
	USB_Printf("[%s] >> open ipod device success", __FUNCTION__);
	if(libusb_init(&g_usb_ctx) < 0)
	{
		USB_Printf("[%s] >>libusb init fail.", __FUNCTION__);
		libusb_exit(g_usb_ctx);
		return CARIT_FAIL;
	}
	libusb_set_debug(g_usb_ctx,LIBUSB_LOG_LEVEL_INFO);
	cnt = libusb_get_device_list(g_usb_ctx, &pDevs);
	if(cnt <= 0)
	{
		USB_Printf("[%s] >>get devices num error.", __FUNCTION__);
		libusb_exit(g_usb_ctx);
		return CARIT_FAIL;
	}
	for(iNum = 0; iNum < cnt; iNum++)
	{
		if(libusb_get_device_descriptor(pDevs[iNum], &desc) < 0)
		{
			USB_Printf("[%s] >> get device descriptor error", __FUNCTION__);
			continue;
		}
		USB_Printf("[%s] >> get vendor id = %d.", __FUNCTION__, desc.idVendor);
		if(0x05ac == desc.idVendor)
		{
			idVendor = desc.idVendor;
			idProduct = desc.idProduct;
			break;
		}
	}
	if(iNum == cnt)
	{
		USB_Printf("[%s] >> no phone device.", __FUNCTION__);
		libusb_exit(g_usb_ctx);
		return CARIT_FAIL;
	}
	USB_Printf("[%s] >> open [%d].", __FUNCTION__,libusb_open(pDevs[iNum], &g_device_handle));
	if(NULL == g_device_handle)
	{
		USB_Printf("[%s] >> open phone device error.", __FUNCTION__);
		libusb_exit(g_usb_ctx);
		return CARIT_FAIL;
	}
	libusb_free_device_list(pDevs, 1);
	if(1 == libusb_kernel_driver_active(g_device_handle, 2))
	{
		if(0 != libusb_detach_kernel_driver(g_device_handle,2))
		{
			USB_Printf("[%s] >> detach kernel driver error.", __FUNCTION__);
			libusb_close(g_device_handle);
			libusb_exit(g_usb_ctx);
			return CARIT_FAIL;
		}
	}
	
	if(libusb_claim_interface(g_device_handle,2) < 0)
	{
		USB_Printf("[%s] >> libusb_claim_interface >> error.", __FUNCTION__);
		libusb_close(g_device_handle);
		libusb_exit(g_usb_ctx);
		return CARIT_FAIL;
	}
	/*
	if(libusb_set_configuration(g_device_handle,2) < 0)
	{
		USB_Printf("[%s] >> libusb_set_configuration >> error.", __FUNCTION__);
		libusb_close(g_device_handle);
		libusb_exit(g_usb_ctx);
		return CARIT_FAIL;
	}
	*/
	return CARIT_OK;
}

CARIT_S32 phone_deinit()
{
	libusb_release_interface(g_device_handle, 2);
	libusb_close(g_device_handle);
	libusb_exit(g_usb_ctx);
	close(g_device_fd);
	g_usb_ctx = NULL;
	g_device_fd = -1;
	g_device_handle = NULL;
	return CARIT_OK;
}

static JNINativeMethod gMethods[] = {
	{"phoneDeviceAuthentication", "()I", (void*)device_startAuthenticaion},
	{"phoneDeviceInit", "()I", (void*)phone_init},
	{"phoneDeviceDeinit", "()I", (void*)phone_deinit},
	{"ioctlWrite", "(I[BI)I", (void*)ioctl_write},
	{"ioctlRead", "(I[BI)[B", (void*)ioctl_read},
	{"checksum", "([BII)B", (void*)check_sum},
	{"openiic", "()I", (void*)open_iic},
	{"closeiic", "(I)I", (void*)close_iic},
	{"ioctlWrite", "(II[BI)I", (void*)ioctl_write_},
	{"ioctlRead", "(II[BI)[B", (void*)ioctl_read_},
	
};


static int registerNativeMethods(JNIEnv* env, const char* className,
    JNINativeMethod* gMethods, int numMethods)
{
	jclass clazz;
	clazz = (*env)->FindClass(env, className);
	if(NULL == clazz)
	{
		return JNI_FALSE;
	}
	if((*env)->RegisterNatives(env, clazz, gMethods, numMethods) < 0)
	{
		return JNI_FALSE;
	}
	return JNI_TRUE;
}


static int registerNatives(JNIEnv* env)
{
  if (!registerNativeMethods(env, "com/carit/ipodusbplayer/IpodUsb",
		  gMethods, (sizeof(gMethods) / sizeof(gMethods[0]))))
  {
    return JNI_FALSE;
  }
  return JNI_TRUE;
}

jint JNI_OnLoad(JavaVM* vm, void* reserved)
{
	JNIEnv* env = NULL;
	if((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_4) != JNI_OK)
	{
		return -1;
	}
	assert(NULL != env);
	if(!registerNatives(env))
	{
		return -1;
	}
	return JNI_VERSION_1_4;
}

CARIT_S32 build_cmd1(CARIT_U8 lingo_id ,CARIT_U8 command_id, CARIT_U8* parm,CARIT_U8 parm_length,CARIT_U8* result){
	// 4 = 0x13, 0x00, 0x55, packet payload length
	// 2 = lingo id + command id
	// 1 = checksum
	
	CARIT_U8 length = 4 + 2 +parm_length+1;
	CARIT_U8 result_t[length] ;
	CARIT_U8 buffer[]= {0x13, 0x00, 0x55,length-5,lingo_id,command_id};
	memcpy(&result_t[0], &buffer[0], 6);
	if(parm_length!=0){
		memcpy(&result_t[6], &parm[0], parm_length);
	}
	USB_Printf("[%s] >> sizeof(parm) = [%d] length = [%d] ", __FUNCTION__,parm_length,length);
	result_t[length-1] = phone_getChecksum(&result_t[3], length-4);
	#if 0
	int iNum = 0;
	LOGE("[%s] >> begin. actual_len = %d", __FUNCTION__, length);
	for(iNum = 0; iNum < length; iNum++)
	{
		LOGE(" *[%d] = 0x%x  ", iNum, result_t[iNum]);
	}
	LOGE("[%s] >> endle.", __FUNCTION__);
	#endif
	memset(&result[0],0,100);
	memcpy(&result[0], &result_t[0], length);
	return sizeof(result_t);
}
CARIT_S32 build_cmd2(CARIT_U8 lingo_id ,CARIT_U8 command_id1,CARIT_U8 command_id2, CARIT_U8* parm,CARIT_U8 parm_length,CARIT_U8* result){
	// 4 = 0x13, 0x00, 0x55, packet payload length
	// 3 = lingo id + command id1 + command id2
	// 1 = checksum
	
	CARIT_U8 length = 4 + 3 +parm_length+1;
	CARIT_U8 result_t[length] ;
	CARIT_U8 buffer[]= {0x13, 0x00, 0x55,length-5,lingo_id,command_id1,command_id2};
	memcpy(&result_t[0], &buffer[0], 7);
	if(parm_length!=0){
		memcpy(&result_t[7], &parm[0], parm_length);
	}
	USB_Printf("[%s] >> sizeof(parm) = [%d] length = [%d] ", __FUNCTION__,parm_length,length);
	result_t[length-1] = phone_getChecksum(&result_t[3], length-4);
	#if 0
	int iNum = 0;
	LOGE("[%s] >> begin. actual_len = %d", __FUNCTION__, length);
	for(iNum = 0; iNum < length; iNum++)
	{
		LOGE(" *[%d] = 0x%x  ", iNum, result_t[iNum]);
	}
	LOGE("[%s] >> endle.", __FUNCTION__);
	#endif
	memset(&result[0],0,100);
	memcpy(&result[0], &result_t[0], length);
	return sizeof(result_t);
}

void delay200ms(void){
   unsigned char i,j,k;
   for(i=5;i>0;i--)
     for(j=132;j>0;j--)
       for(k=150;k>0;k--);
}
CARIT_S32 device_test()
{
	
	CARIT_U8 ack_buffer[64] = {0};
	CARIT_U8 buffer_head[100] ;
	delay200ms();

	CARIT_S32 length = build_cmd1(0x00,0x03,NULL,0,buffer_head);
	if(usb_writeData(buffer_head, length) < 0)
	{
		LOGE("[%s] >> write head data error.", __FUNCTION__);
		return CARIT_FAIL;
	}
	usb_readData(ack_buffer, sizeof(ack_buffer));
	while(1){
		if (ack_buffer[4]==0xa&&ack_buffer[5]==0x2)
			{
				CARIT_U8 command[12] = {0x00,0x00,0x7D,0x00,0x00,0x00,0xAC,0x44,0x00,0x00,0xBB,0x80}; 
				length = build_cmd1(0x0a,0x03,command,12,buffer_head);
				//----RetAccSampleRateCaps
				usb_writeData(buffer_head, length);
				break;
			}else{
			delay200ms();
			usb_readData(ack_buffer, sizeof(ack_buffer));
			}
	}

	
	usb_readData(ack_buffer, sizeof(ack_buffer));
	delay200ms();
	//----RequestLingoProtocolVersion
	CARIT_U8 cmd[1] = {4};
	length = build_cmd1(0x00,0x0F,cmd,1,buffer_head);

	if(usb_writeData(buffer_head, length) < 0)
	{
		LOGE("[%s] >> write head data error.", __FUNCTION__);
		return CARIT_FAIL;
	}
	usb_readData(ack_buffer, sizeof(ack_buffer));
	delay200ms();
	/*
	//----RequestLingoProtocolVersion
	length = build_cmd1(0x00,0x0F,NULL,0,buffer_head);

	if(usb_writeData(buffer_head, length) < 0)
	{
		LOGE("[%s] >> write head data error.", __FUNCTION__);
		return CARIT_FAIL;
	}
	usb_readData(ack_buffer, sizeof(ack_buffer));
	delay200ms();
	*/
	length = build_cmd1(0x00,0x05,NULL,0,buffer_head);

	if(usb_writeData(buffer_head, length) < 0)
	{
		LOGE("[%s] >> write head data error.", __FUNCTION__);
		return CARIT_FAIL;
	}
	usb_readData(ack_buffer, sizeof(ack_buffer));
	while(1){
		if (ack_buffer[6]==0&&ack_buffer[7]==5)
			{
				break;
			}else{
			delay200ms();
			usb_readData(ack_buffer, sizeof(ack_buffer));
			}
	}
	delay200ms();
	CARIT_U8 command[1] = {2};
	length = build_cmd2(0x04,0x00,0x29,command,1,buffer_head);

	if(usb_writeData(buffer_head, length) < 0)
	{
		LOGE("[%s] >> write head data error.", __FUNCTION__);
		return CARIT_FAIL;
	}
	usb_readData(ack_buffer, sizeof(ack_buffer));

	delay200ms();
	CARIT_U8 command_[1] = {1};
	length = build_cmd2(0x04,0x00,0x29,command_,1,buffer_head);

	if(usb_writeData(buffer_head, length) < 0)
	{
		LOGE("[%s] >> write head data error.", __FUNCTION__);
		return CARIT_FAIL;
	}
	usb_readData(ack_buffer, sizeof(ack_buffer));

	delay200ms();
	//CARIT_U8 command__[3] = {0x03,0x01,0x01};
	//length = build_cmd1(0x00,0x2B,command__,3,buffer_head);

	//if(usb_writeData(buffer_head, length) < 0)
	//{
	//	LOGE("[%s] >> write head data error.", __FUNCTION__);
	//	return CARIT_FAIL;
	//}
	usb_readData(ack_buffer, sizeof(ack_buffer));

	delay200ms();
	int i=5;
	while(i>0){
			if (ack_buffer[4]==0xa&&ack_buffer[5]==0x2)
			{
				CARIT_U8 command[12] = {0x00,0x00,0x7D,0x00,0x00,0x00,0xAC,0x44,0x00,0x00,0xBB,0x80}; 
				length = build_cmd1(0x0a,0x03,command,12,buffer_head);
				//----RetAccSampleRateCaps
				usb_writeData(buffer_head, length);

			}
			delay200ms();
			if(usb_readData(ack_buffer, sizeof(ack_buffer))==CARIT_FAIL){
				break;
			}
			i--;
	}
/*	

	if(usb_writeData(command__, 3) < 0)
	{
		LOGE("[%s] >> write head data error.", __FUNCTION__);
		return CARIT_FAIL;
	}
	usb_readData(ack_buffer, sizeof(ack_buffer));
	*/
}


int main()

{
	phone_init();
	device_startAuthenticaion();
	device_test();
	
    printf("--------------------------");

    return 0;

}
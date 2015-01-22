package com.carit.ipodusbplayer;

public class IpodUsb {
    
    
    public static final int L_ID_GEN = 0x00;
    public static final int L_ID_EIP = 0x04;
    public static final int L_ID_DA = 0x0A;
    
    public static final int IPODAUTH_ACCESSORY_GET_VERSION = 0x120 ;//CP->AC
    public static final int IPODAUTH_ACCESSORY_GET_DEVICEID = 0x121 ;//CP->AC
    public static final int IPODAUTH_ACCESSORY_GET_CERTIFICATE_LEN = 0x122 ;//CP->AC
    public static final int IPODAUTH_ACCESSORY_GET_CERTIFICATE_DATA = 0x123 ;//CP->AC
    public static final int IPODAUTH_ACCESSORY_GET_WAIT_STATUS = 0x124 ;//CP->AC
    public static final int IPODAUTH_ACCESSORY_GET_READ_STATUS = 0x125 ;//CP->AC
    public static final int IPODAUTH_ACCESSORY_GET_SIGNATURE_LEN = 0x126; //CP->AC
    public static final int IPODAUTH_ACCESSORY_GET_SIGNATURE_DATA = 0x127; //CP->AC
    public static final int IPODAUTH_ACCESSORY_GET_MAJORVERSION = 0x128; //CP->AP
    public static final int IPODAUTH_ACCESSORY_GET_MINORVERSION = 0x129; //CP->AP
    public static final int IPODAUTH_ACCESSORY_SET_CHALLENGE_LEN = 0x12A; //AC->CP
    public static final int IPODAUTH_ACCESSORY_SET_CHALLENGE_DATA = 0x12B; //AC->CP
    public static final int IPODAUTH_ACCESSORY_SET_CONTROL = 0x12C; //AC->CP
	
	static {
		System.loadLibrary("usb1.0");
		System.loadLibrary("ipod_usb");
	}

	public native int phoneDeviceAuthentication();
	
	public native int phoneDeviceInit();
	
	public native int phoneDeviceDeinit();
	
	public native int ioctlWrite(int cmd,byte[] param,int length);
	
	public native int ioctlWrite(int file_id,int cmd,byte[] param,int length);
	
	public native byte[] ioctlRead(int cmd,byte[] param,int length);
	
	public native byte[] ioctlRead(int file_id,int cmd,byte[] param,int length);
	
	public native byte checksum(byte[] param,int offset,int length);
	
	public native int openiic();
	
	public native int closeiic(int file_id);
}

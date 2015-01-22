
package com.carit.ipodusbplayer;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.hardware.usb.UsbConstants;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbEndpoint;
import android.hardware.usb.UsbInterface;
import android.hardware.usb.UsbManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import com.android.internal.util.HexDump;

import java.util.HashMap;
import java.util.Iterator;

public class MainActivity extends Activity implements OnClickListener {

    // TextView textInfo;
    // TextView textSearchedEndpoint;

    // TextView textDeviceName;
    // TextView textStatus;

    private static final int targetVendorID = 1452; // Arduino Uno
    private static final int targetProductID = 4776; // Arduino Uno, not 0067
    // private static final int targetProductID = 4709; // Arduino Uno, not 0067
    UsbDevice deviceFound = null;
    UsbInterface usbInterfaceFound = null;
    UsbEndpoint endpointIn = null;
    UsbEndpoint endpointOut = null;

    private static final String ACTION_USB_PERMISSION = "com.android.example.USB_PERMISSION";
    PendingIntent mPermissionIntent;

    UsbInterface usbInterface;
    UsbDeviceConnection usbDeviceConnection;

    EditText textOut;
    Button buttonPlay;
    Button buttonNext;
    Button buttonPrv;
    private IpodUsb mIpodUsb = new IpodUsb();

    private Thread mInputThread;
    private Thread mOutputThread;

    private boolean isAuthenticaionSuccess;
    private boolean isGetAuthenticaionSignature;

    private byte[] mGetAuthenticaionSignature = new byte[20];

    public static final String TAG = "--Ipod USB";

    // private int iic_file_id;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main_layout);

        mPermissionIntent = PendingIntent.getBroadcast(this, 0, new Intent(
                ACTION_USB_PERMISSION), 0);
        IntentFilter filter = new IntentFilter(ACTION_USB_PERMISSION);
        registerReceiver(mUsbReceiver, filter);

        registerReceiver(mUsbDeviceReceiver, new IntentFilter(
                UsbManager.ACTION_USB_DEVICE_ATTACHED));
        registerReceiver(mUsbDeviceReceiver, new IntentFilter(
                UsbManager.ACTION_USB_DEVICE_DETACHED));

        connectUsb();

        buttonPlay = (Button) findViewById(R.id.play);
        buttonPlay.setOnClickListener(this);
        buttonNext = (Button) findViewById(R.id.next);
        buttonNext.setOnClickListener(this);
        buttonPrv = (Button) findViewById(R.id.prv);
        buttonPrv.setOnClickListener(this);
        // mIpodUsb.ioctlWrite(IpodUsb.IPODAUTH_ACCESSORY_GET_DEVICEID_, array,
        // 4);

    }

    OnClickListener buttonSendOnClickListener =
            new OnClickListener() {

                public void onClick(View v) {

                }
            };

    @Override
    protected void onDestroy() {
        releaseUsb();

        unregisterReceiver(mUsbReceiver);
        unregisterReceiver(mUsbDeviceReceiver);
        super.onDestroy();
    }
    
    private Handler mHandler = new Handler(){

        @Override
        public void handleMessage(Message msg) {
            switch(msg.what){
                case 0:
                    buttonNext.setEnabled(true);
                    buttonPlay.setEnabled(true);
                    buttonPrv.setEnabled(true);
                    break;
                case 1:
                    Toast.makeText(getBaseContext(), "Inter Digital Audio Mode", Toast.LENGTH_SHORT).show();
                    break;
            }
            super.handleMessage(msg);
        }
        
    };

    private void connectUsb() {

        Toast.makeText(MainActivity.this, "connectUsb()", Toast.LENGTH_LONG)
                .show();

        searchEndPoint();

        if (usbInterfaceFound != null) {
            setupUsbComm();
        }

    }

    private void releaseUsb() {

        Toast.makeText(MainActivity.this, "releaseUsb()", Toast.LENGTH_LONG)
                .show();
        isDestroy = true;
        if (mInputThread != null && mInputThread.isAlive()) {
            try {
                mInputThread.join();
            } catch (InterruptedException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
        if (mOutputThread != null && mOutputThread.isAlive()) {
            try {
                mOutputThread.join();
            } catch (InterruptedException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }

        if (usbDeviceConnection != null) {
            if (usbInterface != null) {
                usbDeviceConnection.releaseInterface(usbInterface);
                usbInterface = null;
            }
            usbDeviceConnection.close();
            usbDeviceConnection = null;
        }

        deviceFound = null;
        usbInterfaceFound = null;
        endpointIn = null;
        endpointOut = null;
    }

    private void searchEndPoint() {

        usbInterfaceFound = null;
        endpointOut = null;
        endpointIn = null;

        // Search device for targetVendorID and targetProductID
        if (deviceFound == null) {
            UsbManager manager = (UsbManager) getSystemService(Context.USB_SERVICE);
            HashMap<String, UsbDevice> deviceList = manager.getDeviceList();
            Iterator<UsbDevice> deviceIterator = deviceList.values().iterator();

            while (deviceIterator.hasNext()) {
                UsbDevice device = deviceIterator.next();
                String s = device.toString() + "\n" + "DeviceID: "
                        + device.getDeviceId() + "\n" + "DeviceName: "
                        + device.getDeviceName() + "\n" + "DeviceClass: "
                        + device.getDeviceClass() + "\n" + "DeviceSubClass: "
                        + device.getDeviceSubclass() + "\n" + "VendorID: "
                        + device.getVendorId() + "\n" + "ProductID: "
                        + device.getProductId() + "\n" + "InterfaceCount: "
                        + device.getInterfaceCount();
                Log.e(TAG, s);
                if (device.getVendorId() == targetVendorID) {
                    // if (device.getProductId() == targetProductID) {
                    deviceFound = device;
                    // }
                }
            }
        }

        if (deviceFound == null) {
            Toast.makeText(MainActivity.this, "device not found",
                    Toast.LENGTH_LONG).show();
        } else {
            String s = deviceFound.toString() + "\n" + "DeviceID: "
                    + deviceFound.getDeviceId() + "\n" + "DeviceName: "
                    + deviceFound.getDeviceName() + "\n" + "DeviceClass: "
                    + deviceFound.getDeviceClass() + "\n" + "DeviceSubClass: "
                    + deviceFound.getDeviceSubclass() + "\n" + "VendorID: "
                    + deviceFound.getVendorId() + "\n" + "ProductID: "
                    + deviceFound.getProductId() + "\n" + "InterfaceCount: "
                    + deviceFound.getInterfaceCount();

            // Search for UsbInterface with Endpoint of USB_ENDPOINT_XFER_BULK,
            // and direction USB_DIR_OUT and USB_DIR_IN

            for (int i = 0; i < deviceFound.getInterfaceCount(); i++) {
                UsbInterface usbif = deviceFound.getInterface(i);

                UsbEndpoint tOut = null;
                UsbEndpoint tIn = null;
                int tEndpointCnt = usbif.getEndpointCount();
                if (tEndpointCnt > 0) {
                    for (int j = 0; j < tEndpointCnt; j++) {
                        if (usbif.getId() == 2) {
                            if (usbif.getEndpoint(j).getDirection() == UsbConstants.USB_DIR_IN
                                    && usbif.getEndpoint(j).getAddress() == 131) {
                                tIn = usbif.getEndpoint(j);
                            }
                        }
                        if (usbif.getEndpoint(j).getType() == UsbConstants.USB_ENDPOINT_XFER_CONTROL) {
                        }
                        if (tIn != null) {
                            // This interface have both USB_DIR_OUT
                            // and USB_DIR_IN of USB_ENDPOINT_XFER_BULK
                            usbInterfaceFound = usbif;
                            endpointOut = tOut;
                            endpointIn = tIn;
                            break;
                        }
                    }

                }

            }

            if (usbInterfaceFound == null) {
            } else {
                // textSearchedEndpoint.setText("UsbInterface found: "
                // + usbInterfaceFound.toString() + "\n\n"
                // + "Endpoint OUT: " + endpointOut.toString() + "\n\n"
                // + "Endpoint IN: " + endpointIn.toString());
            }
        }
    }

    private boolean setupUsbComm() {

        // for more info, search SET_LINE_CODING and
        // SET_CONTROL_LINE_STATE in the document:
        // "Universal Serial Bus Class Definitions for Communication Devices"
        // at http://adf.ly/dppFt
        final int RQSID_SET_LINE_CODING = 0x20;
        final int RQSID_SET_CONTROL_LINE_STATE = 0x09;

        boolean success = false;

        UsbManager manager = (UsbManager) getSystemService(Context.USB_SERVICE);
        Boolean permitToRead = manager.hasPermission(deviceFound);

        if (permitToRead) {
            usbDeviceConnection = manager.openDevice(deviceFound);

            if (usbDeviceConnection != null) {
                // byte buffer[] = {
                // 0x13, 0x0, 0x55, 0x4, 0x4, 0x0, 0x29, 0x1, (byte) 0xce
                // };
                // for (int i = 0; i < deviceFound.getInterfaceCount(); i++) {
                // UsbInterface usbif = deviceFound.getInterface(i);

                usbDeviceConnection.claimInterface(usbInterfaceFound, true);
                // Log.e("USB_PIOD",
                // "claimInterface  i="+i+"usbif id =  "+usbif.getId()+" "+usbDeviceConnection.claimInterface(usbif,
                // true));
                mInputThread = new Thread(runnable);
                mInputThread.start();
                // usbResult = usbDeviceConnection.controlTransfer(0x21, //
                // requestType
                // RQSID_SET_CONTROL_LINE_STATE, // SET_CONTROL_LINE_STATE
                // 0x0211, // value
                // 0x0002, // index
                // buffer, // buffer
                // 9, // length
                // 100); // timeout
                mOutputThread = new Thread() {

                    @Override
                    public void run() {
                        int usbResult;
                        usbResult = startAuthenticaion();
                        Log.e(TAG, "controlTransfer(RQSID_SET_LINE_CODING): " + usbResult);
                        super.run();
                    }

                };
                mOutputThread.start();

            }

        } else {
            manager.requestPermission(deviceFound, mPermissionIntent);
            Toast.makeText(MainActivity.this, "Permission: " + permitToRead,
                    Toast.LENGTH_LONG).show();
        }

        return success;
    }

    private final BroadcastReceiver mUsbReceiver = new BroadcastReceiver() {

        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            if (ACTION_USB_PERMISSION.equals(action)) {

                Toast.makeText(MainActivity.this, "ACTION_USB_PERMISSION",
                        Toast.LENGTH_LONG).show();

                synchronized (this) {
                    UsbDevice device = (UsbDevice) intent
                            .getParcelableExtra(UsbManager.EXTRA_DEVICE);

                    if (intent.getBooleanExtra(
                            UsbManager.EXTRA_PERMISSION_GRANTED, false)) {
                        if (device != null) {
                            connectUsb();
                        }
                    } else {
                        Toast.makeText(MainActivity.this,
                                "permission denied for device " + device,
                                Toast.LENGTH_LONG).show();
                    }
                }
            }
        }
    };

    private final BroadcastReceiver mUsbDeviceReceiver = new BroadcastReceiver() {

        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            if (UsbManager.ACTION_USB_DEVICE_ATTACHED.equals(action)) {

                deviceFound = (UsbDevice) intent
                        .getParcelableExtra(UsbManager.EXTRA_DEVICE);
                Toast.makeText(
                        MainActivity.this,
                        "ACTION_USB_DEVICE_ATTACHED: \n"
                                + deviceFound.toString(), Toast.LENGTH_LONG)
                        .show();

                connectUsb();

            } else if (UsbManager.ACTION_USB_DEVICE_DETACHED.equals(action)) {

                UsbDevice device = (UsbDevice) intent
                        .getParcelableExtra(UsbManager.EXTRA_DEVICE);

                Toast.makeText(MainActivity.this,
                        "ACTION_USB_DEVICE_DETACHED: \n" + device.toString(),
                        Toast.LENGTH_LONG).show();

                if (device != null) {
                    if (device == deviceFound) {
                        releaseUsb();
                    } else {
                        Toast.makeText(MainActivity.this,
                                "device == deviceFound, no call releaseUsb()\n" +
                                        device.toString() + "\n" +
                                        deviceFound.toString(),
                                Toast.LENGTH_LONG).show();
                    }
                } else {
                    Toast.makeText(MainActivity.this,
                            "device == null, no call releaseUsb()", Toast.LENGTH_LONG).show();
                }

            }
        }

    };
    private boolean isDestroy = false;
    Runnable runnable = new Runnable() {

        public void run() {
            // TODO Auto-generated method stub
            // System.out.println("进入线程了");
            // usbDeviceConnection.claimInterface(usbInterfaceFound, true);
            while (!isDestroy) {
                synchronized (this) {
                    if (usbDeviceConnection != null) {
                        // ByteBuffer buffer = ByteBuffer.allocate(64);
                        // Log.e("USB Ipod","request.queue = "+request.queue(buffer,
                        // 64));
                        // if
                        // (usbDeviceConnection.requestWait().equals(request)) {
                        byte[] data = new byte[64];
                        if (usbDeviceConnection.bulkTransfer(endpointIn, data, 64, 1000) > 0) {
                            final String message = "<<<<<<<<<<<<<<< Read " + data.length
                                    + " bytes: \n" + HexDump.dumpHexString(data)
                                    + "\n\n";
                            // System.out.println(message);
                            Log.d(TAG, message);
                            parseResult(data);
                        }
                        // Log.e("USB Ipod","length = "+usbDeviceConnection.bulkTransfer(endpointIn,
                        // data, 64,
                        // 1000)+" interface = "+usbif.getId()+" endpoint = "+endpointIn.getAddress());
                        // System.out.println(message);
                        // Log.e("USB Ipod", message);
                        // }

                    }
                }

            }

        }
    };

    private void parseResult(byte[] result) {
        if (result.length == 64 && result[1] == 0x00 && result[2] == 0x55) {
            int length = result[3];
            byte result_sum = result[4 + length];
            byte sum_ = checksum(result, 3, length + 1);
            if (result_sum == sum_) {
                Log.e(TAG, "checksum ok!");
            } else {
                Log.e(TAG,
                        "checksum result[4+length] = 0x"
                                + Integer.toHexString(unsignedToBytes(result[4 + length]))
                                + " checksum = 0x"
                                + Integer.toHexString(unsignedToBytes(checksum(result, 3,
                                        length + 1))));
            }
            int lingo_id = result[4];
            switch (lingo_id) {
                case IpodUsb.L_ID_GEN:
                    switch (result[5]) {
                        case 0x19:
                            if (result[6] == 0) {
                                isAuthenticaionSuccess = true;
                                Log.e(TAG, "--------------isGetAuthenticaionSignature----");
                                mHandler.sendEmptyMessage(0);
                                byte [] cmd = build_cmd1(0x00, 0x03, null, 0x00);
                                writeData(cmd, cmd.length);
                            }
                            else {
                                isAuthenticaionSuccess = false;
                            }
                            break;
                        case 0x17:
                            Log.e(TAG, "--------------isGetAuthenticaionSignature----");
                            System.arraycopy(result, 6, mGetAuthenticaionSignature, 0, 20);
                            isGetAuthenticaionSignature = true;
                            break;
                        case 0x14: {
                            byte[] deviceID = new byte[4];
                            deviceID = mIpodUsb.ioctlRead(IpodUsb.IPODAUTH_ACCESSORY_GET_DEVICEID,
                                    deviceID, 4);
                            byte buffer_dai_playload[] = new byte[135];
                            buffer_dai_playload[0] = (byte) 0x86;
                            buffer_dai_playload[1] = 0x00;
                            buffer_dai_playload[2] = 0x15;
                            buffer_dai_playload[3] = 0x02;
                            byte buffer_dai[] = new byte[139];
                            buffer_dai[0] = (byte) 0x15;
                            buffer_dai[1] = 0x00;
                            buffer_dai[2] = 0x55;
                            byte certificate_data[] = new byte[128];
                            byte[] certificateBuf = new byte[2];
                            certificateBuf = mIpodUsb.ioctlRead(
                                    IpodUsb.IPODAUTH_ACCESSORY_GET_CERTIFICATE_LEN, certificateBuf,
                                    certificateBuf.length);
                            Log.e(TAG, "certificateBuf =" + unsignedToBytes(certificateBuf[0])
                                    + " certificateBuf = " + unsignedToBytes(certificateBuf[1]));
                            long certificateLen = (unsignedToBytes(certificateBuf[0]) << 8 | unsignedToBytes(certificateBuf[1]));
                            int cerNum = (int) (certificateLen / 128);
                            int cerLeft = (int) (certificateLen % 128);
                            Log.e(TAG, "cerNum =" + cerNum + " cerLeft = " + cerLeft);
                            int iNum = 0;
                            for (iNum = 0; iNum < cerNum; iNum++) {
                                certificate_data[0] = (byte) (0x31 + iNum);
                                certificate_data = mIpodUsb.ioctlRead(
                                        IpodUsb.IPODAUTH_ACCESSORY_GET_CERTIFICATE_DATA,
                                        certificate_data, certificate_data.length);
                                // Log.e(TAG,
                                // "certificate_data ="+HexDump.dumpHexString(certificate_data));
                                buffer_dai_playload[5] = (byte) iNum;
                                buffer_dai_playload[6] = (byte) cerNum;
                                System.arraycopy(certificate_data, 0, buffer_dai_playload, 7, 128);
                                byte sum = checksum(buffer_dai_playload, 0,
                                        buffer_dai_playload.length);
                                if (0 == iNum)
                                {
                                    buffer_dai[1] = 0x02;
                                } else
                                {
                                    if (cerLeft > 0)
                                    {
                                        buffer_dai[1] = 0x03;
                                    } else
                                    {
                                        buffer_dai[1] = 0x01;
                                    }
                                }
                                System.arraycopy(buffer_dai_playload, 0, buffer_dai, 3, 135);
                                buffer_dai[138] = sum;
                                writeData(buffer_dai, buffer_dai.length);
                                try {
                                    Thread.sleep(200);
                                } catch (InterruptedException e) {
                                    // TODO Auto-generated catch block
                                    e.printStackTrace();
                                }
                            }
                            Log.e(TAG, " send cerLef now");
                            if (cerLeft > 0)
                            {
                                certificate_data[0] = (byte) (0x31 + iNum);
                                certificate_data = mIpodUsb.ioctlRead(
                                        IpodUsb.IPODAUTH_ACCESSORY_GET_CERTIFICATE_DATA,
                                        certificate_data, certificate_data.length);
                                buffer_dai_playload[0] = (byte) (cerLeft + 6);
                                buffer_dai_playload[5] = (byte) iNum;
                                buffer_dai_playload[6] = (byte) iNum;
                                System.arraycopy(certificate_data, 0, buffer_dai_playload, 7,
                                        cerLeft);
                                byte sum = checksum(buffer_dai_playload, 0, cerLeft + 7);
                                buffer_dai[1] = 0x01;
                                System.arraycopy(buffer_dai_playload, 0, buffer_dai, 3, cerLeft + 7);
                                buffer_dai[cerLeft + 10] = sum;
                                writeData(buffer_dai, cerLeft + 11);
                                try {
                                    Thread.sleep(200);
                                } catch (InterruptedException e) {
                                    // TODO Auto-generated catch block
                                    e.printStackTrace();
                                }
                            }
                        }
                            break;
                    }
                    break;
                case IpodUsb.L_ID_EIP:
                    break;
                case IpodUsb.L_ID_DA:
                    switch(result[5]){
                        case 0x02:
                            byte command[] = {0x00,0x00,0x7D,0x00,0x00,0x00,(byte)0xAC,0x44,0x00,0x00,(byte)0xBB,(byte)0x80}; 
                            byte cmd[] = build_cmd1(0x0a,0x03,command,12);
                            writeData(cmd, cmd.length);
                            try {
                                Thread.sleep(200);
                            } catch (InterruptedException e) {
                                // TODO Auto-generated catch block
                                e.printStackTrace();
                            }
                            cmd = build_cmd1(0x00,0x05,null,0);
                            writeData(cmd, cmd.length);
                            break;
                        case 0x04:
                            //mHandler.sendEmptyMessage(1);
                            break;
                    }
                    break;
            }
        }
    }

    public int startAuthenticaion() {
       
        byte[] deviceID = new byte[4];
        deviceID = mIpodUsb.ioctlRead(IpodUsb.IPODAUTH_ACCESSORY_GET_DEVICEID, deviceID, 4);
        byte ack_buffer[] = new byte[64];
        byte buffer_dai_playload[] = new byte[135];
        buffer_dai_playload[0] = (byte) 0x86;
        buffer_dai_playload[1] = 0x00;
        buffer_dai_playload[2] = 0x15;
        buffer_dai_playload[3] = 0x02;
        byte buffer_dai[] = new byte[139];
        buffer_dai[0] = (byte) 0x15;
        buffer_dai[1] = 0x00;
        buffer_dai[2] = 0x55;
        byte certificate_data[] = new byte[128];
        byte buffer_head_playload[] = {
                0x0E, 0x00, 0x13, 0x00, 0x00, 0x04, 0x15, 0x00, 0x00, 0x00, 0x06, deviceID[0],
                deviceID[1], deviceID[2], deviceID[3]
        };
        byte checksum = checksum(buffer_head_playload, 0, buffer_head_playload.length);
        byte buffer_head[] = {
                0x13, 0x00, 0x55, 0x0E, 0x00, 0x13, 0x00, 0x00, 0x04,
                0x15, 0x00, 0x00, 0x00, 0x06, deviceID[0], deviceID[1], deviceID[2], deviceID[3], 0
        };
        buffer_head[18] = checksum;
        if (writeData(buffer_head, buffer_head.length) < 0)
        {
            // LOGE("[%s] >> write head data error.", __FUNCTION__);
            return -1;
        }
        try {
            Thread.sleep(200);
        } catch (InterruptedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
       
        while (!isAuthenticaionSuccess && !isDestroy) {
            Log.e(TAG, "----------!!isAuthenticaionSuccess");
            if (isGetAuthenticaionSignature) {
                Log.e(TAG, "----------isGetAuthenticaionSignature");
                byte aSign[] = new byte[20];
                byte aSignLen[] = {
                        0x00, 0x14
                };
                int signLength = 0;
                byte control[] = {
                    0x01
                };
                byte status[] = {
                    0x00
                };
                byte signData[] = new byte[128];
                byte buffer_sign_playload[] = new byte[160];
                buffer_sign_playload[2] = 0x18;
                byte buffer_sign[] = new byte[160];
                buffer_sign[0] = 0x15;
                buffer_sign[1] = 0x00;
                buffer_sign[2] = 0x55;

                if (mIpodUsb.ioctlWrite(IpodUsb.IPODAUTH_ACCESSORY_SET_CHALLENGE_LEN, aSignLen,
                        aSignLen.length) < 0)
                {
                    return -1;
                }
                if (mIpodUsb.ioctlWrite(IpodUsb.IPODAUTH_ACCESSORY_SET_CHALLENGE_DATA,
                        mGetAuthenticaionSignature, mGetAuthenticaionSignature.length) < 0)
                {
                    return -1;
                }
                if (mIpodUsb.ioctlWrite(IpodUsb.IPODAUTH_ACCESSORY_SET_CONTROL, control,
                        control.length) < 0)
                {
                    return -1;
                }

                while (true)
                {
                    try {
                        Thread.sleep(600);
                    } catch (InterruptedException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                    status = mIpodUsb.ioctlRead(IpodUsb.IPODAUTH_ACCESSORY_GET_READ_STATUS, status,
                            status.length);
                    Log.e(TAG, ">>> status =" + status[0]);
                    if (0x10 == status[0])
                    {
                        break;
                    }
                }
                aSignLen = mIpodUsb.ioctlRead(IpodUsb.IPODAUTH_ACCESSORY_GET_SIGNATURE_LEN,
                        aSignLen, aSignLen.length);
                Log.e(TAG, ">>> aSignLen[0] ." + aSignLen[0] + " aSignLen[1]="
                        + unsignedToBytes(aSignLen[1]));
                signLength = (((aSignLen[0]) << 8) | unsignedToBytes(aSignLen[1]));
                signData[0] = 0x12;
                Log.e(TAG, ">>> get signature data .");
                signData = mIpodUsb.ioctlRead(IpodUsb.IPODAUTH_ACCESSORY_GET_SIGNATURE_DATA,
                        signData, signData.length);
//                Log.e(TAG, "-------------- signature data" + HexDump.dumpHexString(signData));
//                Log.e(TAG, "-------------- ");
//                Log.e(TAG, "--------signLength =  " + signLength);
                buffer_sign_playload[0] = (byte) (signLength + 2);
                // memcpy(&buffer_sign_playload[3], &signData[0], signLength);
                System.arraycopy(signData, 0, buffer_sign_playload, 3, 128);
//                Log.e(TAG,
//                        "-------------- buffer_sign_playload data"
//                                + HexDump.dumpHexString(buffer_sign_playload));
//                Log.e(TAG, "-------------- ");
                checksum = checksum(buffer_sign_playload, 0, signLength + 3);
                // memcpy(&buffer_sign[3], &buffer_sign_playload[0],
                // signLength+3);
                System.arraycopy(buffer_sign_playload, 0, buffer_sign, 3, signLength + 3);
//                Log.e(TAG, "-------------- buffer_sign data" + HexDump.dumpHexString(buffer_sign));
//                Log.e(TAG, "-------------- ");
                buffer_sign[signLength + 6] = checksum;
                writeData(buffer_sign, signLength + 7);
            }
            try {
                Thread.sleep(400);
            } catch (InterruptedException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
        /*
         * while(1) { usb_readData(ack_buffer, sizeof(ack_buffer)); if(0x19 ==
         * ack_buffer[5] && 0x00 == ack_buffer[6]) {
         * LOGE("[%s] >>> Authenticaion success!", __FUNCTION__); break; }
         * if(0x17 == ack_buffer[5]) { byte aSign[20] = {0}; byte aSignLen[2] =
         * {0x00, 0x14}; CARIT_S32 signLength = 0; byte control[1] = {0x01};
         * byte status[1] = {0x00}; byte signData[128] = {0x00}; byte
         * buffer_sign_playload[160] = {0x00, 0x00, 0x18,}; byte
         * buffer_sign[160] = {0x15, 0x00, 0x55, }; memcpy(&aSign[0],
         * &ack_buffer[6], 20);
         * if(ioctl(g_device_fd,IPODAUTH_ACCESSORY_SET_CHALLENGE_LEN,aSignLen) <
         * 0) { LOGE("[%s] >>>>> set challenge length error.", __FUNCTION__);
         * return CARIT_FAIL; }
         * if(ioctl(g_device_fd,IPODAUTH_ACCESSORY_SET_CHALLENGE_DATA,aSign) <
         * 0) { LOGE("[%s] >>>>> set challenge data error.", __FUNCTION__);
         * return CARIT_FAIL; }
         * if(ioctl(g_device_fd,IPODAUTH_ACCESSORY_SET_CONTROL,control) < 0) {
         * LOGE("[%s] >>>>> set control error.", __FUNCTION__); return
         * CARIT_FAIL; } while(1) { usleep(600000);
         * LOGE("[%s] >>>> get read status begin", __FUNCTION__);
         * if(ioctl(g_device_fd,IPODAUTH_ACCESSORY_GET_READ_STATUS,status) < 0)
         * { LOGE("[%s] >>> get read status error", __FUNCTION__); //return
         * CARIT_FAIL; } LOGE("[%s] >> read status = %d", __FUNCTION__,
         * status[0]); if(0x10 == status[0]) { break; } }
         * LOGE("[%s] >>> get signature length .", __FUNCTION__);
         * if(ioctl(g_device_fd,IPODAUTH_ACCESSORY_GET_SIGNATURE_LEN,aSignLen) <
         * 0) { LOGE("[%s] >>> get signature length error.", __FUNCTION__);
         * return CARIT_FAIL; } signLength = ((aSignLen[0] << 8) | aSignLen[1]);
         * signData[0] = 0x12; LOGE("[%s] >>> get signature data .",
         * __FUNCTION__); if(ioctl(g_device_fd,
         * IPODAUTH_ACCESSORY_GET_SIGNATURE_DATA, signData) < 0) {
         * LOGE("[%s] >>> get signature data error.", __FUNCTION__); return
         * CARIT_FAIL; } buffer_sign_playload[0] = (byte)(signLength+2);
         * memcpy(&buffer_sign_playload[3], &signData[0], signLength); checksum
         * = phone_getChecksum(buffer_sign_playload, signLength+3);
         * memcpy(&buffer_sign[3], &buffer_sign_playload[0], signLength+3);
         * buffer_sign[signLength+6] = checksum; usb_writeData(buffer_sign,
         * signLength+7); } }
         */
        return 0;

    }

    int writeData(byte[] buffer, int length) {
        int usbResult;

        Log.i(TAG, ">>>>>>>> length = " + length + HexDump.dumpHexString(buffer));

        Log.i(TAG, "---------------");
        usbResult = usbDeviceConnection.controlTransfer(0x21, // requestType
                0x09, // SET_CONTROL_LINE_STATE
                0x0211, // value
                0x0002, // index
                buffer, // buffer
                length, // length
                100); // timeout

        Log.e(TAG, "controlTransfer(SET_CONTROL_LINE_STATE): " + usbResult);
        return usbResult;
    }

    private byte checksum(byte[] buffer, int offset, int len)
    {
        // int i = 0;
        // int checksum = 0;
        // for (i = 0; i < len; i++)
        // {
        // checksum += buffer[offset + i];
        // }
        // checksum = ~checksum + 1;
        byte checksum = mIpodUsb.checksum(buffer, offset, len);
        // byte checksum = 0;
        // Log.e("Ipod USB", ">> checksum = 0x" +
        // Integer.toHexString(unsignedToBytes((byte) checksum)));
        return (byte) checksum;
    }

    public static int unsignedToBytes(byte b) {
        return b & 0xFF;
    }

    byte[] build_cmd1(int lingo_id, int command_id, byte[] parm, int parm_length) {
        // 4 = 0x13, 0x00, 0x55, packet payload length
        // 2 = lingo id + command id
        // 1 = checksum

        final int length = 4 + 2 + parm_length + 1;
        byte result_t[] = new byte[length];
        byte buffer[] = {
                0x13, 0x00, 0x55, (byte) (length - 5), (byte)lingo_id, (byte)command_id
        };
        for (int i = 0; i < 6; i++) {
            result_t[i] = buffer[i];
        }

        if (parm_length != 0) {
            for (int i = 0; i < parm_length; i++) {
                result_t[6 + i] = parm[i];
            }
        }
        // USB_Printf("[%s] >> sizeof(parm) = [%d] length = [%d] ",
        // __FUNCTION__,parm_length,length);
        result_t[length - 1] = checksum(result_t, 3, length - 4);
        // int iNum = 0;
//        Log.e(TAG, ">> begin. actual_len = " + length);
//        for (int iNum = 0; iNum < length; iNum++)
//        {
//            Log.e(TAG, " [" + iNum + "] = 0x" + Integer.toHexString(result_t[iNum]));
//        }
//        Log.e(TAG, ">> endle.");
        return result_t;
    }

    byte[] build_cmd2(int lingo_id, int command_id1, int command_id2, byte[] parm,
            int parm_length) {
        // 4 = 0x13, 0x00, 0x55, packet payload length
        // 2 = lingo id + command id
        // 1 = checksum

        final int length = 4 + 3 + parm_length + 1;
        byte result_t[] = new byte[length];
        byte buffer[] = {
                0x13, 0x00, 0x55, (byte) (length - 5), (byte)lingo_id, (byte)command_id1, (byte)command_id2
        };
        for (int i = 0; i < 7; i++) {
            result_t[i] = buffer[i];
        }

        if (parm_length != 0) {
            for (int i = 0; i < parm_length; i++) {
                result_t[7 + i] = parm[i];
            }
        }
        // USB_Printf("[%s] >> sizeof(parm) = [%d] length = [%d] ",
        // __FUNCTION__,parm_length,length);
        result_t[length - 1] = checksum(result_t, 3, length - 4);
        // int iNum = 0;
//        Log.e(TAG, ">> begin. actual_len = " + length);
//        for (int iNum = 0; iNum < length; iNum++)
//        {
//            Log.e(TAG, " [" + iNum + "] = 0x" + Integer.toHexString(result_t[iNum]));
//        }
//        Log.e(TAG, ">> endle.");
        return result_t;
    }

    public void onClick(View arg0) {
        switch (arg0.getId()) {
            case R.id.next:
                if (deviceFound != null) {
                    byte cmd[] ={0x03};
                    byte []buffer = build_cmd2(0x4, 0x0, 0x29, cmd, 1);
                    writeData(buffer, buffer.length);
                    //Log.e(TAG, "controlTransfer(SET_CONTROL_LINE_STATE): " + usbResult);
                } else {
                    Toast.makeText(MainActivity.this,
                            "deviceFound == null",
                            Toast.LENGTH_LONG).show();
                }
                break;
            case R.id.play:
                if (deviceFound != null) {

                    byte cmd[] ={0x01};
                    byte []buffer = build_cmd2(0x4, 0x0, 0x29, cmd, 1);
                    writeData(buffer, buffer.length);
                } else {
                    Toast.makeText(MainActivity.this,
                            "deviceFound == null",
                            Toast.LENGTH_LONG).show();
                }

                break;
            case R.id.prv:
                if (deviceFound != null) {

                    byte cmd[] ={0x04};
                    byte []buffer = build_cmd2(0x4, 0x0, 0x29, cmd, 1);
                    writeData(buffer, buffer.length);
                } else {
                    Toast.makeText(MainActivity.this,
                            "deviceFound == null",
                            Toast.LENGTH_LONG).show();
                }
                break;
        }

    }

}

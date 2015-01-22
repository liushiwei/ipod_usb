LOCAL_PATH := $(call my-dir)

 include $(CLEAR_VARS)   
LOCAL_MODULE    := static  
LOCAL_SRC_FILES := libusb1.0.a  
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)   
LOCAL_MODULE    := libusb1.0  
LOCAL_SRC_FILES := libusb1.0.so  
include $(PREBUILT_SHARED_LIBRARY)

include $(CLEAR_VARS)

LOCAL_STATIC_LIBRARIES := static  
LOCAL_LDLIBS := -llog  
LOCAL_MODULE    := usbipod

LOCAL_SRC_FILES := hello-a.c \
				ipod_usb.c

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := \
       ipod_usb.c \

LOCAL_C_INCLUDES += $(JNI_H_INCLUDE) $(LOCAL_PATH)
        
LOCAL_SHARED_LIBRARIES := libutils libc libusb1.0

LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog
LOCAL_LDLIBS := -llog
 
LOCAL_MODULE := ipod_usb
include $(BUILD_SHARED_LIBRARY)

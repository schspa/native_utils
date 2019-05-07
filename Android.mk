LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := inject
LOCAL_SRC_FILES := inject.c main.c


LOCAL_LDLIBS := -llog
#LOCAL_FORCE_STATIC_EXECUTABLE := true

include $(BUILD_EXECUTABLE)


include $(CLEAR_VARS)

LOCAL_LDLIBS += -llog
#LOCAL_ARM_MODE := arm
LOCAL_MODULE    := entry
LOCAL_SRC_FILES := entry.c
include $(BUILD_SHARED_LIBRARY)

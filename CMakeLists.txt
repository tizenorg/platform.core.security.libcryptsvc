CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(cryptsvc C)

SET(PREFIX ${CMAKE_INSTALL_PREFIX})
SET(EXEC_PREFIX "\${prefix}")
SET(INCLUDEDIR "\${prefix}/include")

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/include)

SET(pc_requires " openssl dlog libcrypto capi-system-info")

INCLUDE(FindPkgConfig)
pkg_check_modules(pkgs REQUIRED ${pc_requires})

FOREACH(flag ${pkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

SET(source_dir "./srcs")
SET(include_dir "./include")
SET(test_dir "./test")

SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -fvisibility=hidden")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}")
SET(EXTRA_CXXFLAGS "${EXTRA_CXXFLAGS} ${EXTRA_CFLAGS}")

#ADD_DEFINITIONS("-DCTR_SUPPORT")	# for using CTR mode
#ADD_DEFINITIONS("-DCRYPT_SVC_LOG")	# for debug
#ADD_DEFINITIONS("-DCRYPTOSVC_TARGET")	# to get DUK from Target

##################################################################################################################
# for libcryptsvc.so
SET(SRCS
	${source_dir}/SecCryptoSvc.c
)

SET(libcryptsvc_LDFLAGS "${pkgs_LDFLAGS}")
SET(libcryptsvc_CFLAGS " ${CFLAGS} -fvisibility=hidden -g -fPIC -I${CMAKE_CURRENT_SOURCE_DIR}/include ")
SET(libcryptsvc_CPPFLAGS " -DPIC ")

ADD_LIBRARY(${PROJECT_NAME} SHARED ${SRCS})

TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${libcryptsvc_LDFLAGS})

IF("${ARCH}" MATCHES "arm")
TARGET_LINK_LIBRARIES(${PROJECT_NAME})
ENDIF("${ARCH}" MATCHES "arm")

SET_TARGET_PROPERTIES(
	${PROJECT_NAME}
	PROPERTIES
	VERSION ${FULLVER}
	SOVERSION ${MAJORVER}
)
##################################################################################################################

##################################################################################################################
# for libdevice_info.so
SET(SRCS_DEVICE_INFO
    ${source_dir}/device_info.c
)

SET(libdevice_info_LDFLAGS "${pkgs_LDFLAGS}")
SET(libdevice_info_CFLAGS " ${CFLAGS} ${CMAKE_C_FLAGS} -fvisibility=hidden -g -fPIC -I${CMAKE_CURRENT_SOURCE_DIR}/include ")
SET(libdevice_info_CPPFLAGS " -DPIC ")

SET(LIBDEVICE_INFO_SO "device_info")
ADD_LIBRARY(${LIBDEVICE_INFO_SO} SHARED ${SRCS_DEVICE_INFO})

TARGET_LINK_LIBRARIES(${LIBDEVICE_INFO_SO} ${libdevice_info_LDFLAGS} cryptsvc)

IF("${ARCH}" MATCHES "arm")
TARGET_LINK_LIBRARIES(${LIBDEVICE_INFO_SO})
ENDIF("${ARCH}" MATCHES "arm")


SET_TARGET_PROPERTIES(
    ${LIBDEVICE_INFO_SO}
    PROPERTIES
    VERSION ${FULLVER}
    SOVERSION ${MAJORVER}
)
##################################################################################################################


##################################################################################################################
# for module_test
#SET(module_test_SOURCES
	#${test_dir}/module_test.c
	#${source_dir}/CryptoSvc-debug.c
#)

#SET(module_test_CFLAGS " -fvisibility=hidden -I. -I${CMAKE_CURRENT_SOURCE_DIR}/include ")
#SET(module_test_LDFALGS " -module -avoid-version ${pkgs_LDFLAGS} ")

#ADD_EXECUTABLE(${test_dir}/module_test ${module_test_SOURCES})
#TARGET_LINK_LIBRARIES(${test_dir}/module_test ${pkgs_LDFLAGS} cryptsvc)
#SET_TARGET_PROPERTIES(${test_dir}/module_test PROPERTIES COMPILE_FLAGS "${module_test_CFLAGS} ")
##################################################################################################################

#FIND_PROGRAM(UNAME NAMES uname)
#EXEC_PROGRAM("${UNAME}" ARGS "-m" OUTPUT_VARIABLE "ARCH")
IF("${ARCH}" MATCHES "arm")
	#ADD_DEFINITIONS("-DTARGET")
	ADD_DEFINITIONS("-DCRYPTOSVC_TARGET")
	ADD_DEFINITIONS("-DCRYPTOSVC_TZ")
	#MESSAGE("add -DTARGET")
ENDIF("${ARCH}" MATCHES "arm")

SET(PC_NAME ${PROJECT_NAME})
SET(PC_DESCRIPTION ${DESCRIPTION})
SET(PC_LDFLAGS " -l${PROJECT_NAME} ")
SET(PC_REQUIRED ${pc_requires})
CONFIGURE_FILE(${PROJECT_NAME}.pc.in ${PROJECT_NAME}.pc @ONLY)

INSTALL(FILES ${PROJECT_NAME}.pc DESTINATION ${LIB_INSTALL_DIR}/pkgconfig)
INSTALL(TARGETS ${PROJECT_NAME} DESTINATION ${LIB_INSTALL_DIR})
INSTALL(TARGETS ${LIBDEVICE_INFO_SO} DESTINATION ${LIB_INSTALL_DIR})
INSTALL(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/ DESTINATION ${INCLUDEDIR})

ADD_DEFINITIONS(-D_bool_cryptsvc)

ADD_SUBDIRECTORY(gadget)

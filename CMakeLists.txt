CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(cryptsvc C)

SET(PREFIX ${CMAKE_INSTALL_PREFIX})
SET(EXEC_PREFIX "\${prefix}")
SET(LIBDIR "\${prefix}/lib")
SET(INCLUDEDIR "\${prefix}/include")

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/include)

SET(pc_requires " openssl dlog libcrypto ")

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
	#${source_dir}/CryptoSvc-debug.c
	${source_dir}/SecCryptoSvc.c
	#${source_dir}/SecKmBase64.c
)

SET(libcryptsvc_LDFLAGS "${pkgs_LDFLAGS}")
SET(libcryptsvc_CFLAGS " ${CFLAGS} -fvisibility=hidden -g -fPIC -I${CMAKE_CURRENT_SOURCE_DIR}/include ")
SET(libcryptsvc_CPPFLAGS " -DPIC ")

ADD_LIBRARY(${PROJECT_NAME} SHARED ${SRCS})

TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${libcryptsvc_LDFLAGS})

IF("${ARCH}" MATCHES "arm")
TARGET_LINK_LIBRARIES(${PROJECT_NAME} -L./libs -lDeviceInfo)
ENDIF("${ARCH}" MATCHES "arm")

SET_TARGET_PROPERTIES(
	${PROJECT_NAME}
	PROPERTIES
	VERSION ${FULLVER}
	SOVERSION ${MAJORVER}
)
##################################################################################################################

##################################################################################################################
# for libtzsvc.so
SET(SRCS_TZ
	${source_dir}/SecCryptoSvc.c
	${source_dir}/SecTzSvc.c
)

SET(libtzsvc_LDFLAGS "${pkgs_LDFLAGS}")
SET(libtzsvc_CFLAGS " ${CFLAGS} -fvisibility=hidden -g -fPIC -I${CMAKE_CURRENT_SOURCE_DIR}/include ")
SET(libtzsvc_CPPFLAGS " -DPIC ")

SET(LIBTZ_SO "tzsvc")
ADD_LIBRARY(${LIBTZ_SO} SHARED ${SRCS_TZ})

TARGET_LINK_LIBRARIES(${LIBTZ_SO} ${libtzsvc_LDFLAGS})

IF("${ARCH}" MATCHES "arm")
TARGET_LINK_LIBRARIES(${LIBTZ_SO} -L./libs -lDeviceInfo)
ENDIF("${ARCH}" MATCHES "arm")

SET_TARGET_PROPERTIES(
	${LIBTZ_SO}
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
	#MESSAGE("add -DTARGET")
ENDIF("${ARCH}" MATCHES "arm")

SET(PC_NAME ${PROJECT_NAME})
SET(PC_DESCRIPTION ${DESCRIPTION})
SET(PC_LDFLAGS " -l${PROJECT_NAME} -l${LIBTZ_SO} ")
SET(PC_REQUIRED ${pc_requires})
CONFIGURE_FILE(${PROJECT_NAME}.pc.in ${PROJECT_NAME}.pc @ONLY)

INSTALL(FILES ${PROJECT_NAME}.pc DESTINATION lib/pkgconfig)
INSTALL(TARGETS ${PROJECT_NAME} DESTINATION lib)
INSTALL(TARGETS ${LIBTZ_SO} DESTINATION lib)
INSTALL(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/ DESTINATION ${INCLUDEDIR})

ADD_DEFINITIONS(-D_bool_cryptsvc)

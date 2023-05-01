/* Copyright (c) 2023 Cameron Harper
 *
 * */

#ifndef WIC_CONFIG_H
#define WIC_CONFIG_H

#include <stdio.h>
#include <inttypes.h>
#include <assert.h>

#define WIC_DEBUG(TAG, ...) do{printf("DEBUG %s: ", TAG);printf(__VA_ARGS__);printf("\n");}while(0);
#define WIC_ERROR(TAG, ...) do{printf("ERROR %s: ", TAG);printf(__VA_ARGS__);printf("\n");}while(0);
#define WIC_ASSERT(XX) assert(XX);

#endif

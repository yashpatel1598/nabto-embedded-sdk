#ifndef _NC_IAM_DUMP_H_
#define _NC_IAM_DUMP_H_

#include "nc_iam.h"

#include <platform/np_error_code.h>
#include <string.h>
#include <cbor.h>


np_error_code nc_iam_dump(struct nc_iam* iam, uint64_t* version, void* buffer, size_t bufferLength, size_t* used);
np_error_code nc_iam_load(struct nc_iam* iam, void* cbor, size_t cborLength);
void nc_iam_dump_user(struct nc_iam* iam, struct nc_iam_user* user, CborEncoder* encoder);

#endif
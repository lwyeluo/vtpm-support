/*
 * QEMU PowerPC pSeries Logical Partition (aka sPAPR) hardware System Emulator
 *
 * PAPR Virtual TPM, aka ibmvtpm
 *
 * Copyright (c) 2015 IBM Corporation.
 *
 * Authors:
 *    Stefan Berger <stefanb@linux.vnet.ibm.com>
 *
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */
#ifndef TPM_SPAPR_VTPM_H
#define TPM_SPAPR_VTPM_H

#include "hw/ppc/spapr.h"
#include "hw/ppc/spapr_vio.h"

typedef struct vio_crq {
    uint8_t valid;  /* 0x80: cmd; 0xc0: init crq
                       0x81-0x83: CRQ message response */
    uint8_t msg;    /* see below */
    uint16_t len;   /* len of TPM request; len of TPM response */
    uint32_t data;  /* rtce_dma_handle when sending TPM request */
    uint64_t reserved;
} vio_crq;

typedef union spapr_vtpm_crq {
    vio_crq s;
    uint8_t raw[sizeof(vio_crq)];
} spapr_vtpm_crq;

#define SPAPR_VTPM_VALID_INIT_CRQ_COMMAND  0xC0
#define SPAPR_VTPM_VALID_COMMAND           0x80
#define SPAPR_VTPM_MSG_RESULT              0x80

/* msg types for valid = SPAPR_VTPM_VALID_INIT_CRQ */
#define SPAPR_VTPM_INIT_CRQ_RESULT           0x1
#define SPAPR_VTPM_INIT_CRQ_COMPLETE_RESULT  0x2

/* msg types for valid = SPAPR_VTPM_VALID_CMD */
#define SPAPR_VTPM_GET_VERSION               0x1
#define SPAPR_VTPM_TPM_COMMAND               0x2
#define SPAPR_VTPM_GET_RTCE_BUFFER_SIZE      0x3
#define SPAPR_VTPM_PREPARE_TO_SUSPEND        0x4

#endif /* TPM_SPAPR_VTPM_H */

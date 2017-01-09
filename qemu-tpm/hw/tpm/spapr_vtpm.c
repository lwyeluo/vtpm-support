/*
 * QEMU PowerPC pSeries Logical Partition (aka sPAPR) hardware System Emulator
 *
 * PAPR Virtual TPM, aka ibmvtpm
 *
 * Parts based on spapr_vscsi.c
 * Copyright (c) 2010,2011 Benjamin Herrenschmidt, IBM Corporation.
 *
 * Parts based on tpm_tis.c
 * Copyright (C) 2006,2010-2013 IBM Corporation
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

/*
 * For communication with the backend we are using the data structures used
 * by the TPM TIS implementation (tpm_tis.c), which provides a superset of
 * functionality with up to 5 localities. We always use locality = 0 and
 * reuse the buffer to transfer the TPM command packets to the backend and
 * receive TPM responses from the backend.
 */

#include "sysemu/tpm_backend.h"
#include "tpm_int.h"
#include "qemu/main-loop.h"
#include "sysemu/tpm_backend.h"

#include "spapr_vtpm.h"
#include "hw/ppc/spapr.h"
#include "hw/ppc/spapr_vio.h"

#include <libfdt.h>

#define DEBUG_SPAPR_VTPM 0

#define DPRINTF(fmt, ...) do { \
    if (DEBUG_SPAPR_VTPM) { \
        printf("QEMU-vTPM:" fmt, ## __VA_ARGS__); \
    } \
} while (0);


#define TYPE_VIO_SPAPR_VTPM_DEVICE "spapr-vtpm"
#define VIO_SPAPR_VTPM_DEVICE(obj) \
     OBJECT_CHECK(SPAPRvTPMState, (obj), TYPE_VIO_SPAPR_VTPM_DEVICE)

typedef struct {
    VIOsPAPRDevice vdev;

    spapr_vtpm_crq crq; /* track single TPM command */

    union {
        /*
         * The backends expect TIS related data structures;
         * we reuse it but only use locality 0.
         */
        TPMTISEmuState tis;
    } s;

    uint8_t     locty_number;
    TPMLocality *locty_data;

    char *backend;
    TPMBackend *be_driver;
    TPMVersion be_tpm_version;

    QemuMutex state_lock;
    QemuCond cmd_complete;
} SPAPRvTPMState;

/* Only use 1 locality (locality 0) */
#define SPAPR_VTPM_NUM_LOCALITIES 1

static uint32_t spapr_vtpm_get_size_from_buffer(const TPMSizedBuffer *sb)
{
    return be32_to_cpu(*(uint32_t *)&sb->buffer[2]);
}

static void spapr_vtpm_show_buffer(const TPMSizedBuffer *sb, const char *string)
{
#if DEBUG_SPAPR_VTPM
    uint32_t len, i;

    len = spapr_vtpm_get_size_from_buffer(sb);
    printf("spapr_vtpm: %s length = %d\n", string, len);
    for (i = 0; i < len; i++) {
        if (i && !(i % 16)) {
            printf("\n");
        }
        printf("%.2X ", sb->buffer[i]);
    }
    printf("\n");
#endif
}

/*
 * Send a request to the TPM.
 */
static void spapr_vtpm_tpm_send(SPAPRvTPMState *s, uint8_t locty)
{
    TPMTISEmuState *tis = &s->s.tis;

    spapr_vtpm_show_buffer(&tis->loc[locty].w_buffer, "spapr_vtpm: Tx TPM");

    s->locty_number = locty;
    s->locty_data = &tis->loc[locty];

    /*
     * w_offset serves as length indicator for length of data;
     * it's reset when the response comes back.
     * Since we copy the data via DMA, we need to set it here explicitly.
     */
    tis->loc[locty].w_offset =
        spapr_vtpm_get_size_from_buffer(&tis->loc[locty].w_buffer);

    tis->loc[locty].state = TPM_TIS_STATE_EXECUTION;

    tpm_backend_deliver_request(s->be_driver);
}

static void spapr_vtpm_got_payload(SPAPRvTPMState *s, spapr_vtpm_crq *crq)
{
    TPMTISEmuState *tis = &s->s.tis;
    uint8_t locty = 0;

    DPRINTF("vtpm_got_payload: crq->s.data = 0x%x  crq->s.len = %d\n",
            crq->s.data, crq->s.len);
    /* XXX Handle failure differently ? */
    if (spapr_vio_dma_read(&s->vdev, crq->s.data,
                           tis->loc[locty].w_buffer.buffer,
                           tis->loc[locty].w_buffer.size)) {
        fprintf(stderr, "vtpm_got_payload: DMA read failure !\n");
        return;
    }

    /* let vTPM handle any malformed request */
    spapr_vtpm_tpm_send(s, locty);
}

static int spapr_vtpm_do_crq(struct VIOsPAPRDevice *dev, uint8_t *crq_data)
{
    SPAPRvTPMState *s = VIO_SPAPR_VTPM_DEVICE(dev);
    TPMTISEmuState *tis = &s->s.tis;
    uint8_t locty = 0;
    spapr_vtpm_crq local_crq;
    spapr_vtpm_crq *crq = &s->crq; /* use for TPM requests only */

    memcpy(&local_crq.raw, crq_data, sizeof(local_crq.raw));

    DPRINTF("VTPM: do_crq %02x %02x ...\n",
            local_crq.raw[0], local_crq.raw[1]);

    switch (local_crq.s.valid) {
    case SPAPR_VTPM_VALID_INIT_CRQ_COMMAND: /* Init command/response */

        /* Respond to initialization request */
        switch (local_crq.s.msg) {
        case SPAPR_VTPM_INIT_CRQ_RESULT:
            DPRINTF("vtpm_do_crq: SPAPR_VTPM_INIT_CRQ_RESULT\n");
            memset(local_crq.raw, 0, sizeof(local_crq.raw));
            local_crq.s.valid = SPAPR_VTPM_VALID_INIT_CRQ_COMMAND;
            local_crq.s.msg = SPAPR_VTPM_INIT_CRQ_RESULT;
            spapr_vio_send_crq(dev, local_crq.raw);
            break;

        case SPAPR_VTPM_INIT_CRQ_COMPLETE_RESULT:
            DPRINTF("vtpm_do_crq: SPAPR_VTPM_INIT_CRQ_COMP_RESULT\n");
            memset(local_crq.raw, 0, sizeof(local_crq.raw));
            local_crq.s.valid = SPAPR_VTPM_VALID_INIT_CRQ_COMMAND;
            local_crq.s.msg = SPAPR_VTPM_INIT_CRQ_COMPLETE_RESULT;
            spapr_vio_send_crq(dev, local_crq.raw);
            break;
        }

        break;
    case SPAPR_VTPM_VALID_COMMAND: /* Payloads */
        switch (local_crq.s.msg) {
        case SPAPR_VTPM_TPM_COMMAND:
            DPRINTF("vtpm_do_crq: got TPM command payload!\n");
            if (tis->loc[locty].state == TPM_TIS_STATE_EXECUTION)
                return H_BUSY;
            /* this crq is tracked */
            memcpy(crq->raw, crq_data, sizeof(crq->raw));
            crq->s.valid = be16_to_cpu(0);
            crq->s.len = be16_to_cpu(crq->s.len);
            crq->s.data = be32_to_cpu(crq->s.data);
            spapr_vtpm_got_payload(s, crq);
            break;

        case SPAPR_VTPM_GET_RTCE_BUFFER_SIZE:
            DPRINTF("vtpm_do_crq: resp: buffer size is %u\n",
                    tis->loc[locty].w_buffer.size);
            local_crq.s.msg |= SPAPR_VTPM_MSG_RESULT;
            local_crq.s.len = cpu_to_be16(tis->loc[locty].w_buffer.size);
            spapr_vio_send_crq(dev, local_crq.raw);
            break;

        case SPAPR_VTPM_GET_VERSION:
            DPRINTF("vtpm_do_crq: resp: version 1\n");
            local_crq.s.msg |= SPAPR_VTPM_MSG_RESULT;
            local_crq.s.len = cpu_to_be16(0);
            switch (s->be_tpm_version) {
            case TPM_VERSION_UNSPEC:
                local_crq.s.data = cpu_to_be32(0);
                break;
            case TPM_VERSION_1_2:
                local_crq.s.data = cpu_to_be32(1);
                break;
            case TPM_VERSION_2_0:
                local_crq.s.data = cpu_to_be32(2);
                break;
            }
            spapr_vio_send_crq(dev, local_crq.raw);
            break;

        case SPAPR_VTPM_PREPARE_TO_SUSPEND:
            DPRINTF("vtpm_do_crq: resp: prep to suspend\n");
            local_crq.s.msg |= SPAPR_VTPM_MSG_RESULT;
            spapr_vio_send_crq(dev, local_crq.raw);
            break;

        default:
            fprintf(stderr, "vtpm_do_crq: Unknown message type %02x\n",
                    crq->s.msg);
        }
        break;
    default:
        fprintf(stderr, "vtpm_do_crq: unknown CRQ %02x %02x ...\n",
                local_crq.raw[0], local_crq.raw[1]);
    };

    return 0;
}

static void spapr_vtpm_receive_bh(void *opaque)
{
    SPAPRvTPMState *s = opaque;
    TPMTISEmuState *tis = &s->s.tis;
    spapr_vtpm_crq *crq = &s->crq;
    uint8_t locty = 0;
    uint32_t len;
    int rc;

    tis->bh_scheduled = false;

    qemu_mutex_lock(&s->state_lock);

    tis->loc[locty].state = TPM_TIS_STATE_COMPLETION;
    tis->loc[locty].r_offset = 0;
    tis->loc[locty].w_offset = 0;

    len = spapr_vtpm_get_size_from_buffer(&tis->loc[locty].r_buffer);

    spapr_vtpm_show_buffer(&tis->loc[locty].r_buffer, "spapr_vtpm: rx TPM");

    DPRINTF("dma_write to crq->s.data = 0x%x\n", crq->s.data);
    rc = spapr_vio_dma_write(&s->vdev, crq->s.data,
                             tis->loc[locty].r_buffer.buffer,
                             MIN(len, tis->loc[locty].r_buffer.size));

    crq->s.valid = SPAPR_VTPM_MSG_RESULT;
    crq->s.msg = SPAPR_VTPM_TPM_COMMAND | SPAPR_VTPM_MSG_RESULT;
    crq->s.len = cpu_to_be16(len);
    crq->s.data = cpu_to_be32(crq->s.data);

    if (rc == 0) {
        rc = spapr_vio_send_crq(&s->vdev, crq->raw);
        if (rc) {
            fprintf(stderr, "spapr_vtpm_receive_bh: Error sending response\n");
        }
    } else {
        fprintf(stderr, "spapr_vtpm_receive_bh: Error with DMA write\n");
    }

    /* notify of completed command */
    qemu_cond_signal(&s->cmd_complete);
    qemu_mutex_unlock(&s->state_lock);
}

/*
 * Callback from the TPM to indicate that the response was received.
 */
static void spapr_vtpm_receive_cb(void *opaque, uint8_t locty,
                                  bool is_selftest_done)
{
    SPAPRvTPMState *s = opaque;
    TPMTISEmuState *tis = &s->s.tis;

    qemu_mutex_lock(&s->state_lock);
    /* notify of completed command */
    qemu_cond_signal(&s->cmd_complete);
    qemu_mutex_unlock(&s->state_lock);

    qemu_bh_schedule(tis->bh);

    tis->bh_scheduled = true;
}

static int spapr_vtpm_do_startup_tpm(SPAPRvTPMState *s)
{
    return tpm_backend_startup_tpm(s->be_driver);
}

/*
 * Get the TPMVersion of the backend device being used
 */
TPMVersion spapr_vtpm_get_tpm_version(Object *obj)
{
    SPAPRvTPMState *s = VIO_SPAPR_VTPM_DEVICE(obj);

    return tpm_backend_get_tpm_version(s->be_driver);
}

static void spapr_vtpm_reset(VIOsPAPRDevice *dev)
{
    SPAPRvTPMState *s = VIO_SPAPR_VTPM_DEVICE(dev);
    TPMTISEmuState *tis = &s->s.tis;
    int c;

    s->be_tpm_version = tpm_backend_get_tpm_version(s->be_driver);

    tpm_backend_reset(s->be_driver);

    for (c = 0; c < SPAPR_VTPM_NUM_LOCALITIES; c++) {
        tis->loc[c].w_offset = 0;
        tpm_backend_realloc_buffer(s->be_driver, &tis->loc[c].w_buffer);
        tis->loc[c].r_offset = 0;
        tpm_backend_realloc_buffer(s->be_driver, &tis->loc[c].r_buffer);
    }

    spapr_vtpm_do_startup_tpm(s);
}

void spapr_vtpm_create(VIOsPAPRBus *bus)
{
    DeviceState *dev;

    DPRINTF("%s\n", __func__);

    dev = qdev_create(&bus->bus, "spapr-vtpm");

    qdev_init_nofail(dev);
}

/* persistent state handling */

static void spapr_vtpm_pre_save(void *opaque)
{
    TPMState *s = opaque;
    TPMTISEmuState *tis = &s->s.tis;
    uint8_t locty = 0;

    DPRINTF("vtpm: suspend: locty = %d : r_offset = %d, w_offset = %d\n",
            locty, tis->loc[0].r_offset, tis->loc[0].w_offset);

    qemu_mutex_lock(&s->state_lock);

    /* wait for outstanding request to complete */
    if (tis->loc[locty].state == TPM_TIS_STATE_EXECUTION) {
        /*
         * If we get here when the bh is scheduled but did not run,
         * we won't get notified...
         */
        if (!tis->bh_scheduled) {
            /* backend thread to notify us */
            qemu_cond_wait(&s->cmd_complete, &s->state_lock);
        }
        if (tis->loc[locty].state == TPM_TIS_STATE_EXECUTION) {
            /* bottom half did not run - run its function */
            qemu_mutex_unlock(&s->state_lock);
            spapr_vtpm_receive_bh(opaque);
            qemu_mutex_lock(&s->state_lock);
        }
    }

    qemu_mutex_unlock(&s->state_lock);

    /*
     * requests are immediately sent to the backend, so we only ever
     * have a buffer with TPM response data.
     */
    switch (tis->loc[locty].state) {
    case TPM_TIS_STATE_COMPLETION:
        memcpy(tis->buf,
               tis->loc[locty].r_buffer.buffer,
               MIN(sizeof(tis->buf),
                   tis->loc[locty].r_buffer.size));
    break;
    default:
        /* leak nothing */
        memset(tis->buf, 0, sizeof(tis->buf));
    break;
    }
}

static int spapr_vtpm_post_load(void *opaque,
                                int version_id __attribute__((unused)))
{
    TPMState *s = opaque;
    TPMTISEmuState *tis = &s->s.tis;
    uint8_t locty = 0;

    switch (tis->loc[locty].state) {
    case TPM_TIS_STATE_COMPLETION:
        memcpy(tis->loc[locty].r_buffer.buffer,
               tis->buf,
               MIN(sizeof(tis->buf),
                   tis->loc[locty].r_buffer.size));
    break;
    default:
    break;
    }

    DPRINTF("tpm_tis: resume : locty = %d : r_offset = %d, w_offset = %d\n",
            locty, tis->loc[0].r_offset, tis->loc[0].w_offset);

    return 0;
}

static const VMStateDescription vmstate_locty = {
    .name = "loc",
    .version_id = 1,
    .minimum_version_id = 0,
    .minimum_version_id_old = 0,
    .fields      = (VMStateField[]) {
        VMSTATE_UINT32(state, TPMLocality),
        VMSTATE_END_OF_LIST(),
    }
};

static const VMStateDescription vmstate_spapr_vtpm = {
    .name = "spapr_vtpm",
    .version_id = 1,
    .minimum_version_id = 0,
    .minimum_version_id_old = 0,
    .pre_save  = spapr_vtpm_pre_save,
    .post_load = spapr_vtpm_post_load,
    .fields = (VMStateField[]) {
        VMSTATE_SPAPR_VIO(vdev, SPAPRvTPMState),

        VMSTATE_STRUCT_ARRAY(s.tis.loc, TPMState, TPM_TIS_NUM_LOCALITIES, 1,
                             vmstate_locty, TPMLocality),

        VMSTATE_END_OF_LIST()
    },
};

static Property spapr_vtpm_properties[] = {
    DEFINE_SPAPR_PROPERTIES(SPAPRvTPMState, vdev),
    DEFINE_PROP_STRING("tpmdev", SPAPRvTPMState, backend),
    DEFINE_PROP_END_OF_LIST(),
};

static void spapr_vtpm_realizefn(VIOsPAPRDevice *dev, Error **errp)
{
    SPAPRvTPMState *s = VIO_SPAPR_VTPM_DEVICE(dev);

    dev->crq.SendFunc = spapr_vtpm_do_crq;

    s->be_driver = qemu_find_tpm(s->backend);
    if (!s->be_driver) {
        error_setg(errp, "spapr_vtpm: backend driver with id %s could not be "
                   "found", s->backend);
        return;
    }

    s->be_driver->fe_model = TPM_MODEL_SPAPR_VTPM;

    if (tpm_backend_init(s->be_driver, s, &s->locty_number, &s->locty_data,
                         spapr_vtpm_receive_cb)) {
        error_setg(errp, "spapr_vtpm: backend driver with id %s could not be "
                   "initialized", s->backend);
        return;
    }

    s->s.tis.bh = qemu_bh_new(spapr_vtpm_receive_bh, s);
}

static void spapr_vtpm_initfn(Object *obj)
{
    SPAPRvTPMState *s = VIO_SPAPR_VTPM_DEVICE(obj);

    qemu_mutex_init(&s->state_lock);
    qemu_cond_init(&s->cmd_complete);
}

static void spapr_vtpm_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VIOsPAPRDeviceClass *k = VIO_SPAPR_DEVICE_CLASS(klass);

    k->realize = spapr_vtpm_realizefn;
    k->reset = spapr_vtpm_reset;
    k->dt_name = "vtpm";
    k->dt_type = "IBM,vtpm";
    k->dt_compatible = "IBM,vtpm";
    k->signal_mask = 0x00000001;
    k->rtce_window_size = 0x10000000;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    dc->props = spapr_vtpm_properties;
    dc->vmsd = &vmstate_spapr_vtpm;
}

static const TypeInfo spapr_vtpm_info = {
    .name          = TYPE_VIO_SPAPR_VTPM_DEVICE,
    .parent        = TYPE_VIO_SPAPR_DEVICE,
    .instance_size = sizeof(SPAPRvTPMState),
    .instance_init = spapr_vtpm_initfn,
    .class_init    = spapr_vtpm_class_init,
};

static void spapr_vtpm_register_types(void)
{
    type_register_static(&spapr_vtpm_info);
    tpm_register_model(TPM_MODEL_SPAPR_VTPM);
}

type_init(spapr_vtpm_register_types)

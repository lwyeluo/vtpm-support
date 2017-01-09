/*
 * TPM utility functions
 *
 *  Copyright (c) 2010 - 2015 IBM Corporation
 *  Authors:
 *    Stefan Berger <stefanb@us.ibm.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>
 */

#include "tpm_util.h"
#include "tpm_int.h"
#include "tpm_ioctl.h"
#include "qemu/error-report.h"

#define DEBUG_TPM 0

#define DPRINTF(fmt, ...) do { \
    if (DEBUG_TPM) { \
        fprintf(stderr, fmt, ## __VA_ARGS__); \
    } \
} while (0)


/*
 * A basic test of a TPM device. We expect a well formatted response header
 * (error response is fine) within one second.
 */
static int tpm_util_test(int fd,
                         unsigned char *request,
                         size_t requestlen,
                         uint16_t *return_tag)
{
    struct tpm_resp_hdr *resp;
    fd_set readfds;
    int n;
    struct timeval tv = {
        .tv_sec = 1,
        .tv_usec = 0,
    };
    unsigned char buf[1024];

    n = write(fd, request, requestlen);
    if (n < 0) {
        return errno;
    }
    if (n != requestlen) {
        return EFAULT;
    }

    FD_ZERO(&readfds);
    FD_SET(fd, &readfds);

    /* wait for a second */
    n = select(fd + 1, &readfds, NULL, NULL, &tv);
    if (n != 1) {
        return errno;
    }

    n = read(fd, &buf, sizeof(buf));
    if (n < sizeof(struct tpm_resp_hdr)) {
        return EFAULT;
    }

    resp = (struct tpm_resp_hdr *)buf;
    /* check the header */
    if (be32_to_cpu(resp->len) != n) {
        return EBADMSG;
    }

    *return_tag = be16_to_cpu(resp->tag);

    return 0;
}

/*
 * Probe for the TPM device in the back
 * Returns 0 on success with the version of the probed TPM set, 1 on failure.
 */
int tpm_util_test_tpmdev(int tpm_fd, TPMVersion *tpm_version)
{
    /*
     * Sending a TPM1.2 command to a TPM2 should return a TPM1.2
     * header (tag = 0xc4) and error code (TPM_BADTAG = 0x1e)
     *
     * Sending a TPM2 command to a TPM 2 will give a TPM 2 tag in the
     * header.
     * Sending a TPM2 command to a TPM 1.2 will give a TPM 1.2 tag
     * in the header and an error code.
     */
    const struct tpm_req_hdr test_req = {
        .tag = cpu_to_be16(TPM_TAG_RQU_COMMAND),
        .len = cpu_to_be32(sizeof(test_req)),
        .ordinal = cpu_to_be32(TPM_ORD_GetTicks),
    };

    const struct tpm_req_hdr test_req_tpm2 = {
        .tag = cpu_to_be16(TPM2_ST_NO_SESSIONS),
        .len = cpu_to_be32(sizeof(test_req_tpm2)),
        .ordinal = cpu_to_be32(TPM2_CC_ReadClock),
    };
    uint16_t return_tag;
    int ret;

    /* Send TPM 2 command */
    ret = tpm_util_test(tpm_fd, (unsigned char *)&test_req_tpm2,
                        sizeof(test_req_tpm2), &return_tag);
    /* TPM 2 would respond with a tag of TPM2_ST_NO_SESSIONS */
    if (!ret && return_tag == TPM2_ST_NO_SESSIONS) {
        *tpm_version = TPM_VERSION_2_0;
        return 0;
    }

    /* Send TPM 1.2 command */
    ret = tpm_util_test(tpm_fd, (unsigned char *)&test_req,
                        sizeof(test_req), &return_tag);
    if (!ret && return_tag == TPM_TAG_RSP_COMMAND) {
        *tpm_version = TPM_VERSION_1_2;
        /* this is a TPM 1.2 */
        return 0;
    }

    *tpm_version = TPM_VERSION_UNSPEC;

    return 1;
}

static void tpm_sized_buffer_reset(TPMSizedBuffer *tsb)
{
    g_free(tsb->buffer);
    tsb->buffer = NULL;
    tsb->size = 0;
}

/*
 * Transfer a TPM state blob from the TPM into a provided buffer.
 *
 * @fd: file descriptor to talk to the CUSE TPM
 * @type: the type of blob to transfer
 * @decrypted_blob: whether we request to receive decrypted blobs
 * @tsb: the TPMSizeBuffer to fill with the blob
 * @flags: the flags to return to the caller
 */
static int tpm_util_cuse_get_state_blob(int fd,
                                        uint8_t type,
                                        bool decrypted_blob,
                                        TPMSizedBuffer *tsb,
                                        uint32_t *flags)
{
    ptm_getstate pgs;
    uint16_t offset = 0;
    ptm_res res;
    ssize_t n;
    size_t to_read;

    tpm_sized_buffer_reset(tsb);

    pgs.u.req.state_flags = (decrypted_blob) ? PTM_STATE_FLAG_DECRYPTED : 0;
    pgs.u.req.type = type;
    pgs.u.req.offset = offset;

    if (ioctl(fd, PTM_GET_STATEBLOB, &pgs) < 0) {
        error_report("CUSE TPM PTM_GET_STATEBLOB ioctl failed: %s",
                     strerror(errno));
        goto err_exit;
    }
    res = pgs.u.resp.tpm_result;
    if (res != 0 && (res & 0x800) == 0) {
        error_report("Getting the stateblob (type %d) failed with a TPM "
                     "error 0x%x", type, res);
        goto err_exit;
    }

    *flags = pgs.u.resp.state_flags;

    tsb->buffer = g_malloc(pgs.u.resp.totlength);
    memcpy(tsb->buffer, pgs.u.resp.data, pgs.u.resp.length);
    tsb->size = pgs.u.resp.length;

    /* if there are bytes left to get use read() interface */
    while (tsb->size < pgs.u.resp.totlength) {
        to_read = pgs.u.resp.totlength - tsb->size;
        if (unlikely(to_read > SSIZE_MAX)) {
            to_read = SSIZE_MAX;
        }

        n = read(fd, &tsb->buffer[tsb->size], to_read);
        if (n != to_read) {
            error_report("Could not read stateblob (type %d) : %s",
                         type, strerror(errno));
            goto err_exit;
        }
        tsb->size += to_read;
    }

    DPRINTF("tpm_util: got state blob type %d, %d bytes, flags 0x%08x, "
            "decrypted=%d\n", type, tsb->size, *flags, decrypted_blob);

    return 0;

err_exit:
    return 1;
}

int tpm_util_cuse_get_state_blobs(int tpm_fd,
                                  bool decrypted_blobs,
                                  TPMBlobBuffers *tpm_blobs)
{
    if (tpm_util_cuse_get_state_blob(tpm_fd, PTM_BLOB_TYPE_PERMANENT,
                                     decrypted_blobs,
                                     &tpm_blobs->permanent,
                                     &tpm_blobs->permanent_flags) ||
       tpm_util_cuse_get_state_blob(tpm_fd, PTM_BLOB_TYPE_VOLATILE,
                                     decrypted_blobs,
                                     &tpm_blobs->volatil,
                                     &tpm_blobs->volatil_flags) ||
       tpm_util_cuse_get_state_blob(tpm_fd, PTM_BLOB_TYPE_SAVESTATE,
                                     decrypted_blobs,
                                     &tpm_blobs->savestate,
                                     &tpm_blobs->savestate_flags)) {
        goto err_exit;
    }

    return 0;

 err_exit:
    tpm_sized_buffer_reset(&tpm_blobs->volatil);
    tpm_sized_buffer_reset(&tpm_blobs->permanent);
    tpm_sized_buffer_reset(&tpm_blobs->savestate);

    return 1;
}

static int tpm_util_cuse_do_set_stateblob_ioctl(int fd,
                                                uint32_t flags,
                                                uint32_t type,
                                                uint32_t length)
{
    ptm_setstate pss;

    pss.u.req.state_flags = flags;
    pss.u.req.type = type;
    pss.u.req.length = length;

    if (ioctl(fd, PTM_SET_STATEBLOB, &pss) < 0) {
        error_report("CUSE TPM PTM_SET_STATEBLOB ioctl failed: %s",
                     strerror(errno));
        return 1;
    }

    if (pss.u.resp.tpm_result != 0) {
        error_report("Setting the stateblob (type %d) failed with a TPM "
                     "error 0x%x", type, pss.u.resp.tpm_result);
        return 1;
    }

    return 0;
}


/*
 * Transfer a TPM state blob to the CUSE TPM.
 *
 * @fd: file descriptor to talk to the CUSE TPM
 * @type: the type of TPM state blob to transfer
 * @tsb: TPMSizeBuffer containing the TPM state blob
 * @flags: Flags describing the (encryption) state of the TPM state blob
 */
static int tpm_util_cuse_set_state_blob(int fd,
                                        uint32_t type,
                                        TPMSizedBuffer *tsb,
                                        uint32 flags)
{
    uint32_t offset = 0;
    ssize_t n;
    size_t to_write;

    /* initiate the transfer to the CUSE TPM */
    if (tpm_util_cuse_do_set_stateblob_ioctl(fd, flags, type, 0)) {
        return 1;
    }

    /* use the write() interface for transferring the state blob */
    while (offset < tsb->size) {
        to_write = tsb->size - offset;
        if (unlikely(to_write > SSIZE_MAX)) {
            to_write = SSIZE_MAX;
        }

        n = write(fd, &tsb->buffer[offset], to_write);
        if (n != to_write) {
            error_report("Writing the stateblob (type %d) failed: %s",
                         type, strerror(errno));
            goto err_exit;
        }
        offset += to_write;
    }

    /* inidicate that the transfer is finished */
    if (tpm_util_cuse_do_set_stateblob_ioctl(fd, flags, type, 0)) {
        goto err_exit;
    }

    DPRINTF("tpm_util: set the state blob type %d, %d bytes, flags 0x%08x\n",
            type, tsb->size, flags);

    return 0;

err_exit:
    return 1;
}

int tpm_util_cuse_set_state_blobs(int tpm_fd,
                                  TPMBlobBuffers *tpm_blobs)
{
    ptm_res res;

    if (ioctl(tpm_fd, PTM_STOP, &res) < 0) {
        error_report("tpm_passthrough: Could not stop "
                     "the CUSE TPM: %s (%i)",
                     strerror(errno), errno);
        return 1;
    }

    if (tpm_util_cuse_set_state_blob(tpm_fd, PTM_BLOB_TYPE_PERMANENT,
                                     &tpm_blobs->permanent,
                                     tpm_blobs->permanent_flags) ||
        tpm_util_cuse_set_state_blob(tpm_fd, PTM_BLOB_TYPE_VOLATILE,
                                     &tpm_blobs->volatil,
                                     tpm_blobs->volatil_flags) ||
        tpm_util_cuse_set_state_blob(tpm_fd, PTM_BLOB_TYPE_SAVESTATE,
                                     &tpm_blobs->savestate,
                                     tpm_blobs->savestate_flags)) {
        return 1;
    }

    return 0;
}

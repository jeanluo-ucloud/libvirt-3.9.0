/*
 * QEMU S390x KVM floating interrupt controller (flic)
 *
 * Copyright 2014 IBM Corp.
 * Author(s): Jens Freimann <jfrei@linux.vnet.ibm.com>
 *            Cornelia Huck <cornelia.huck@de.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or (at
 * your option) any later version. See the COPYING file in the top-level
 * directory.
 */

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "cpu.h"
#include <sys/ioctl.h>
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "hw/sysbus.h"
#include "sysemu/kvm.h"
#include "hw/s390x/s390_flic.h"
#include "hw/s390x/adapter.h"
#include "hw/s390x/css.h"
#include "trace.h"

#define FLIC_SAVE_INITIAL_SIZE getpagesize()
#define FLIC_FAILED (-1UL)
#define FLIC_SAVEVM_VERSION 1

typedef struct KVMS390FLICState {
    S390FLICState parent_obj;

    uint32_t fd;
    bool clear_io_supported;
} KVMS390FLICState;

DeviceState *s390_flic_kvm_create(void)
{
    DeviceState *dev = NULL;

    if (kvm_enabled()) {
        dev = qdev_create(NULL, TYPE_KVM_S390_FLIC);
        object_property_add_child(qdev_get_machine(), TYPE_KVM_S390_FLIC,
                                  OBJECT(dev), NULL);
    }
    return dev;
}

/**
 * flic_get_all_irqs - store all pending irqs in buffer
 * @buf: pointer to buffer which is passed to kernel
 * @len: length of buffer
 * @flic: pointer to flic device state
 *
 * Returns: -ENOMEM if buffer is too small,
 * -EINVAL if attr.group is invalid,
 * -EFAULT if copying to userspace failed,
 * on success return number of stored interrupts
 */
static int flic_get_all_irqs(KVMS390FLICState *flic,
                             void *buf, int len)
{
    struct kvm_device_attr attr = {
        .group = KVM_DEV_FLIC_GET_ALL_IRQS,
        .addr = (uint64_t) buf,
        .attr = len,
    };
    int rc;

    rc = ioctl(flic->fd, KVM_GET_DEVICE_ATTR, &attr);

    return rc == -1 ? -errno : rc;
}

static void flic_enable_pfault(KVMS390FLICState *flic)
{
    struct kvm_device_attr attr = {
        .group = KVM_DEV_FLIC_APF_ENABLE,
    };
    int rc;

    rc = ioctl(flic->fd, KVM_SET_DEVICE_ATTR, &attr);

    if (rc) {
        fprintf(stderr, "flic: couldn't enable pfault\n");
    }
}

static void flic_disable_wait_pfault(KVMS390FLICState *flic)
{
    struct kvm_device_attr attr = {
        .group = KVM_DEV_FLIC_APF_DISABLE_WAIT,
    };
    int rc;

    rc = ioctl(flic->fd, KVM_SET_DEVICE_ATTR, &attr);

    if (rc) {
        fprintf(stderr, "flic: couldn't disable pfault\n");
    }
}

/** flic_enqueue_irqs - returns 0 on success
 * @buf: pointer to buffer which is passed to kernel
 * @len: length of buffer
 * @flic: pointer to flic device state
 *
 * Returns: -EINVAL if attr.group is unknown
 */
static int flic_enqueue_irqs(void *buf, uint64_t len,
                            KVMS390FLICState *flic)
{
    int rc;
    struct kvm_device_attr attr = {
        .group = KVM_DEV_FLIC_ENQUEUE,
        .addr = (uint64_t) buf,
        .attr = len,
    };

    rc = ioctl(flic->fd, KVM_SET_DEVICE_ATTR, &attr);

    return rc ? -errno : 0;
}

int kvm_s390_inject_flic(struct kvm_s390_irq *irq)
{
    static KVMS390FLICState *flic;

    if (unlikely(!flic)) {
        flic = KVM_S390_FLIC(s390_get_flic());
    }
    return flic_enqueue_irqs(irq, sizeof(*irq), flic);
}

static int kvm_s390_clear_io_flic(S390FLICState *fs, uint16_t subchannel_id,
                           uint16_t subchannel_nr)
{
    KVMS390FLICState *flic = KVM_S390_FLIC(fs);
    int rc;
    uint32_t sid = subchannel_id << 16 | subchannel_nr;
    struct kvm_device_attr attr = {
        .group = KVM_DEV_FLIC_CLEAR_IO_IRQ,
        .addr = (uint64_t) &sid,
        .attr = sizeof(sid),
    };
    if (unlikely(!flic->clear_io_supported)) {
        return -ENOSYS;
    }
    rc = ioctl(flic->fd, KVM_SET_DEVICE_ATTR, &attr);
    return rc ? -errno : 0;
}

static int kvm_s390_modify_ais_mode(S390FLICState *fs, uint8_t isc,
                                    uint16_t mode)
{
    KVMS390FLICState *flic = KVM_S390_FLIC(fs);
    struct kvm_s390_ais_req req = {
        .isc = isc,
        .mode = mode,
    };
    struct kvm_device_attr attr = {
        .group = KVM_DEV_FLIC_AISM,
        .addr = (uint64_t)&req,
    };

    if (!fs->ais_supported) {
        return -ENOSYS;
    }

    return ioctl(flic->fd, KVM_SET_DEVICE_ATTR, &attr) ? -errno : 0;
}

static int kvm_s390_inject_airq(S390FLICState *fs, uint8_t type,
                                uint8_t isc, uint8_t flags)
{
    KVMS390FLICState *flic = KVM_S390_FLIC(fs);
    uint32_t id = css_get_adapter_id(type, isc);
    struct kvm_device_attr attr = {
        .group = KVM_DEV_FLIC_AIRQ_INJECT,
        .attr = id,
    };

    if (!fs->ais_supported) {
        return -ENOSYS;
    }

    return ioctl(flic->fd, KVM_SET_DEVICE_ATTR, &attr) ? -errno : 0;
}

/**
 * __get_all_irqs - store all pending irqs in buffer
 * @flic: pointer to flic device state
 * @buf: pointer to pointer to a buffer
 * @len: length of buffer
 *
 * Returns: return value of flic_get_all_irqs
 * Note: Retry and increase buffer size until flic_get_all_irqs
 * either returns a value >= 0 or a negative error code.
 * -ENOMEM is an exception, which means the buffer is too small
 * and we should try again. Other negative error codes can be
 * -EFAULT and -EINVAL which we ignore at this point
 */
static int __get_all_irqs(KVMS390FLICState *flic,
                          void **buf, int len)
{
    int r;

    do {
        /* returns -ENOMEM if buffer is too small and number
         * of queued interrupts on success */
        r = flic_get_all_irqs(flic, *buf, len);
        if (r >= 0) {
            break;
        }
        len *= 2;
        *buf = g_try_realloc(*buf, len);
        if (!buf) {
            return -ENOMEM;
        }
    } while (r == -ENOMEM && len <= KVM_S390_FLIC_MAX_BUFFER);

    return r;
}

static int kvm_s390_register_io_adapter(S390FLICState *fs, uint32_t id,
                                        uint8_t isc, bool swap,
                                        bool is_maskable, uint8_t flags)
{
    struct kvm_s390_io_adapter adapter = {
        .id = id,
        .isc = isc,
        .maskable = is_maskable,
        .swap = swap,
        .flags = flags,
    };
    KVMS390FLICState *flic = KVM_S390_FLIC(fs);
    int r;
    struct kvm_device_attr attr = {
        .group = KVM_DEV_FLIC_ADAPTER_REGISTER,
        .addr = (uint64_t)&adapter,
    };

    if (!kvm_gsi_routing_enabled()) {
        /* nothing to do */
        return 0;
    }

    r = ioctl(flic->fd, KVM_SET_DEVICE_ATTR, &attr);

    return r ? -errno : 0;
}

static int kvm_s390_io_adapter_map(S390FLICState *fs, uint32_t id,
                                   uint64_t map_addr, bool do_map)
{
    struct kvm_s390_io_adapter_req req = {
        .id = id,
        .type = do_map ? KVM_S390_IO_ADAPTER_MAP : KVM_S390_IO_ADAPTER_UNMAP,
        .addr = map_addr,
    };
    struct kvm_device_attr attr = {
        .group = KVM_DEV_FLIC_ADAPTER_MODIFY,
        .addr = (uint64_t)&req,
    };
    KVMS390FLICState *flic = KVM_S390_FLIC(fs);
    int r;

    if (!kvm_gsi_routing_enabled()) {
        /* nothing to do */
        return 0;
    }

    r = ioctl(flic->fd, KVM_SET_DEVICE_ATTR, &attr);
    return r ? -errno : 0;
}

static int kvm_s390_add_adapter_routes(S390FLICState *fs,
                                       AdapterRoutes *routes)
{
    int ret, i;
    uint64_t ind_offset = routes->adapter.ind_offset;

    for (i = 0; i < routes->num_routes; i++) {
        ret = kvm_irqchip_add_adapter_route(kvm_state, &routes->adapter);
        if (ret < 0) {
            goto out_undo;
        }
        routes->gsi[i] = ret;
        routes->adapter.ind_offset++;
    }
    kvm_irqchip_commit_routes(kvm_state);

    /* Restore passed-in structure to original state. */
    routes->adapter.ind_offset = ind_offset;
    return 0;
out_undo:
    while (--i >= 0) {
        kvm_irqchip_release_virq(kvm_state, routes->gsi[i]);
        routes->gsi[i] = -1;
    }
    routes->adapter.ind_offset = ind_offset;
    return ret;
}

static void kvm_s390_release_adapter_routes(S390FLICState *fs,
                                            AdapterRoutes *routes)
{
    int i;

    for (i = 0; i < routes->num_routes; i++) {
        if (routes->gsi[i] >= 0) {
            kvm_irqchip_release_virq(kvm_state, routes->gsi[i]);
            routes->gsi[i] = -1;
        }
    }
}

/**
 * kvm_flic_save - Save pending floating interrupts
 * @f: QEMUFile containing migration state
 * @opaque: pointer to flic device state
 * @size: ignored
 *
 * Note: Pass buf and len to kernel. Start with one page and
 * increase until buffer is sufficient or maxium size is
 * reached
 */
static int kvm_flic_save(QEMUFile *f, void *opaque, size_t size,
                         VMStateField *field, QJSON *vmdesc)
{
    KVMS390FLICState *flic = opaque;
    int len = FLIC_SAVE_INITIAL_SIZE;
    void *buf;
    int count;
    int r = 0;

    flic_disable_wait_pfault((struct KVMS390FLICState *) opaque);

    buf = g_try_malloc0(len);
    if (!buf) {
        /* Storing FLIC_FAILED into the count field here will cause the
         * target system to fail when attempting to load irqs from the
         * migration state */
        error_report("flic: couldn't allocate memory");
        qemu_put_be64(f, FLIC_FAILED);
        return -ENOMEM;
    }

    count = __get_all_irqs(flic, &buf, len);
    if (count < 0) {
        error_report("flic: couldn't retrieve irqs from kernel, rc %d",
                     count);
        /* Storing FLIC_FAILED into the count field here will cause the
         * target system to fail when attempting to load irqs from the
         * migration state */
        qemu_put_be64(f, FLIC_FAILED);
        r = count;
    } else {
        qemu_put_be64(f, count);
        qemu_put_buffer(f, (uint8_t *) buf,
                        count * sizeof(struct kvm_s390_irq));
    }
    g_free(buf);

    return r;
}

/**
 * kvm_flic_load - Load pending floating interrupts
 * @f: QEMUFile containing migration state
 * @opaque: pointer to flic device state
 * @size: ignored
 *
 * Returns: value of flic_enqueue_irqs, -EINVAL on error
 * Note: Do nothing when no interrupts where stored
 * in QEMUFile
 */
static int kvm_flic_load(QEMUFile *f, void *opaque, size_t size,
                         VMStateField *field)
{
    uint64_t len = 0;
    uint64_t count = 0;
    void *buf = NULL;
    int r = 0;

    flic_enable_pfault((struct KVMS390FLICState *) opaque);

    count = qemu_get_be64(f);
    len = count * sizeof(struct kvm_s390_irq);
    if (count == FLIC_FAILED) {
        r = -EINVAL;
        goto out;
    }
    if (count == 0) {
        r = 0;
        goto out;
    }
    buf = g_try_malloc0(len);
    if (!buf) {
        r = -ENOMEM;
        goto out;
    }

    if (qemu_get_buffer(f, (uint8_t *) buf, len) != len) {
        r = -EINVAL;
        goto out_free;
    }
    r = flic_enqueue_irqs(buf, len, (struct KVMS390FLICState *) opaque);

out_free:
    g_free(buf);
out:
    return r;
}

typedef struct KVMS390FLICStateMigTmp {
    KVMS390FLICState *parent;
    uint8_t simm;
    uint8_t nimm;
} KVMS390FLICStateMigTmp;

static int kvm_flic_ais_pre_save(void *opaque)
{
    KVMS390FLICStateMigTmp *tmp = opaque;
    KVMS390FLICState *flic = tmp->parent;
    struct kvm_s390_ais_all ais;
    struct kvm_device_attr attr = {
        .group = KVM_DEV_FLIC_AISM_ALL,
        .addr = (uint64_t)&ais,
        .attr = sizeof(ais),
    };

    if (ioctl(flic->fd, KVM_GET_DEVICE_ATTR, &attr)) {
        error_report("Failed to retrieve kvm flic ais states");
        return -EINVAL;
    }

    tmp->simm = ais.simm;
    tmp->nimm = ais.nimm;

    return 0;
}

static int kvm_flic_ais_post_load(void *opaque, int version_id)
{
    KVMS390FLICStateMigTmp *tmp = opaque;
    KVMS390FLICState *flic = tmp->parent;
    struct kvm_s390_ais_all ais = {
        .simm = tmp->simm,
        .nimm = tmp->nimm,
    };
    struct kvm_device_attr attr = {
        .group = KVM_DEV_FLIC_AISM_ALL,
        .addr = (uint64_t)&ais,
    };

    /* This can happen when the user mis-configures its guests in an
     * incompatible fashion or without a CPU model. For example using
     * qemu with -cpu host (which is not migration safe) and do a
     * migration from a host that has AIS to a host that has no AIS.
     * In that case the target system will reject the migration here.
     */
    if (!ais_needed(flic)) {
        return -ENOSYS;
    }

    return ioctl(flic->fd, KVM_SET_DEVICE_ATTR, &attr) ? -errno : 0;
}

static const VMStateDescription kvm_s390_flic_ais_tmp = {
    .name = "s390-flic-ais-tmp",
    .pre_save = kvm_flic_ais_pre_save,
    .post_load = kvm_flic_ais_post_load,
    .fields = (VMStateField[]) {
        VMSTATE_UINT8(simm, KVMS390FLICStateMigTmp),
        VMSTATE_UINT8(nimm, KVMS390FLICStateMigTmp),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription kvm_s390_flic_vmstate_ais = {
    .name = "s390-flic/ais",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = ais_needed,
    .fields = (VMStateField[]) {
        VMSTATE_WITH_TMP(KVMS390FLICState, KVMS390FLICStateMigTmp,
                         kvm_s390_flic_ais_tmp),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription kvm_s390_flic_vmstate = {
    /* should have been like kvm-s390-flic,
     * can't change without breaking compat */
    .name = "s390-flic",
    .version_id = FLIC_SAVEVM_VERSION,
    .minimum_version_id = FLIC_SAVEVM_VERSION,
    .fields = (VMStateField[]) {
        {
            .name = "irqs",
            .info = &(const VMStateInfo) {
                .name = "irqs",
                .get = kvm_flic_load,
                .put = kvm_flic_save,
            },
            .flags = VMS_SINGLE,
        },
        VMSTATE_END_OF_LIST()
    },
    .subsections = (const VMStateDescription * []) {
        &kvm_s390_flic_vmstate_ais,
        NULL
    }
};

typedef struct KVMS390FLICStateClass {
    S390FLICStateClass parent_class;
    DeviceRealize parent_realize;
} KVMS390FLICStateClass;

#define KVM_S390_FLIC_GET_CLASS(obj) \
    OBJECT_GET_CLASS(KVMS390FLICStateClass, (obj), TYPE_KVM_S390_FLIC)

#define KVM_S390_FLIC_CLASS(klass) \
    OBJECT_CLASS_CHECK(KVMS390FLICStateClass, (klass), TYPE_KVM_S390_FLIC)

static void kvm_s390_flic_realize(DeviceState *dev, Error **errp)
{
    KVMS390FLICState *flic_state = KVM_S390_FLIC(dev);
    struct kvm_create_device cd = {0};
    struct kvm_device_attr test_attr = {0};
    int ret;
    Error *errp_local = NULL;

    KVM_S390_FLIC_GET_CLASS(dev)->parent_realize(dev, &errp_local);
    if (errp_local) {
        goto fail;
    }
    flic_state->fd = -1;
    if (!kvm_check_extension(kvm_state, KVM_CAP_DEVICE_CTRL)) {
        error_setg_errno(&errp_local, errno, "KVM is missing capability"
                         " KVM_CAP_DEVICE_CTRL");
        trace_flic_no_device_api(errno);
        goto fail;
    }

    cd.type = KVM_DEV_TYPE_FLIC;
    ret = kvm_vm_ioctl(kvm_state, KVM_CREATE_DEVICE, &cd);
    if (ret < 0) {
        error_setg_errno(&errp_local, errno, "Creating the KVM device failed");
        trace_flic_create_device(errno);
        goto fail;
    }
    flic_state->fd = cd.fd;

    /* Check clear_io_irq support */
    test_attr.group = KVM_DEV_FLIC_CLEAR_IO_IRQ;
    flic_state->clear_io_supported = !ioctl(flic_state->fd,
                                            KVM_HAS_DEVICE_ATTR, test_attr);
    return;
fail:
    error_propagate(errp, errp_local);
}

static void kvm_s390_flic_reset(DeviceState *dev)
{
    KVMS390FLICState *flic = KVM_S390_FLIC(dev);
    S390FLICState *fs = S390_FLIC_COMMON(dev);
    struct kvm_device_attr attr = {
        .group = KVM_DEV_FLIC_CLEAR_IRQS,
    };
    int rc = 0;
    uint8_t isc;

    if (flic->fd == -1) {
        return;
    }

    flic_disable_wait_pfault(flic);

    if (fs->ais_supported) {
        for (isc = 0; isc <= MAX_ISC; isc++) {
            rc = kvm_s390_modify_ais_mode(fs, isc, SIC_IRQ_MODE_ALL);
            if (rc) {
                error_report("Failed to reset ais mode for isc %d: %s",
                             isc, strerror(-rc));
            }
        }
    }

    rc = ioctl(flic->fd, KVM_SET_DEVICE_ATTR, &attr);
    if (rc) {
        trace_flic_reset_failed(errno);
    }

    flic_enable_pfault(flic);
}

static void kvm_s390_flic_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    S390FLICStateClass *fsc = S390_FLIC_COMMON_CLASS(oc);

    KVM_S390_FLIC_CLASS(oc)->parent_realize = dc->realize;
    dc->realize = kvm_s390_flic_realize;
    dc->vmsd = &kvm_s390_flic_vmstate;
    dc->reset = kvm_s390_flic_reset;
    fsc->register_io_adapter = kvm_s390_register_io_adapter;
    fsc->io_adapter_map = kvm_s390_io_adapter_map;
    fsc->add_adapter_routes = kvm_s390_add_adapter_routes;
    fsc->release_adapter_routes = kvm_s390_release_adapter_routes;
    fsc->clear_io_irq = kvm_s390_clear_io_flic;
    fsc->modify_ais_mode = kvm_s390_modify_ais_mode;
    fsc->inject_airq = kvm_s390_inject_airq;
}

static const TypeInfo kvm_s390_flic_info = {
    .name          = TYPE_KVM_S390_FLIC,
    .parent        = TYPE_S390_FLIC_COMMON,
    .instance_size = sizeof(KVMS390FLICState),
    .class_size    = sizeof(KVMS390FLICStateClass),
    .class_init    = kvm_s390_flic_class_init,
};

static void kvm_s390_flic_register_types(void)
{
    type_register_static(&kvm_s390_flic_info);
}

type_init(kvm_s390_flic_register_types)

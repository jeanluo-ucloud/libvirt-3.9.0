#include "qemu/osdep.h"
#include "block/block_int.h"
#include "qemu/queue.h"
#include "qemu/timer.h"
#include "qemu/sockets.h"
#include "qapi/qmp/qerror.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qemu/cutils.h"
#include "block/aio.h"

#define DRIVER_NAME			"udisk"

#define QERR_DEVICE_NOT_GETLENGTH	\
        "Device 'udisk' failed to getlength, ret code: %d"

#define UBS_PATH_PREFIX     "/dev/disk/by-path"
#define UBS_GATE_PREFIX     "udisk:"
#define UBS_UDISK_PREFIX    "udisk"

#define MAX_DISKID 			128
#define MAX_IP 				32
#define SECTOR_SIZE 		512ull

#define REQUEST_TIMEOUT 	10000ul
#define RECONNECT_DELAY 	500ul
#define RECONNECT_TIMEOUT 	4000ul
#define MAX_ERROR_TIME 		10000ul

static int64_t routine_timeout = 1000ul;

#define DEBUG	1
#undef DPRINTF
#define DPRINTF(fmt, args...)                                       \
    do {                                                            \
        if (DEBUG)                                                  \
            fprintf(stderr, "%s %d: " fmt "\n", __func__,           \
                    __LINE__, ##args);                              \
} while (0)

struct protohead {
    uint32_t size;
    uint32_t cmd;
    uint64_t sector;
    uint64_t secnum;
    uint64_t flowno;
    uint32_t magic;
    int retcode;
    char data[0];
}__attribute__ ((packed));

struct proto_stat {
    char udisk_id[MAX_DISKID];
    char udisk_ip[MAX_IP];
    unsigned short udisk_port;
} __attribute__ ((packed));

enum {
    CMD_READ	= 0,
    CMD_WRITE 	= 1,
    CMD_STAT 	= 2,
    CMD_NOP 	= 3,
    CMD_FLUSH 	= 4,
    CMD_TRUNCATE = 5,
};

enum {
    MAGIC_NUMBER = 0xf123987a,
};

typedef enum {
    DS_NORMAL = 0,
    DS_RECONNECT = 1 << 0,
} UDiskDeviceState;

QTAILQ_HEAD(AIOReqHead, AIOReq);
typedef struct BDRVUDiskState {
    int curr_socket;
    int is_cached; 							/* 0 for no cache, 1 for cache */
    uint64_t sectors;
    uint64_t time_out_flowno;
    bool is_first_timeout;
    CoMutex lock;

    Coroutine *co_recv;
    Coroutine *co_send;
    uint64_t seqno;
    Coroutine *co_timeout;

    UDiskDeviceState state;

    /* routine timer for reconnect and finish long time request in per 50ms */
    QEMUTimer *routine_timer;

    CoMutex queue_lock;
    struct AIOReqHead net_inflight_head;
    uint64_t net_inflight_count;

    char bsid[128]; 						/* uuid for block device */
    char bsip[64];
    char sock_name[80];						/* max 64 + some */
    unsigned short bsport;

    AioContext *aio_ctx;
    int routine_timer_times;
} BDRVUDiskState;

typedef struct UDiskAIOCB {
    BlockAIOCB common;
    BDRVUDiskState *s;

    QEMUIOVector *qiov;
    int64_t sector;
    int aiocb_type;
    int nr_sectors;
    int ret;
    int canceled;
    int finished;
    void coroutine_fn (*aio_done_func)(struct UDiskAIOCB *acb);

    Coroutine *coroutine;
    int nr_pending;
} UDiskAIOCB;

typedef struct AIOReq {
    UDiskAIOCB *aiocb;
    struct protohead head;

    unsigned int send_offset;
    unsigned int iov_offset;
    uint64_t offset;
    unsigned int data_len;
    uint8_t flags;
    uint64_t seqno;

    uint64_t request_time;

    QTAILQ_ENTRY(AIOReq) entry;
} AIOReq;

static void coroutine_fn do_net_request(BDRVUDiskState *s, AIOReq *aio_req);
static void co_send_request(void *opaque);
static void co_recv_response(void *opaque);

static int udisk_unix_connect(const char *path, int syncflag,
                              struct BDRVUDiskState *s)
{
    int fd;

    fd = unix_connect(path, NULL);
    if (fd <= 0)
        return -EIO;

    if (!syncflag)
        qemu_set_nonblock(fd);

    return fd;
}

static inline uint64_t gen_flowno(void)
{
    static uint64_t flowseed = 0;
    return flowseed++;
}

static struct protohead *make_stat_request(const char *udisk_id,
                                           const char *server_ip,
                                           unsigned short server_port,
                                           uint64_t *flowno)
{
    unsigned packsize = sizeof(struct protohead) + sizeof(struct proto_stat);
    struct protohead *head = malloc(packsize);
    struct proto_stat *stat = (struct proto_stat *)head->data;
    head->size = packsize;
    head->cmd = CMD_STAT;
    head->sector = 0;
    head->secnum = 0;
    head->flowno = *flowno = gen_flowno();
    head->retcode = 0;
    head->magic = MAGIC_NUMBER;
    snprintf(stat->udisk_id, sizeof(stat->udisk_id), "%s", udisk_id);
    snprintf(stat->udisk_ip, sizeof(stat->udisk_ip), "%s", server_ip);
    stat->udisk_port = server_port;
    return head;
}

static struct protohead *make_flush_request(uint64_t *flowno)
{
    unsigned packsize = sizeof(struct protohead);
    struct protohead *head = malloc(packsize);
    head->size = packsize;
    head->cmd = CMD_FLUSH;
    head->sector = 0;
    head->secnum = 0;
    head->flowno = *flowno = gen_flowno();
    head->retcode = 0;
    head->magic = MAGIC_NUMBER;
    return head;
}

static struct protohead *make_truncate_request(char *udisk_id, uint64_t *flowno, uint64_t offset)
{
    unsigned packsize = sizeof(struct protohead) + sizeof(struct proto_stat);
    struct protohead *head = malloc(packsize);
    struct proto_stat *stat = (struct proto_stat *)head->data;
    head->size = packsize;
    head->cmd = CMD_TRUNCATE;
    head->sector = 0;
    head->secnum = DIV_ROUND_UP(offset, SECTOR_SIZE);
    head->flowno = *flowno = gen_flowno();
    head->retcode = 0;
    head->magic = MAGIC_NUMBER;
    snprintf(stat->udisk_id, sizeof(stat->udisk_id), "%s", udisk_id);
    return head;
}

typedef struct UDiskReqCo {
    int sockfd;
    BlockDriverState *bs;
    AioContext *aio_context;
    struct protohead *hdr;
    int ret;
    bool finished;
    Coroutine *co;
} UDiskReqCo;

static void restart_co_req(void *opaque)
{
    UDiskReqCo *srco = opaque;

    aio_co_wake(srco->co);
}

static coroutine_fn void do_co_req(void *opaque)
{
    int ret;
    UDiskReqCo *srco = opaque;
    int sockfd = srco->sockfd;
    struct protohead *req_head = srco->hdr, res_head = {0};

    srco->co = qemu_coroutine_self();
    aio_set_fd_handler(srco->aio_context, sockfd, false,
                       NULL, restart_co_req, NULL, srco);

    ret = qemu_co_send(sockfd, (char *)req_head, req_head->size);
    if ( ret != req_head->size ) {
        ret = -errno;
        goto out;
    }

    aio_set_fd_handler(srco->aio_context, sockfd, false,
                       restart_co_req, NULL, NULL, srco);

    ret = qemu_co_recv(sockfd, (char *)&res_head, sizeof(res_head));
    if ( ret != sizeof(res_head)) {
        ret = -errno;
        goto out;
    }

    ret = res_head.retcode;
out:
    /* there is at most one request for this sockfd, so it is safe to
     * set each handler to NULL. */
    aio_set_fd_handler(srco->aio_context, sockfd, false,
                       NULL, NULL, NULL, NULL);

    srco->co = NULL;
    srco->ret = ret;
    /* Set srco->finished before reading bs->wakeup.  */
    atomic_mb_set(&srco->finished, true);
    if (srco->bs) {
        bdrv_wakeup(srco->bs);
    }
}

static int do_req(int fd, BlockDriverState *bs, struct protohead *head)
{
    Coroutine *co;
    UDiskReqCo srco = {
        .sockfd = fd,
        .aio_context = bs ? bdrv_get_aio_context(bs) : qemu_get_aio_context(),
        .bs = bs,
        .hdr = head,
        .ret = 0,
        .finished = false,
    };

    if (qemu_in_coroutine()) {
        do_co_req(&srco);
    } else {
        co = qemu_coroutine_create(do_co_req, &srco);
        if (bs) {
            bdrv_coroutine_enter(bs, co);
            BDRV_POLL_WHILE(bs, !srco.finished);
        } else {
            qemu_coroutine_enter(co);
            while (!srco.finished) {
                aio_poll(qemu_get_aio_context(), true);
            }
        }
    }

    return srco.ret;
}

static void bdrv_udisk_aio_cancel(BlockAIOCB *blockacb)
{
    UDiskAIOCB *acb = container_of(blockacb, UDiskAIOCB, common);
    qemu_aio_unref(acb);
}

static AIOCBInfo bdrv_udisk_aio_pool = {
    .aiocb_size         = sizeof(UDiskAIOCB),
    .cancel_async       = bdrv_udisk_aio_cancel,
};

static inline const char *udisk_state2string(UDiskDeviceState state)
{
#define CASE_AND_RETURN(x)                      \
    case x:                                     \
        return #x

    switch ( state ) {
        CASE_AND_RETURN(DS_NORMAL);
        CASE_AND_RETURN(DS_RECONNECT);
    }
    return "null";
}

static inline void udisk_set_state(BDRVUDiskState *s, UDiskDeviceState state)
{
    if (!(s->state & state)) {
        s->state |= state;
    }
}

static inline void udisk_unset_state(BDRVUDiskState *s, UDiskDeviceState state)
{
    if (s->state & state) {
        s->state &= ~state;
    }
}

static inline AIOReq *alloc_aio_req(BDRVUDiskState *s, UDiskAIOCB *acb,
                                    unsigned int data_len, uint64_t offset,
                                    uint8_t flags, unsigned int iov_offset)
{
    AIOReq *aio_req;

    aio_req = g_malloc(sizeof(*aio_req));
    aio_req->aiocb = acb;
    aio_req->send_offset = 0;
    aio_req->iov_offset = iov_offset;
    aio_req->offset = offset;
    aio_req->data_len = data_len;
    aio_req->flags = flags;
    aio_req->seqno = ++s->seqno;
    aio_req->request_time = qemu_clock_get_ns(QEMU_CLOCK_REALTIME) / 1000000;
    if ( s->seqno == 0 ) {
        aio_req->seqno = ++s->seqno;
    }
    return aio_req;
}

static UDiskAIOCB *udisk_aio_setup(BlockDriverState *bs, QEMUIOVector *qiov,
                                   int64_t sector, int nr_sectors, int cmd)
{
    UDiskAIOCB *acb;

    acb = qemu_aio_get(&bdrv_udisk_aio_pool, bs, NULL, NULL);

    acb->qiov = qiov;
    acb->sector = sector;
    acb->nr_sectors = nr_sectors;
    acb->coroutine = qemu_coroutine_self();
    acb->canceled = 0;
    acb->aiocb_type = cmd;
    return acb;
}

static int udisk_sync_getlength(BDRVUDiskState *s, Error **errp)
{
    uint64_t flowno;
    struct protohead *req_head, res_head = {0};
    int ret = -1;

    req_head = make_stat_request(s->bsid, s->bsip, s->bsport, &flowno);
    ret = qemu_co_send(s->curr_socket, (char *)req_head, req_head->size);
    if ( ret != req_head->size ) {
        error_setg_errno(errp, errno, QERR_DEVICE_NOT_GETLENGTH, ret);
        goto out;
    }
    ret = qemu_co_recv(s->curr_socket, (char *)&res_head, sizeof(res_head));
    if ( ret != sizeof(res_head)) {
        error_setg_errno(errp, errno, QERR_DEVICE_NOT_GETLENGTH, ret);
        goto out;
    }

    if ( res_head.retcode != 0 ) {
        error_setg_errno(errp, errno, QERR_DEVICE_NOT_GETLENGTH, res_head.retcode);
        goto out;
    }

    s->sectors = res_head.secnum;
    ret = 0;
out:
    free(req_head);
    return ret;
}

static void udisk_close_client(BDRVUDiskState *s)
{
    if ( s->curr_socket != -1 ) {
        if (s->aio_ctx != NULL) {
            aio_set_fd_handler(s->aio_ctx, s->curr_socket, false,
                               NULL, NULL, NULL, NULL);
        }
        close(s->curr_socket);
        s->curr_socket = -1;
    }
    udisk_set_state(s, DS_RECONNECT);
    routine_timeout = 100;
}

static void udisk_close(BlockDriverState *bs)
{
    struct BDRVUDiskState *s = bs->opaque;

    udisk_close_client(s);
    if ( s->routine_timer ) {
        timer_del(s->routine_timer);
        timer_free(s->routine_timer);
        s->routine_timer = NULL;
    }
}

static bool is_req_timeout(BDRVUDiskState *s)
{
    AIOReq *aio_req;

    if (s->is_first_timeout == true) {
        s->is_first_timeout = false;
        return false;
    }
    if (s->net_inflight_count == 0) {
        return false;
    }

    aio_req = QTAILQ_FIRST(&s->net_inflight_head);
    if (aio_req->head.flowno == s->time_out_flowno) {
        uint64_t flowno;
        struct protohead *req_head, res_head = {0};
        int ret;
        req_head = make_flush_request(&flowno);
        aio_set_fd_handler(s->aio_ctx, s->curr_socket, false,
                           co_recv_response, co_send_request, NULL, s);
        ret = qemu_co_send(s->curr_socket, (char *)req_head, req_head->size);
        if ( ret != req_head->size ) {
            DPRINTF("%s: flush req_head size wrong, retcode: %d, %m\n", s->bsid, ret);
            free(req_head);
            return false;
        }

        ret = qemu_co_recv(s->curr_socket, (char *)&res_head, sizeof(res_head));
        if ( ret != sizeof(res_head)) {
            DPRINTF("%s: receive wrong size response, retcode: %d, %m\n", s->bsid, ret);
            free(req_head);
            return false;
        }

        if ( res_head.retcode != 0 ) {
            DPRINTF("%s: Gate In Cache Mode, can not reconnect\n", s->bsid);
            free(req_head);
            return false;
        }
        if ( res_head.cmd != CMD_FLUSH ) {
            DPRINTF("%s: Flush Receive Response Not Flush:%u\n", s->bsid, res_head.cmd);
        }
        free(req_head);
        return true;
    }
    s->time_out_flowno = aio_req->head.flowno;
    return false;
}

static void coroutine_fn dispatch_request(void *opaque, AIOReq *aio_req)
{
    BDRVUDiskState *s = opaque;
    if (!(s->state & DS_RECONNECT)) {
        do_net_request(s, aio_req);
    }
}

static void coroutine_fn aio_recv_response(void *opaque)
{
    BDRVUDiskState *s = opaque;
    int fd = s->curr_socket;
    int ret = 0, error = 1;
    AIOReq *aio_req = NULL, *n = NULL;
    UDiskAIOCB *acb;
    struct protohead head;

    ret = qemu_co_recv(fd, (char *)&head, sizeof(head));
    if (ret != sizeof(head)) {
        error_report("%s: failed to get the header, ret:%d, errno:%d, errmsg:%s", s->bsid, ret, errno, strerror(errno));
        goto out;
    }

    QTAILQ_FOREACH_SAFE(aio_req, &s->net_inflight_head, entry, n) {
        if (aio_req->seqno == head.flowno) {
            break;
        }
    }
    if (!aio_req) {
        error_report("%s: cannot find aio_req, size:%u, cmd:%u, sector:%lu, sec_num:%lu, flowno:%lu, magic:%u",
                     s->bsid, head.size, head.cmd, head.sector, head.secnum, head.flowno, head.magic);
        goto out;
    }

    acb = aio_req->aiocb;
    if ( head.cmd != CMD_READ ) {
        assert(head.size == sizeof(head));
    } else {
        if ( head.size > sizeof(head)) {
            ret = qemu_co_recvv(fd, acb->qiov->iov,
                                acb->qiov->niov,
                                aio_req->send_offset,
                                head.size - sizeof(head));
            if ( ret != head.size - sizeof(head) ) {
                error_report("%s: failed to get the data, ret:%d, errno:%d, errmsg:%s", s->bsid, ret, errno, strerror(errno));
                goto out;
            }
        }
    }
    if ( head.retcode >= 0 ) {
        acb->ret = 0;
        error = 0;
    } else {
        acb->ret = -EIO;
    }

    qemu_co_mutex_lock(&s->queue_lock);
    QTAILQ_REMOVE(&s->net_inflight_head, aio_req, entry);
    s->net_inflight_count--;
    qemu_co_mutex_unlock(&s->queue_lock);
    g_free(aio_req);
    acb->nr_pending--;

    if ( qemu_coroutine_self() != acb->coroutine ) {
        aio_co_wake(acb->coroutine);
    }
 out:
    s->co_recv = NULL;
    if (error) {
        udisk_close_client(s);
        timer_mod(s->routine_timer,
                  qemu_clock_get_ns(QEMU_CLOCK_REALTIME) / 1000000 + routine_timeout);
    }
}

static void co_send_request(void *opaque)
{
    BDRVUDiskState *s = opaque;

    if (s->co_timeout)
        qemu_coroutine_enter(s->co_timeout);

    if (s->co_send)
        aio_co_wake(s->co_send);
}

static void co_recv_response(void *opaque)
{
    BDRVUDiskState *s = opaque;

    if (s->state & DS_RECONNECT) {
        s->co_recv = NULL;
        aio_set_fd_handler(s->aio_ctx, s->curr_socket, false,
                           NULL, co_send_request, NULL, s);
        return;
    }

    if (s->co_timeout)
        qemu_coroutine_enter(s->co_timeout);

    if (!s->co_recv) {
        s->co_recv = qemu_coroutine_create(aio_recv_response, s);
    }

    aio_co_enter(s->aio_ctx, s->co_recv);
}

static void udisk_net_reconnect(BDRVUDiskState *s)
{
    int ret;
    Error *err = NULL;
    AIOReq *p, *n;

    udisk_close_client(s);
    while (s->co_send) {
        DPRINTF("%s: clear send coroutine, co_send:%p\n", s->bsid, s->co_send);
        qemu_coroutine_enter(s->co_send);
    }

    while (s->co_recv) {
        DPRINTF("%s: clear recv coroutine, co_recv:%p\n", s->bsid, s->co_recv);
        qemu_coroutine_enter(s->co_recv);
    }

    s->curr_socket = udisk_unix_connect(s->sock_name, 0, s);
    if ( s->curr_socket < 0 ) {
        DPRINTF("%s: udisk reconnect failed: %m\n", s->bsid);
        s->curr_socket = -1;
        return;
    }
    routine_timeout = 1000;

    aio_set_fd_handler(s->aio_ctx, s->curr_socket, false,
                       co_recv_response, co_send_request, NULL, s);
    ret = udisk_sync_getlength(s, &err);
    if (ret != 0 || err) {
        error_free(err);
        udisk_close_client(s);
        return;
    }

    /* resend all the pending request */
    QTAILQ_FOREACH_SAFE(p, &s->net_inflight_head, entry, n)
        do_net_request(s, p);
    udisk_unset_state(s, DS_RECONNECT);

    aio_set_fd_handler(s->aio_ctx, s->curr_socket, false,
                       co_recv_response, NULL, NULL, s);
}

static void coroutine_fn udisk_reconnect_co_entry(void *opaque)
{
    BDRVUDiskState *s = opaque;

    ++s->routine_timer_times;
    // reconnect
    if (-1 == s->curr_socket) {
        udisk_net_reconnect(s);
        goto out;
    }
    // routine_cb每S触发一次，每次触发都判断是否需要重连，每10s判断是否超时重连
    if (s->routine_timer_times < 10) {
        goto out;
    }
    s->routine_timer_times = 0;
    // tell if request is timeout
    if (is_req_timeout(s)) {
        //TODO handle resend
        udisk_net_reconnect(s);
    }
out:
    s->co_timeout = NULL;
}

static void routine_cb(void *p)
{
    BDRVUDiskState *s = p;

    timer_mod(s->routine_timer,
              qemu_clock_get_ns(QEMU_CLOCK_REALTIME) / 1000000 + routine_timeout);
    if (!s->co_timeout) {
        s->co_timeout = qemu_coroutine_create(udisk_reconnect_co_entry, s);
        qemu_coroutine_enter(s->co_timeout);
    }
}

static QemuOptsList runtime_opts = {
    .name = "udisk",
    .head = QTAILQ_HEAD_INITIALIZER(runtime_opts.head),
    .desc = {
        {
            .name = "filename",
            .type = QEMU_OPT_STRING,
            .help = "URL to the udisk image",
        },
        { /* end of list */}
    },
};

static int udisk_parse_filename(struct BDRVUDiskState *s, const char *filename)
{
    char *p1, *p2, *p3;
    char port[1024];
    int port_num;

    // udisk:192.168.8.205:8124:550c6ef1-2654-4ceb-81bd-1d925de6fa44
    if (!(p1 = strchr(filename, ':')))
        goto error;
    if (!(p2 = strchr(p1+1, ':')))
        goto error;
    if (!(p3 = strchr(p2+1, ':')))
        goto error;

    strncpy(s->bsip, p1+1, p2-p1-1);
    strncpy(port, p2+1, p3-p2-1);

    port_num = atoi(port);
    if ( port_num >= 65536 ) {
        goto error;
    }
    s->bsport = port_num;

    snprintf(s->bsid, sizeof(s->bsid), "%s", p3 + 1);
    return 0;

error:
    return -1;
}

static void coroutine_fn do_net_request(BDRVUDiskState *s, AIOReq *aio_req)
{
    int ret = 0;

    qemu_co_mutex_lock(&s->lock);
    s->co_send = qemu_coroutine_self();
    aio_set_fd_handler(s->aio_ctx, s->curr_socket, false,
                       co_recv_response, co_send_request, NULL, s);

    ret = qemu_co_send(s->curr_socket, &aio_req->head,
                       sizeof(aio_req->head));
    if (ret != sizeof(aio_req->head)) {
        DPRINTF("%s: failed to send head: %m", s->bsid);
        goto out;
    }
    if ((aio_req->aiocb->aiocb_type == CMD_WRITE)) {
        ret = qemu_co_sendv(s->curr_socket, aio_req->aiocb->qiov->iov,
                            aio_req->aiocb->qiov->niov,
                            aio_req->send_offset,
                            aio_req->data_len);
        if (ret != aio_req->data_len) {
            DPRINTF("%s: failed to send data: %m", s->bsid);
            goto out;
        }
    }
out:
    aio_set_fd_handler(s->aio_ctx, s->curr_socket, false,
                       co_recv_response, NULL, NULL, s);
    s->co_send = NULL;
    qemu_co_mutex_unlock(&s->lock);
}

static int udisk_open(BlockDriverState *bs, QDict *options,
                      int flags, Error **errp)
{
    Error *err = NULL;
    struct BDRVUDiskState *s = bs->opaque;
    QemuOpts *opts;
    Error *local_err = NULL;
    int ret = 0;

    opts = qemu_opts_create(&runtime_opts, NULL, 0, &err);
    qemu_opts_absorb_qdict(opts, options, &local_err);
    if (local_err) {
        error_report_err(local_err);
    }

    if ( 0 != udisk_parse_filename(s, bs->filename) ) {
        error_report("udisk parse filename %s failed", bs->filename);
        return -EINVAL;
    }

    s->state = DS_NORMAL;
    s->routine_timer = NULL;
    s->time_out_flowno = 0;
    s->is_first_timeout = true;
    s->routine_timer_times = 0;

    snprintf(s->sock_name, 80, "/var/%s.sock", s->bsip);
    s->curr_socket = unix_connect(s->sock_name, NULL);
    if ( -1 == s->curr_socket ) {
        error_report("%s: udisk unix connect failed: %m", s->bsid);
        goto end;
    }

    ret = udisk_sync_getlength(s, &err);
    if ( err ) {
        error_report("%s: udisk sync get length failed: %m", s->bsid);
        goto end;
    }

    QTAILQ_INIT(&s->net_inflight_head);
    qemu_co_mutex_init(&s->lock);
    qemu_co_mutex_init(&s->queue_lock);

    // add aio context
    s->aio_ctx = bdrv_get_aio_context(bs);
    s->net_inflight_count = 0;

    s->routine_timer = aio_timer_new(s->aio_ctx, QEMU_CLOCK_REALTIME,
                                     SCALE_MS, routine_cb, s);
    timer_mod(s->routine_timer,
              qemu_clock_get_ns(QEMU_CLOCK_REALTIME) / 1000000 +
              routine_timeout);

 end:
    if ( err != NULL ) {
        error_report_err(err);
        if ( s->curr_socket >= 0 ) {
            udisk_close(bs);
        }
        if ( s->routine_timer ) {
            timer_del(s->routine_timer);
            timer_free(s->routine_timer);
        }
        return ret;
    } else {
        qemu_set_nonblock(s->curr_socket);
        return ret;
    }
}

static int udisk_file_open(BlockDriverState *bs,
                           QDict *options, int flags, Error **errp)
{
    return udisk_open(bs, options, flags, errp);
}

static void udisk_attach_aio_context(BlockDriverState *bs,
                                     AioContext *new_context)
{
    struct BDRVUDiskState *s = bs->opaque;
    s->aio_ctx = new_context;
    aio_set_fd_handler(new_context, s->curr_socket, false,
                       co_recv_response, NULL, NULL, s);
    s->routine_timer = aio_timer_new(s->aio_ctx, QEMU_CLOCK_REALTIME,
                                     SCALE_MS, routine_cb, s);
    timer_mod(s->routine_timer,
              qemu_clock_get_ns(QEMU_CLOCK_REALTIME) / 1000000 + routine_timeout);
}

static void udisk_detach_aio_context(BlockDriverState *bs)
{
    struct BDRVUDiskState *s = bs->opaque;
    aio_set_fd_handler(s->aio_ctx, s->curr_socket, false,
                       NULL, NULL, NULL, s);
    if (s->routine_timer) {
        timer_del(s->routine_timer);
        timer_free(s->routine_timer);
        s->routine_timer = NULL;
    }
}

static void coroutine_fn udisk_gen_head(AIOReq *aio_req)
{
    struct UDiskAIOCB *acb = aio_req->aiocb;
    aio_req->head.size = sizeof(struct protohead);
    aio_req->head.cmd = acb->aiocb_type;
    aio_req->head.sector = acb->sector;
    aio_req->head.secnum = acb->nr_sectors;
    aio_req->head.flowno = aio_req->seqno;
    aio_req->head.retcode = 0;
    if ( acb->aiocb_type == CMD_WRITE ) {
        aio_req->head.size += acb->nr_sectors * SECTOR_SIZE;
    }
    aio_req->head.magic = MAGIC_NUMBER;
}

static void coroutine_fn udisk_co_rw_vector(void *p)
{
    UDiskAIOCB *acb = p;
    BDRVUDiskState *s = acb->common.bs->opaque;
    AIOReq *aio_req;
    unsigned long total = acb->nr_sectors * BDRV_SECTOR_SIZE;

    acb->nr_pending++;
    aio_req = alloc_aio_req(s, acb, total, 0, 0, 0);
    udisk_gen_head(aio_req);

    qemu_co_mutex_lock(&s->queue_lock);
    QTAILQ_INSERT_TAIL(&s->net_inflight_head, aio_req, entry);
    s->net_inflight_count++;
    qemu_co_mutex_unlock(&s->queue_lock);

    dispatch_request(s, aio_req);
}

static int64_t udisk_getlength(BlockDriverState *bs)
{
    BDRVUDiskState *s = bs->opaque;
    return s->sectors * SECTOR_SIZE;
}

static int udisk_probe_device(const char *filename)
{
    if (strstart(filename, DRIVER_NAME, NULL))
        return 100;

    return 0;
}

static coroutine_fn int udisk_co_pdiscard(BlockDriverState *bs,
                                          int64_t sector_num, int nb_sectors)
{
    return 0;
}

static coroutine_fn int coroutine_fn udisk_co_flush(BlockDriverState *bs)
{
    return 0;
}

static int coroutine_fn udisk_co_readv(BlockDriverState *bs, int64_t sector_num,
                                       int nb_sectors, QEMUIOVector *qiov)
{
    UDiskAIOCB *acb;
    int ret;

    acb = udisk_aio_setup(bs, qiov, sector_num, nb_sectors, CMD_READ);
    acb->finished = 0;
    udisk_co_rw_vector(acb);
    qemu_coroutine_yield();

    ret = acb->ret;
    qemu_aio_unref(acb);
    return ret;
}

static int coroutine_fn udisk_co_writev(BlockDriverState *bs, int64_t sector_num,
                                        int nb_sectors, QEMUIOVector *qiov)
{
    UDiskAIOCB *acb;
    int ret;

    acb = udisk_aio_setup(bs, qiov, sector_num, nb_sectors, CMD_WRITE);
    udisk_co_rw_vector(acb);
    qemu_coroutine_yield();

    ret = acb->ret;
    qemu_aio_unref(acb);
    return ret;
}

static int udisk_truncate(BlockDriverState *bs, int64_t offset,
                          PreallocMode prealloc, Error **errp)
{
    BDRVUDiskState *s = bs->opaque;
    uint64_t old_length;
    uint64_t flowno;
    struct protohead *req_head;
    int ret, fd;

    if (prealloc != PREALLOC_MODE_OFF && prealloc != PREALLOC_MODE_METADATA &&
        prealloc != PREALLOC_MODE_FALLOC && prealloc != PREALLOC_MODE_FULL)
    {
        error_setg(errp, "%s: Unsupported preallocation mode '%s'",
                   s->bsid, PreallocMode_lookup[prealloc]);
        return -ENOTSUP;
    }

    old_length = s->sectors * SECTOR_SIZE;
    if (offset < old_length) {
        error_setg(errp, "%s: udisk doesn't support shrinking images yet", s->bsid);
        return -ENOTSUP;
    }

    fd = udisk_unix_connect(s->sock_name, 0, s);
    if ( fd < 0 ) {
        error_setg(errp, "%s: udisk connect failed: %m\n", s->bsid);
        return fd;
    }

    req_head = make_truncate_request(s->bsid, &flowno, offset);
    ret = do_req(fd, bs, req_head);

    if (ret == 0)
        s->sectors = DIV_ROUND_UP(offset, SECTOR_SIZE);

    if ( ret < 0 ) {
        error_setg(errp, "%s: udisk resize failed: %m\n", s->bsid);
    }

    free(req_head);
    closesocket(fd);
    return ret;
}

static BlockDriver bdrv_udisk = {
    .format_name                    = DRIVER_NAME,
    .protocol_name                  = DRIVER_NAME,
    .instance_size                  = sizeof(BDRVUDiskState),
    .bdrv_probe_device              = udisk_probe_device,
    .bdrv_file_open                 = udisk_file_open,
    .bdrv_open                      = udisk_open,
    .bdrv_getlength                 = udisk_getlength,
    .bdrv_close                     = udisk_close,

    .bdrv_co_readv                  = udisk_co_readv,
    .bdrv_co_writev                 = udisk_co_writev,
    .bdrv_co_pdiscard               = udisk_co_pdiscard,
    .bdrv_co_flush_to_disk          = udisk_co_flush,
    .bdrv_detach_aio_context       	= udisk_detach_aio_context,
    .bdrv_attach_aio_context       	= udisk_attach_aio_context,
    .bdrv_truncate                  = udisk_truncate,
};

static void bdrv_udisk_init(void)
{
    bdrv_register(&bdrv_udisk);
}
block_init(bdrv_udisk_init);

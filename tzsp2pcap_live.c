#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdbool.h>
#include <getopt.h>

#define DEFAULT_LISTEN_PORT 37008
#define DEFAULT_BUFFER_SIZE 65535
#define DEFAULT_TAP_DEVICE "tzsp0"

/* TZSP Protocol Definitions */
#define TZSP_TYPE_RECEIVED_TAG_LIST 0
#define TZSP_TYPE_PACKET_FOR_TRANSMIT 1
#define TZSP_TYPE_KEEPALIVE 4

#define TZSP_TAG_END 1
#define TZSP_TAG_PADDING 0

struct tzsp_header {
	uint8_t version;
	uint8_t type;
	uint16_t encap;
} __attribute__((packed));

/* Global variables */
static int self_pipe[2];
static volatile sig_atomic_t should_exit = 0;

/* Signal handler */
static void signal_handler(int signum)
{
    (void)signum;
    should_exit = 1;
    char dummy = 0;
    if (write(self_pipe[1], &dummy, 1) == -1)
    {
        /* Ignore errors inside signal handler */
    }
}

static void setup_signals(void)
{
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
}

/* Create TAP device */
static int create_tap_device(const char *dev_name)
{
    struct ifreq ifr;
    int fd, err;

    fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
    if (fd < 0)
    {
        perror("open /dev/net/tun");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, dev_name, IFNAMSIZ - 1);

    err = ioctl(fd, TUNSETIFF, (void *)&ifr);
    if (err < 0)
    {
        perror("ioctl TUNSETIFF");
        close(fd);
        return -1;
    }

    /* Restore blocking mode for normal writes */
    int flags = fcntl(fd, F_GETFL);
    if (flags != -1)
    {
        fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
    }

    printf("TAP device %s created\n", ifr.ifr_name);
    return fd;
}

static int bring_interface_up(const char *dev_name)
{
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        perror("socket(AF_INET)");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev_name, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0)
    {
        perror("ioctl SIOCGIFFLAGS");
        close(fd);
        return -1;
    }

    if (!(ifr.ifr_flags & IFF_UP))
    {
        ifr.ifr_flags |= IFF_UP;
        if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0)
        {
            perror("ioctl SIOCSIFFLAGS");
            close(fd);
            return -1;
        }
    }

    close(fd);
    return 0;
}

/* Parse TZSP tags and return offset to encapsulated data */
static int parse_tzsp_tags(const uint8_t *data, int len)
{
    int offset = 0;

    while (offset < len)
    {
        uint8_t tag_type = data[offset];

        if (tag_type == TZSP_TAG_END)
        {
            return offset + 1;
        }

        if (tag_type == TZSP_TAG_PADDING)
        {
            offset++;
            continue;
        }

        if (offset + 1 >= len)
            break;

        uint8_t tag_len = data[offset + 1];
        offset += 2 + tag_len;
    }

    return -1;
}

/* Check if packet is a TZSP packet (to filter loops) */
static int is_tzsp_packet(const uint8_t *data, int len, int listen_port)
{
    if (len < 14)
        return 0;

    uint16_t ethertype = (data[12] << 8) | data[13];
    if (ethertype != 0x0800)
        return 0;

    if (len < 34)
        return 0;

    uint8_t ihl = (data[14] & 0x0F) * 4;
    uint8_t proto = data[23];

    if (proto != 17)
        return 0;

    int udp_offset = 14 + ihl;
    if (len < udp_offset + 4)
        return 0;

    uint16_t dest_port = (data[udp_offset + 2] << 8) | data[udp_offset + 3];
    return (dest_port == listen_port);
}

/* Parse and write TZSP packets */
static void parse_tzsp_packet(const uint8_t *buf, int recv_len, int tap_fd,
                  int listen_port, bool filter_enabled, int verbose,
                  unsigned long *pkt_count, unsigned long *filtered_count)
{
    int offset = 0;

    while (offset < recv_len)
    {
        if (recv_len - offset < (int)sizeof(struct tzsp_header))
            break;

        const struct tzsp_header *hdr = (const struct tzsp_header *)(buf + offset);
        offset += sizeof(struct tzsp_header);

        if (hdr->version != 1)
        {
            if (verbose)
            {
                fprintf(stderr, "Unsupported TZSP version %u\n", hdr->version);
            }
            break;
        }

        if (hdr->type != TZSP_TYPE_RECEIVED_TAG_LIST &&
            hdr->type != TZSP_TYPE_PACKET_FOR_TRANSMIT)
        {
            if (verbose)
            {
                fprintf(stderr, "Skipping TZSP type %u\n", hdr->type);
            }
            break;
        }

        int tag_end = parse_tzsp_tags(buf + offset, recv_len - offset);
        if (tag_end < 0)
        {
            if (verbose)
            {
                fprintf(stderr, "Malformed TZSP tag list\n");
            }
            break;
        }

        offset += tag_end;
        int frame_len = recv_len - offset;
        if (frame_len <= 0)
            break;

        const uint8_t *frame = buf + offset;

        if (filter_enabled && is_tzsp_packet(frame, frame_len, listen_port))
        {
            (*filtered_count)++;
            if (verbose > 1)
            {
                fprintf(stderr, "Filtered TZSP loop packet -> port %d\n", listen_port);
            }
            offset += frame_len;
            continue;
        }

        ssize_t written = write(tap_fd, frame, frame_len);
        if (written < 0)
        {
            perror("write to TAP");
        }
        else if (written != frame_len)
        {
            fprintf(stderr, "Partial write to TAP: %zd/%d\n", written, frame_len);
        }
        else
        {
            (*pkt_count)++;
            if (verbose && (*pkt_count % 10000 == 0))
            {
                fprintf(stderr, "Injected %lu frames\n", *pkt_count);
            }
        }

        offset += frame_len;
    }
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [options]\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -p PORT    Listen port (default: %d)\n", DEFAULT_LISTEN_PORT);
    fprintf(stderr, "  -d DEVICE  TAP device name (default: %s)\n", DEFAULT_TAP_DEVICE);
    fprintf(stderr, "  -v         Verbose output\n");
    fprintf(stderr, "  -F         Disable TZSP loop filter\n");
    fprintf(stderr, "  -h         Show this help\n");
    exit(1);
}

int main(int argc, char *argv[])
{
    int listen_port = DEFAULT_LISTEN_PORT;
    const char *tap_device = DEFAULT_TAP_DEVICE;
    int verbose = 0;
    bool filter_enabled = true;
    int opt;

    while ((opt = getopt(argc, argv, "p:d:vFh")) != -1)
    {
        switch (opt)
        {
        case 'p':
            listen_port = atoi(optarg);
            break;
        case 'd':
            tap_device = optarg;
            break;
        case 'v':
            verbose++;
            break;
        case 'F':
            filter_enabled = false;
            break;
        case 'h':
        default:
            usage(argv[0]);
        }
    }

    /* Create self-pipe for signal handling */
    if (pipe(self_pipe) < 0)
    {
        perror("pipe");
        return 1;
    }

    setup_signals();

    /* Create TAP device */
    int tap_fd = create_tap_device(tap_device);
    if (tap_fd < 0)
    {
        fprintf(stderr, "Failed to create TAP device. Run as root?\n");
        return 1;
    }

    if (bring_interface_up(tap_device) < 0)
    {
        fprintf(stderr, "Failed to bring %s UP\n", tap_device);
        close(tap_fd);
        return 1;
    }

    /* Create UDP socket */
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        perror("socket");
        close(tap_fd);
        return 1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(listen_port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind");
        close(sock);
        close(tap_fd);
        return 1;
    }

    printf("Listening on UDP port %d, injecting to %s\n", listen_port, tap_device);
    if (filter_enabled)
    {
        printf("Loop filter: ENABLED (filtering TZSP packets to port %d)\n", listen_port);
    }
    else
    {
        printf("Loop filter: DISABLED\n");
    }

    uint8_t *buffer = malloc(DEFAULT_BUFFER_SIZE);
    if (!buffer)
    {
        perror("malloc");
        close(sock);
        close(tap_fd);
        return 1;
    }

    unsigned long pkt_count = 0;
    unsigned long filtered_count = 0;
    fd_set readfds;
    int maxfd = (sock > self_pipe[0] ? sock : self_pipe[0]) + 1;

    while (!should_exit)
    {
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        FD_SET(self_pipe[0], &readfds);

        int ret = select(maxfd, &readfds, NULL, NULL, NULL);
        if (ret < 0)
        {
            if (errno == EINTR)
                continue;
            perror("select");
            break;
        }

        if (FD_ISSET(self_pipe[0], &readfds))
        {
            break;
        }

        if (FD_ISSET(sock, &readfds))
        {
            ssize_t recv_len = recv(sock, buffer, DEFAULT_BUFFER_SIZE, 0);
            if (recv_len < 0)
            {
                perror("recv");
                continue;
            }

            if (recv_len > 0)
            {
                parse_tzsp_packet(buffer, recv_len, tap_fd, listen_port,
                                  filter_enabled, verbose, &pkt_count, &filtered_count);
            }
        }
    }

    printf("\nInjected %lu frames", pkt_count);
    if (filter_enabled)
    {
        printf(" (filtered %lu TZSP loop frames)", filtered_count);
    }
    printf("\n");

    free(buffer);
    close(sock);
    close(tap_fd);
    close(self_pipe[0]);
    close(self_pipe[1]);

    return 0;
}

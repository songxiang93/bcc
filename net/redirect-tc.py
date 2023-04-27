from bcc import BPF
from socket import ntohl, htons, ntohs, inet_aton
from struct import pack, unpack

# Define the IP addresses to forward packets to and receive packets from
DEST_IP = "192.168.1.100"
SRC_IP = "192.168.1.200"

# Define the eBPF program
program = """
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

/* Swap the source and destination IP addresses */
static inline void swap_ip_addr(struct iphdr *iph) {
    u32 tmp = iph->saddr;
    iph->saddr = iph->daddr;
    iph->daddr = tmp;
}

/* Swap the source and destination MAC addresses */
static inline void swap_mac_addr(struct ethhdr *eth) {
    u8 tmp[ETH_ALEN];
    memcpy(tmp, eth->h_dest, ETH_ALEN);
    memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    memcpy(eth->h_source, tmp, ETH_ALEN);
}

int forward_tcp(struct __sk_buff *skb) {
    u8 *cursor = (u8 *)(long)skb->data;
    u32 len = skb->len;

    /* Parse the Ethernet header */
    struct ethhdr *eth = cursor;
    if (eth + 1 > (struct ethhdr *)(cursor + len))
        return 0;
    u16 eth_type = ntohs(eth->h_proto);
    cursor += sizeof(struct ethhdr);

    /* Parse the IP header */
    if (eth_type != ETH_P_IP)
        return 0;
    struct iphdr *iph = cursor;
    if (iph + 1 > (struct iphdr *)(cursor + len))
        return 0;
    u32 saddr = ntohl(iph->saddr);
    u32 daddr = ntohl(iph->daddr);
    cursor += sizeof(struct iphdr);

    /* Parse the TCP header */
    if (iph->protocol != IPPROTO_TCP)
        return 0;
    struct tcphdr *tcph = cursor;
    if (tcph + 1 > (struct tcphdr *)(cursor + len))
        return 0;
    u16 sport = ntohs(tcph->source);
    u16 dport = ntohs(tcph->dest);
    cursor += sizeof(struct tcphdr);

    /* Swap the source and destination IP addresses */
    if (saddr == inet_aton(SRC_IP) and daddr == inet_aton(DEST_IP)) {
        swap_ip_addr(iph);

        /* Modify the TCP checksum to reflect the changed IP addresses */
        u16 csum = ntohs(tcph->check);
        u32 sum = csum + saddr + daddr + ((u16)iph->protocol << 8) + htons(sizeof(struct tcphdr));
        while (sum >> 16)
            sum = (sum & 0xFFFF) + (sum >> 16);
        tcph->check = htons(~sum);

        /* Redirect the packet to the destination IP address */
        skb->pkt_type = PACKET_OUTGOING;
        skb->sk = 0;
        skb->dev = skb->dev_out;
        skb->ip_summed = CHECKSUM_NONE;

        /* Swap the source and destination MAC addresses */
        swap_mac_addr(eth);

        /* Set the destination MAC address to the default gateway */
        u8 new_mac[ETH_ALEN] = {0x00, 0x0c, 0x29, 0x54, 0xb5, 0x25};
        memcpy(eth->h_dest, new_mac, ETH_ALEN);

        /* Set the source MAC address to the current interface */
        skb->mac_off = offsetof(struct ethhdr, h_source);
        skb->mac_len = ETH_ALEN;
        bpf_skb_store_bytes(skb, skb->mac_off, eth->h_source, ETH_ALEN, 0);

        /* Send the packet */
        return skb->len;
    }

    return 0;
}
"""

# Load the eBPF program
b = BPF(text=program)

# Attach the eBPF program to the tc ingress hook
fn = b.load_func("forward_tcp", BPF.SCHED_CLS)

# Attach the tc filter to match incoming TCP packets
# b.attach_filter(fn, 0, 0, 0xFFFFFFF, 0)
#
# # Print a message to indicate that the program is running
# print("eBPF program running...")
#
# # Loop indefinitely to keep the program running
# try:
#     while True:
#         b.kprobe_poll()
# except KeyboardInterrupt:
#     pass
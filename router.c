#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <string.h>
#include <arpa/inet.h>

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define ROUTE_TABLE_SIZE 100

// Routing table
struct route_table_entry *rtable;
int rtable_len;

// Mac table
struct arp_table_entry *arp_table;
int arp_table_len;

void send_icmp (struct ether_header *eth_hdr, char buf[MAX_PACKET_LEN], uint8_t type, int interface, size_t len);
int compare (const void *elem1, const void *elem2);
struct route_table_entry *get_best_route(uint32_t dest_ip);
struct arp_table_entry *get_arp_entry(uint32_t given_ip);
int checksum_func (struct iphdr *ip_hdr, uint16_t received_checksum);
int mac_adr_check (struct ether_header *eth_hdr, int interface);
int ttl_check (struct iphdr *ip_hdr);

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	int arp_table_capacity = 100000;
	int rtable_capacity = 100000;
	rtable = malloc(sizeof(struct route_table_entry) * rtable_capacity);
	arp_table = (struct arp_table_entry *)malloc(sizeof(struct arp_table_entry) * arp_table_capacity);
	arp_table_len = parse_arp_table("arp_table.txt", arp_table);

	qsort(rtable, (int) read_rtable(argv[1], rtable), sizeof(struct route_table_entry), compare);

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		
		int check_mac = mac_adr_check(eth_hdr, interface);
		// Pachetul este pentru acest router
	 	if (check_mac == 1) {
			// Este un pachet de tip IPv4
			if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {

				struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

				if (inet_addr(get_interface_ip(interface)) == ip_hdr->daddr) {
					send_icmp(eth_hdr, buf, 0, interface, len);
					continue;
				}

				uint16_t received_checksum = ntohs(ip_hdr->check);
				if (checksum_func(ip_hdr, received_checksum) == 0) {
					continue;
				}
				// Verificare TTL
				if (ttl_check(ip_hdr)) {
					send_icmp(eth_hdr, buf, 11, interface, len);
					continue;
				}
				// Actualizare checksum si TTL
				ip_hdr->ttl--;
				ip_hdr->check = 0;
				ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
				// Cautare in tabela de rutare
				struct route_table_entry *entry = get_best_route(ip_hdr->daddr);
				if (entry == NULL) {
					// Nu s-a gasit o ruta pentru destinatie, aruncam pachetul si trimitem un mesaj ICMP de tip "Destination unreachable"
					send_icmp(eth_hdr, buf, 3, interface, len);
					continue;
				}
				// Obtinem intrarea ARP pentru adresa IP a urmatorului hop
				struct arp_table_entry *arp = get_arp_entry(entry->next_hop);
				get_interface_mac(entry->interface, eth_hdr->ether_shost);
				memcpy(eth_hdr->ether_dhost, arp->mac, sizeof(uint8_t) * 6);
				// Trimitem pachetul
				send_to_link(entry->interface, buf, len);
				continue;
			} 
		}
	}
}

struct arp_table_entry *get_arp_entry(uint32_t given_ip) {
	int i;
	for (i = 0; i < arp_table_len; i++) {
		if (given_ip == arp_table[i].ip)
			return &arp_table[i];
	}
	return NULL;
}
// Functia de cautare binara pentru a gasi cea mai buna ruta
struct route_table_entry *get_best_route(uint32_t dest_ip) {
    int left = 0;
	int mid;
    int right = ROUTE_TABLE_SIZE - 1;

    while (left <= right) {
        mid = left + (right - left) / 2;

        if ((rtable[mid].prefix & rtable[mid].mask) <= (dest_ip & rtable[mid].mask)) {
            if (mid == ROUTE_TABLE_SIZE - 1 || (rtable[mid + 1].prefix & rtable[mid + 1].mask) > (dest_ip & rtable[mid + 1].mask))
                return &rtable[mid];
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }
    return NULL; // Nu s-a gasit nicio ruta pentru destinatie
}

// Functia de comparatie pentru cautarea binara
int compare (const void *elem1, const void *elem2) {
	// Compararea se face pe baza valorii prefixului combinat cu masca
    struct route_table_entry *entry1 = (struct route_table_entry *)elem1;
	uint32_t combined_masked_prefix1 = entry1->prefix & entry1->mask;

	struct route_table_entry *entry2 = (struct route_table_entry *)elem2;
	uint32_t combined_masked_prefix2 = entry2->prefix & entry2->mask;

	if (combined_masked_prefix1 != combined_masked_prefix2)
		return combined_masked_prefix1 - combined_masked_prefix2;
	else
		return entry1->mask - entry2->mask;
}

void send_icmp (struct ether_header *eth_hdr, char buf[MAX_PACKET_LEN], uint8_t type, int interface, size_t len) {
	// Calculam noua lungime a pachetului
    size_t len2 = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
	uint32_t dest_ip_adr;
	uint8_t temp_mac[6];
	// Extragem header IP din buffer
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

	// Schimbam adresele IP sursa si destinatie
	dest_ip_adr = ip_hdr->daddr;
	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->saddr = dest_ip_adr;
	// Schimbam adresele MAC sursa si destinatie
	for (int i = 0; i < 6; ++i) {
    	temp_mac[i] = eth_hdr->ether_dhost[i];
	}
	for (int i = 0; i < 6; ++i) {
    	eth_hdr->ether_dhost[i] = eth_hdr->ether_shost[i];
	}
	for (int i = 0; i < 6; ++i) {
    	eth_hdr->ether_shost[i] = temp_mac[i];
	}

	// Extragem header ICMP din buffer
	struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
	// ICMP si IP header data
	ip_hdr->protocol = 1;
	icmp_hdr->code = 0;
	icmp_hdr->type = type;
	ip_hdr->check = 0;
	ip_hdr->check = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	send_to_link(interface, buf, len2);
}

int checksum_func (struct iphdr *ip_hdr, uint16_t received_checksum) {
	// Verificare checksum
    ip_hdr->check = 0;
	uint16_t calculated_checksum = 0;
	calculated_checksum = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));
	if (calculated_checksum != received_checksum) {
		// Suma de control nu se potriveste, aruncam pachetul
		return 0;
	}
	return 1;
}

int mac_adr_check (struct ether_header *eth_hdr, int interface) {
	uint8_t mac_adr[6];
	get_interface_mac(interface, mac_adr);

	 // Parcurgem fiecare byte al adresei MAC a destinatarului
	for (int i = 0; i < 6; i++) {
		// Verificam daca byte-ul nu este broadcast si nu corespunde cu adresa MAC a interfetei
		if (eth_hdr->ether_dhost[i] != 0xff && eth_hdr->ether_dhost[i] != mac_adr[i]) {
			return 0;
		}
	}
	return 1;
}

int ttl_check (struct iphdr *ip_hdr) {
	// Verificare TTL
	uint8_t ttl = ip_hdr->ttl;
	if (ttl <= 1) {
		// TTL-ul este prea mic, aruncam pachetul si trimitem un mesaj ICMP de tip "Time exceeded"
		return 1;
	}
	return 0;
}
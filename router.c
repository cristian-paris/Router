#include <queue.h>
#include "skel.h"

struct route_table_entry {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
} __attribute__((packed));

struct arp_entry {
	__u32 ip;
	uint8_t mac[6];
};

struct arp_structure {
	struct arp_entry *arp_table_in;
	int table_capacity;
	int size;
};

int count_lines(char *filename) {
    char c;
    int count = 0;
    FILE *fp = fopen(filename, "r");
  
    if (fp == NULL) {
        perror("Could not open file");
        return 0;
    }
  
    for (c = getc(fp); c != EOF; c = getc(fp)) {
        if (c == '\n') {
            count = count + 1;
        }
    }
    fclose(fp);
    return count;
}

struct route_table_entry *read_rtable(char *argument) {
	int size = count_lines(argument); // r_size
	struct route_table_entry *rtable;

	FILE *f = fopen(argument, "r");
	if (f == NULL) {
		perror("File cannot be opened.\n");
		return NULL;
	}
	
    char prefix[128] = {'\0'};
    char next_hop[128] = {'\0'};
    char mask[128] = {'\0'};
    int temp_int = 0;
	int count = 0;

	rtable = (struct route_table_entry*)malloc(size * sizeof(struct route_table_entry));
	if (rtable == NULL) {
		perror("Allocation failed\n");
		return NULL;
	}

	while (fscanf(f, "%s %s %s %d", prefix, next_hop, mask, &temp_int) != EOF) {
        inet_pton(AF_INET, prefix, &rtable[count].prefix);
        inet_pton(AF_INET, next_hop, &rtable[count].next_hop);
        inet_pton(AF_INET, mask, &rtable[count].mask);
        rtable[count].interface = temp_int;
		count++;
	}
	fclose(f);
	return rtable;
}

int check_arp(uint32_t sender_ip, struct arp_structure *arp_table) {
	for (int i = 0; i < arp_table->size; i++) {
		if (sender_ip == arp_table->arp_table_in[i].ip) {
			return 1;
		}
	}
	return 0;
}

int comparator(const void *o1, const void *o2) {
	struct route_table_entry *o1_aux = (struct route_table_entry *)o1;
	struct route_table_entry *o2_aux = (struct route_table_entry *)o2;
	if (o1_aux->prefix != o2_aux->prefix) {
		return (int)(o1_aux->prefix - o2_aux->prefix);
	} else {
		return (int)(o2_aux->mask - o1_aux->mask);
	}
}

struct route_table_entry *get_best_route(struct route_table_entry* rtable, int l, int r, __u32 dest_ip) {
	while (l <= r) {
        int mid = l + (r - l) / 2;
        if ((rtable[mid].mask & dest_ip) == rtable[mid].prefix) {
            int aux = rtable[mid].prefix;
            while (rtable[mid].prefix == aux) {
                mid--;
            }
            return &rtable[++mid];
		} else if ((rtable[mid].mask & dest_ip) > rtable[mid].prefix) {
            l = mid + 1;
        } else {
            r = mid - 1;
        }
    }
    return NULL;
}

struct arp_entry *get_arp_entry(__u32 ip, struct arp_structure *arp_table) {
	for(int i=0; i < arp_table->size; i++) {
		if(arp_table->arp_table_in[i].ip == ip) {
			return (&arp_table->arp_table_in[i]);
		}
	}
    return NULL;
}

packet* create_copy(packet m) {
	packet* aux = malloc(sizeof(packet));
	if (aux == NULL) {
		perror("Allocation failed\n");
		return NULL;
	}
	aux->interface = m.interface;
	aux->len = m.len;
	return aux;
}

int main(int argc, char *argv[]) {
	setvbuf(stdout , NULL , _IONBF , 0);
	packet m;
	int rc;

	struct route_table_entry *rtable = read_rtable(argv[1]); // parsez si aloc tabela de rutare
	int r_size = count_lines(argv[1]);
	// Sortez crescator dupa prefix si descrecator dupa mask (crescator dupa ambele == crapa)
	qsort(rtable, r_size, sizeof(struct route_table_entry), comparator); 

	// Initializare tabela dinamica arp
	struct arp_structure *arp_table;
	arp_table = (struct arp_structure *)malloc(sizeof(struct arp_structure));
	if (arp_table == NULL) {
		perror("Arp_table allocation failed\n");
		return -1;
	}
	arp_table->arp_table_in = malloc(sizeof(struct arp_entry) * 6);
	if (arp_table->arp_table_in == NULL) {
		perror("Arp_table_in allocation failed\n");
		return -1;
	}
	arp_table->table_capacity = 6;
	arp_table->size = 0;

	queue coada;
	coada = queue_create();

	init(argc - 2, argv + 2);
	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");

		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
		// ICMP Echoreply
		if (ip_hdr->daddr == inet_addr(get_interface_ip(m.interface))) {
			struct icmphdr *icmp_hdr = parse_icmp(m.payload);
			if (icmp_hdr != NULL && icmp_hdr->type == ICMP_ECHO) {
				send_icmp(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost, eth_hdr->ether_shost,
				ICMP_ECHOREPLY, 0, m.interface, icmp_hdr->un.echo.id, icmp_hdr->un.echo.sequence);
				continue;
			}
		}

		struct arp_header *arp_hdr = parse_arp(m.payload);
		if (arp_hdr != NULL) {
			if (ntohs(arp_hdr->op) == ARPOP_REQUEST) { // Trimitere reply cu adresa mac a routerului
				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_dhost));
				get_interface_mac(m.interface, eth_hdr->ether_shost);
				send_arp(arp_hdr->spa, arp_hdr->tpa, eth_hdr, m.interface, htons(ARPOP_REPLY));
				continue;
			} else if (ntohs(arp_hdr->op) == ARPOP_REPLY) {
				if (check_arp(arp_hdr->spa, arp_table) == 0) { // Verificare existenta ip in tabela arp
					if (arp_table->size == arp_table->table_capacity) {
						arp_table->table_capacity *= 2;
						arp_table->arp_table_in = (struct arp_entry*)realloc(arp_table->arp_table_in,
						arp_table->table_capacity * sizeof(struct arp_entry));
					}
					// Primim un reply cu mac-ul, il inregistram in tabela arp
					arp_table->arp_table_in[arp_table->size].ip = arp_hdr->spa;
					memcpy(arp_table->arp_table_in[arp_table->size].mac, arp_hdr->sha, 6);
					arp_table->size++;
				}
				// Trimitem pachetele care se afla in coada
				if (!queue_empty(coada)) {
					packet *aux = (packet *)queue_deq(coada);
					struct ether_header *eth_hdr = (struct ether_header *)(aux->payload);
					struct iphdr *ip_hdr = (struct iphdr *)(aux->payload + sizeof(struct ether_header));
					struct route_table_entry* best = get_best_route(rtable, 0, r_size - 1, ip_hdr->daddr);
					struct arp_entry *dest_MAC_adress = get_arp_entry(best->next_hop, arp_table);
					memcpy(eth_hdr->ether_dhost, dest_MAC_adress->mac, 6);
					get_interface_mac(best->interface, eth_hdr->ether_shost);
					send_packet(best->interface, aux);
					continue;
				}
				continue;
			}
		}
		// Verificare TTL
		if (ip_hdr->ttl <= 1) {
			send_icmp_error(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost, eth_hdr->ether_shost,
			ICMP_TIME_EXCEEDED, 0, m.interface);
			continue;
		}
		// Verificare checksum gresit
		if (ip_checksum(ip_hdr, sizeof(struct iphdr)) != 0) {
			continue;
		}
		// Update header ip
		(ip_hdr->ttl)--;
		ip_hdr->check = 0;
		ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));
		// Gasire cea mai buna ruta
		struct route_table_entry* best_route = get_best_route(rtable, 0, r_size - 1, ip_hdr->daddr);
		if (best_route == NULL) {
			// Ruta nula, trimitem mesaj icmp
			send_icmp_error(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost,
			eth_hdr->ether_shost, ICMP_DEST_UNREACH, 0, m.interface);
			continue;
		} else {
			struct arp_entry *dest_MAC_adress = get_arp_entry(best_route->next_hop, arp_table);
			if (dest_MAC_adress == NULL) {
				// Nu stim mac-ul, cream o copie careia ii dam enqueue si trimitem arp request
				packet* aux = create_copy(m);
				memcpy(aux->payload, m.payload, sizeof(aux->payload));
				get_interface_mac(best_route->interface, eth_hdr->ether_shost);
				memset(eth_hdr->ether_dhost, 0xff, 6);
				eth_hdr->ether_type = htons(ETHERTYPE_ARP);
				send_arp(best_route->next_hop, inet_addr(get_interface_ip(best_route->interface)),
				eth_hdr, best_route->interface, htons(ARPOP_REQUEST));
				queue_enq(coada, aux);
				continue;
			}
			// Trimitem pachetul in cazul in care totul este cunoscut
			memcpy(eth_hdr->ether_dhost, dest_MAC_adress->mac, 6);
			get_interface_mac(best_route->interface, eth_hdr->ether_shost);
			send_packet(best_route->interface, &m);
		}
	}
	// Eliberare memorie
	free(coada);
	free(arp_table->arp_table_in);
	free(arp_table);
	free(rtable);
	return 0;
}
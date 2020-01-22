# Global variables
global domainsInEmails: set[string];
global addressesFromLinks: set[addr];

# Look for links in emails and track the host names
event mime_entity_data(c: connection, length: count, data: string) {
    
    local urls = find_all(data, /https*:\/\/[^\/]*/);
    
    if(|urls| == 0) 
        return;

    for (url in urls) {
        add domainsInEmails[split_string(url, /\//)[2]];
    }

}

# look for address resolutions involving the domain name from links in emails
event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr) {
    
    if (ans$query !in domainsInEmails) {
        return;
    }

    add addressesFromLinks[a];

}

# Alert on outbound connections to address from domain names...
event new_connection(c: connection) {
    
    if (c$id$resp_h !in addressesFromLinks) {
        return;
    }

    print fmt("Outbound connection from %s on port %s to %s on port %s", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);

}

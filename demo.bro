event zeek_init() {
    print "Hello, World";
}

# Connection function
event new_connection(c: connection) {
    print c$id$resp_h;
    print "----------------------------";
}

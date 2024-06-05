target("libcoap")
    set_kind("static")
    add_files("src/*.c|*lwip.c|*riot.c|*contiki*.c|*mbedtls.c", "src/oscore/*.c")
    add_cflags("-std=gnu99  -Werror -DLIBCOAP_PACKAGE_BUILD=\"v4.3.4-dirty\" -MD -MT")
    add_includedirs("include")
    if is_host("windows") then 
        add_ldflags("-lws2_32", "-static-libstdc++","-static", "-static-libgcc")
    end


target("libcoapexample")
    set_kind("binary")
    add_deps("libcoap")
    add_files("examples/coap-client.c")
    add_includedirs("include")
    if is_host("windows") then 
        add_ldflags("-lws2_32", "-static-libstdc++","-static", "-static-libgcc")
    end
idf_component_register(SRCS "openhaystack_main.c" "uECC.c"
                       INCLUDE_DIRS "."
                       REQUIRES bt nvs_flash driver)

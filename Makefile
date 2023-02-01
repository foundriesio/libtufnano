all:
	$(CC) -g -c ./libtufnano.c -o build/libtufnano.o -I tuf_sample_client/ -I ../coreJSON/source/include -I ../mbedtls/include/ -fsanitize=address,leak,undefined,pointer-compare,pointer-subtract -fstack-protector -Wall -Iext/fiat/src/
	$(CC) -g -c ./tuf_sample_client/tuf_sample_client.c -o build/tuf_sample_client.o -I ../coreJSON/source/include -I ../mbedtls/include/ -I ../Unity/src -I ../Unity/extras/fixture/src -I ../Unity/extras/memory/src -fsanitize=address,leak,undefined,pointer-compare,pointer-subtract -fstack-protector -Wall
	$(CC) -g -c ./tuf_sample_client/tuf_client_platform.c -o build/tuf_client_platform.o -I tuf_sample_client/ -I ./ -fsanitize=address,leak,undefined,pointer-compare,pointer-subtract -fstack-protector -Wunused-variable
	$(CC) -g -c ./tests/unit-test/libtufnano_utest.c -o build/libtufnano_utest.o  -I tuf_sample_client/  -I ../coreJSON/source/include -I ../Unity/src -I ../Unity/extras/fixture/src -I ../Unity/extras/memory/src -I . -I ../mbedtls/include/ -fsanitize=address,leak,undefined,pointer-compare,pointer-subtract -fstack-protector -Iext/fiat/src/
	$(CC) -g -c ../coreJSON/source/core_json.c -o build/core_json.o -I ../coreJSON/source/include -DJSON_QUERY_KEY_SEPARATOR=\'/\'
	$(CC) -g -c ../Unity/src/unity.c -o build/unity.o -I ../Unity/src
	$(CC) -g -c ../Unity/extras/fixture/src/unity_fixture.c -o build/unity_fixture.o -I ../Unity/src -I ../Unity/fixture/src  -I ../Unity/extras/memory/src
	$(CC) -g -c ext/fiat/src/curve25519.c -o build/curve25519.o -Iext/fiat/src/ -I../mbedtls/include
	$(CC) -g  ../mbedtls/library/*.o  build/curve25519.o build/core_json.o build/unity.o build/unity_fixture.o build/tuf_sample_client.o build/libtufnano_utest.o build/tuf_client_platform.o -o tuftest -fsanitize=address,leak,undefined,pointer-compare,pointer-subtract -fstack-protector

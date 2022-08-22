all:
	$(CC) -c ./libtufnano.c -o build/libtufnano.o -I ../coreJSON/source/include -I ../mbedtls/include/ -Wno-discarded-qualifiers
	$(CC) -c ./tuf_sample_client/tuf_sample_client.c -o build/tuf_sample_client.o -I ../coreJSON/source/include -I ../mbedtls/include/ -I ../Unity/src -I ../Unity/extras/fixture/src -I ../Unity/extras/memory/src -Wno-discarded-qualifiers
	$(CC) -c ./tuf_sample_client/tuf_client_platform.c -o build/tuf_client_platform.o -I ./
	$(CC) -c ./tests/unit-test/libtufnano_utest.c -o build/libtufnano_utest.o  -I ../Unity/src -I ../Unity/extras/fixture/src -I ../Unity/extras/memory/src -I . -I ../mbedtls/include/
	$(CC) -c ../coreJSON/source/core_json.c -o build/core_json.o -I ../coreJSON/source/include -DJSON_QUERY_KEY_SEPARATOR=\'/\'
	$(CC) -c ../Unity/src/unity.c -o build/unity.o -I ../Unity/src
	$(CC) -c ../Unity/extras/fixture/src/unity_fixture.c -o build/unity_fixture.o -I ../Unity/src -I ../Unity/fixture/src  -I ../Unity/extras/memory/src
	$(CC) ../mbedtls/library/*.o build/libtufnano.o build/core_json.o build/unity.o build/unity_fixture.o build/tuf_sample_client.o build/libtufnano_utest.o build/tuf_client_platform.o -o tuftest

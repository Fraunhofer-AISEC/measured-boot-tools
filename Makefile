all:
	make -C parse-srtm-pcrs
	make -C calculate-srtm-pcrs
	make -C parse-ima-pcr

install:
	install -v -m 0755 parse-srtm-pcrs/parse-srtm-pcrs /usr/bin/
	install -v -m 0755 calculate-srtm-pcrs/calculate-srtm-pcrs /usr/bin/
	install -v -m 0755 parse-ima-pcr/parse-ima-pcr /usr/bin/

clean:
	make -C parse-srtm-pcrs clean
	make -C calculate-srtm-pcrs clean
	make -C parse-ima-pcr clean

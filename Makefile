all:
	make -C parse-srtm-pcrs
	make -C calculate-srtm-pcrs
	make -C parse-ima-log

install:
	install -v -m 0700 parse-srtm-pcrs/parse-srtm-pcrs /usr/bin/
	install -v -m 0700 calculate-srtm-pcrs/calculate-srtm-pcrs /usr/bin/
	install -v -m 0700 parse-ima-log/parse-ima-log /usr/bin/

clean:
	make -C parse-srtm-pcrs clean
	make -C calculate-srtm-pcrs clean
	make -C parse-ima-log clean

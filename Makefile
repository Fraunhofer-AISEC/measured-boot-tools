all:
	make -C calculate-ima-pcr
	make -C calculate-snp-mr
	make -C calculate-srtm-pcrs
	make -C calculate-tdx-mrs
	make -C parse-ima-pcr
	make -C parse-srtm-pcrs
	make -C pcr-extend

install:
	install -v -m 0755 calculate-ima-pcr/calculate-ima-pcr /usr/bin/
	install -v -m 0755 calculate-snp-mr/calculate-snp-mr /usr/bin/
	install -v -m 0755 calculate-srtm-pcrs/calculate-srtm-pcrs /usr/bin/
	install -v -m 0755 calculate-tdx-mrs/calculate-tdx-mrs /usr/bin/
	install -v -m 0755 parse-ima-pcr/parse-ima-pcr /usr/bin/
	install -v -m 0755 parse-srtm-pcrs/parse-srtm-pcrs /usr/bin/
	install -v -m 0755 pcr-extend/pcr-extend /usr/bin/
clean:
	make -C calculate-ima-pcr clean
	make -C calculate-snp-mr clean
	make -C calculate-srtm-pcrs clean
	make -C calculate-tdx-mrs clean
	make -C parse-ima-pcr clean
	make -C parse-srtm-pcrs clean
	make -C pcr-extend clean

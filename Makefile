# NDNLoWPAN
# (C) 2017 HAW Hamburg
# Cenk Gündoğan <cenk.guendogan@haw-hamburg.de>


.PHONY: all build clean

WIRESHARK_SRC := $(PWD)/wireshark

all: build

build: $(WIRESHARK_SRC)/plugins/ndnlowpan/.libs/ndnlowpan.so

wireshark:
	[[ -d "wireshark" ]] || git clone --depth=1 https://code.wireshark.org/review/wireshark
	rsync -a src/ $(WIRESHARK_SRC)
	cd $(WIRESHARK_SRC) && ./autogen.sh && ./configure

$(WIRESHARK_SRC)/plugins/ndnlowpan/.libs/ndnlowpan.so: wireshark
	rsync -a src/ $(WIRESHARK_SRC)
	cd $(WIRESHARK_SRC) && $(MAKE)

clean::
	$(RM) -rf $(WIRESHARK_SRC)/plugins/ndnlowpan/.libs/ndnlowpan.so

distclean::
	$(RM) -rf $(WIRESHARK_SRC)

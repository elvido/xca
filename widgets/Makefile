#
# $Id$
#
############################################################################

MOC_NAMES= ExportCert ExportKey ExportTinyCA NewX509 CrlDetail CertDetail \
	MainWindow validity distname ReqDetail clicklabel ImportMulti \
	KeyDetail

NAMES=$(MOC_NAMES) NewX509_ext

OBJS=$(patsubst %,moc_%.o,$(MOC_NAMES)) $(patsubst %,%.o,$(NAMES))

DELFILES=$(patsubst %,moc_%.cpp,$(MOC_NAMES))

all: widgets.obj

include ../Rules.mak


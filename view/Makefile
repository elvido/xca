#
# $Id$
#
#########################################################################

NAMES= XcaListView KeyView ReqView TempView CertView CrlView 
		

OBJS=$(patsubst %,moc_%.o,$(NAMES)) $(patsubst %,%.o,$(NAMES)) main.o

DELFILES=$(patsubst %,moc_%.cpp,$(NAMES))

all: view.obj

include ../Rules.mak


#
# $Id$
#
#########################################################################

NAMES=func asn1int asn1time x509name x509rev x509v3ext pass_info \
	pki_key pki_x509super pki_x509req pki_x509 \
	pki_pkcs12 pki_temp pki_crl pki_pkcs7 \
	db_base 

MOCNAMES=pki_base db_key db_x509super db_x509req db_x509 db_temp db_crl load_obj

OBJS=$(patsubst %, %.o, $(NAMES) $(MOCNAMES)) $(patsubst %, moc_%.o, $(MOCNAMES))

DELFILES=$(patsubst %,moc_%.cpp,$(MOCNAMES))

include ../Rules.mak
  

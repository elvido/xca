/*
 * Copyright (C) 2001 Christian Hohnstaedt.
 *
 *  All rights reserved.
 *
 *
 *  Redistribution and use in source and binary forms, with or without 
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *  - Neither the name of the author nor the names of its contributors may be 
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * This program links to software with different licenses from:
 *
 *	http://www.openssl.org which includes cryptographic software
 * 	written by Eric Young (eay@cryptsoft.com)"
 *
 *	http://www.sleepycat.com
 *
 *	http://www.trolltech.com
 * 
 *
 *
 * http://www.hohnstaedt.de/xca
 * email: christian@hohnstaedt.de
 *
 * $Id$
 *
 */                           


#include "pki_pkcs7.h"
#include "exception.h"


pki_pkcs7::pki_pkcs7(const QString d )
	:pki_base(d)
{ 
	p7 = PKCS7_new();
	PKCS7_set_type(p7, NID_pkcs7_signed);
	PKCS7_content_new(p7, NID_pkcs7_data);
	class_name = "pki_pkcs7";
}	


pki_pkcs7::~pki_pkcs7()
{
	if (p7) PKCS7_free(p7);
}

void pki_pkcs7::encryptFile(pki_x509 *crt, QString filename)
{
	BIO *bio = NULL;
	STACK_OF(X509) *certstack;
	if (!crt) return;
	bio = BIO_new_file(filename, "r");
	certstack = sk_X509_new_null();
	sk_X509_push(certstack, crt->getCert());
	openssl_error();
	if (p7) PKCS7_free(p7);
	p7 = PKCS7_encrypt(certstack, bio, EVP_des_ede3_cbc(), PKCS7_BINARY);
	openssl_error();	
	sk_X509_free(certstack);
}

void pki_pkcs7::signBio(pki_x509 *crt, BIO *bio)
{
	pki_key *privkey;
	STACK_OF(X509) *certstack;
	if (!crt) return;
	privkey = crt->getRefKey();
	if (!privkey) throw errorEx("No private key for signing found", class_name);
	certstack = sk_X509_new_null();

	pki_x509 *signer = crt->getSigner();
	if (signer == crt) signer = NULL;
	while (signer != NULL ) {
		sk_X509_push(certstack, signer->getCert());
	        openssl_error();
		if (signer == signer->getSigner() ) signer = NULL;
		else signer = signer->getSigner();
	}
	if (p7) PKCS7_free(p7);
	p7 = PKCS7_sign(crt->getCert(), privkey->getKey(), certstack, bio, PKCS7_BINARY);
	openssl_error();	
	sk_X509_free(certstack);
}


void pki_pkcs7::signFile(pki_x509 *crt, QString filename)
{
	BIO *bio = NULL;
	if (!crt) return;
	bio = BIO_new_file(filename, "r");
        openssl_error();
	signBio(crt, bio);
	BIO_free(bio);
}
	
void pki_pkcs7::signCert(pki_x509 *crt, pki_x509 *contCert)
{
	BIO *bio = NULL;
	if (!crt) return;
	bio = BIO_new(BIO_s_mem());
        openssl_error();
	i2d_X509_bio(bio, contCert->getCert());
	signBio(crt, bio);
	BIO_free(bio);
}

void pki_pkcs7::writeP7(QString fname,bool PEM)
{
	FILE *fp;
        fp = fopen(fname,"w");
        if (fp != NULL) {
           if (p7){
                if (PEM)
                   PEM_write_PKCS7(fp, p7);
                else
                   i2d_PKCS7_fp(fp, p7);
                openssl_error();
           }
        }
        else fopen_error(fname);
        fclose(fp);
}

pki_x509 *pki_pkcs7::getCert(int x) {
	pki_x509 *cert;
	cert = new pki_x509(X509_dup(sk_X509_value(getCertStack(), x)));
	openssl_error();
	cert->autoIntName();
	return cert;
}

int pki_pkcs7::numCert() {
	int n= sk_X509_num(getCertStack());
	openssl_error();
	return n;
}

void pki_pkcs7::readP7(QString fname)
{
	FILE *fp;
	fp = fopen(fname, "rb");
       	if (fp) {
		p7 = PEM_read_PKCS7(fp, NULL, NULL, NULL);	
               	if (!p7) {
			ign_openssl_error();
			rewind(fp);
			p7 = d2i_PKCS7_fp(fp, &p7);
		}
		fclose(fp);
		openssl_error();
	}
	else fopen_error(fname);
}


STACK_OF(X509) *pki_pkcs7::getCertStack() {
	STACK_OF(X509) *certstack = NULL; 
	int i;
        if (p7 == NULL) return NULL;
	i = OBJ_obj2nid(p7->type);
	switch (i) {
		case NID_pkcs7_signed:
			certstack = p7->d.sign->cert;
			break;									    
		case NID_pkcs7_signedAndEnveloped:
			certstack = p7->d.signed_and_enveloped->cert;
			break;									    
		default:
			break;
	}
	openssl_error();
	return certstack;
}

void pki_pkcs7::addCert(pki_x509 *crt) {
	if (p7 == NULL || crt == NULL) return;
	PKCS7_add_certificate(p7, crt->getCert());
	openssl_error();
}


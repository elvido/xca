/* vi: set sw=4 ts=4: */
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


#include "db_crl.h"
#include "exception.h"
#include <qmessagebox.h>

db_crl::db_crl(DbEnv *dbe, QString DBfile, DbTxn *tid, XcaListView *lvi)
	:db_base(dbe, DBfile, "crldb", tid, lvi)
{
	loadContainer();
}

pki_base *db_crl::newPKI(){
	return new pki_crl();
}

void db_crl::preprocess()
{
	return;
	if ( container.isEmpty() ) return ;
	QListIterator<pki_base> iter(container); 
	for ( ; iter.current(); ++iter ) { // find the signer and the key of the certificate...
		revokeCerts((pki_crl *)iter.current());
	}
}	

//void db_crl::revokeCerts(db_x509 *crts, pki_crl *crl)
void db_crl::revokeCerts(pki_crl *crl)
{
	int numc, i;
	x509rev revok; 
	numc = crl->numRev();
	a1int x;
	for (i=0; i<numc; i++) {
		revok = crl->getRev(i);
		emit revokeCert(revok);
	}
}

void db_crl::inToCont(pki_base *pki)
{
	revokeCerts((pki_crl *)pki);
	container.append(pki);
}

pki_base *db_crl::insert(pki_base *item)
{
	pki_crl * crl = (pki_crl *)item;
	pki_crl *oldcrl = (pki_crl *)getByReference(crl);
	if (oldcrl) {
		QMessageBox::information(NULL, XCA_TITLE,
			tr("The revokation list already exists in the database as") +
			":\n'" + oldcrl->getIntName() + 
			"'\n" + tr("and so it was not imported"), "OK");
		delete(crl);
		return oldcrl;
	}
	insertPKI(crl);
	return crl;
}



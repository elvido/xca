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


#include "MainWindow.h"


void MainWindow::newReq(pki_temp *temp)
{
	NewX509 *dlg = new NewX509(this, 0, keys, NULL, NULL, temps, csrImg, nsImg);
	if (temp) {
		dlg->defineTemplate(temp);
	}
	dlg->setRequest();
	//dlg->image->setPixmap(*csrImg);
	if (! dlg->exec()){
		delete dlg;
		return;
	}
	try {
		pki_key *key = (pki_key *)keys->getSelectedPKI(dlg->keyList->currentText().latin1());
		string cn = dlg->commonName->text().latin1();
		string c = dlg->countryName->text().latin1();
		string l = dlg->localityName->text().latin1();
		string st = dlg->stateOrProvinceName->text().latin1();
		string o = dlg->organisationName->text().latin1();
		string ou = dlg->organisationalUnitName->text().latin1();
		string email = dlg->emailAddress->text().latin1();
		string desc = dlg->description->text().latin1();
		pki_x509req *req = new pki_x509req(key, cn,c,l,st,o,ou,email,desc, "");
		insertReq(req);
	}
	catch (errorEx &err) {
		Error(err);
	}
}


void MainWindow::showDetailsReq()
{
	pki_x509req *req = (pki_x509req *)reqs->getSelectedPKI();
	showDetailsReq(req);
}
void MainWindow::showDetailsReq(QListViewItem *item)
{
	string req = item->text(0).latin1();
	showDetailsReq((pki_x509req *)reqs->getSelectedPKI(req));
}


void MainWindow::showDetailsReq(pki_x509req *req, bool import)
{
	if (!req) return;
    try {	
	ReqDetail_UI *dlg = new ReqDetail_UI(this,0,true);
	MARK
	dlg->descr->setText(req->getDescription().c_str());
	MARK
	dlg->setCaption(tr(XCA_TITLE));
	MARK
	if (!req->verify() ) {
	MARK
	      	dlg->verify->setDisabled(true);
	MARK
		dlg->verify->setText("ERROR");
	}
	pki_key *key =req->getKey();
	if (key)
	    if(key->isPrivKey()) {
		dlg->privKey->setText(key->getDescription().c_str());
		dlg->privKey->setDisabled(false);
	}
	string land = req->getDN( NID_countryName) + " / " 
		+ req->getDN(NID_stateOrProvinceName);
	dlg->dnCN->setText(req->getDN(NID_commonName).c_str() );
	dlg->dnC->setText(land.c_str());
	dlg->dnL->setText(req->getDN(NID_localityName).c_str());
	dlg->dnO->setText(req->getDN(NID_organizationName).c_str());
	dlg->dnOU->setText(req->getDN(NID_organizationalUnitName).c_str());
	dlg->dnEmail->setText(req->getDN(NID_pkcs9_emailAddress).c_str());
	dlg->image->setPixmap(*csrImg);
	// rename the buttons in case of import 
	if (import) {
		dlg->but_ok->setText(tr("Import"));
		dlg->but_cancel->setText(tr("Discard"));
	}
	
	string odesc = req->getDescription();
	bool ret = dlg->exec();
	string ndesc = dlg->descr->text().latin1();
	delete dlg;
	if (!ret && import) {
		delete req;
	}
	if (!ret) return;
	if (reqs == NULL) {
		init_database();
	}
	if (import) {
		req = insertReq(req);
	}
	
	if (ndesc != odesc) {
			reqs->renamePKI(req, ndesc);
	}
    }
    catch (errorEx &err) {
	    Error(err);
    }
}

void MainWindow::deleteReq()
{
	pki_x509req *req;
	try {
		req = (pki_x509req *)reqs->getSelectedPKI();
	}
	catch (errorEx &err) {
		Error(err);
		return;
	}
	
	if (!req) return;
	if (QMessageBox::information(this,tr(XCA_TITLE),
			tr("Really want to delete the Certificate signing request") +":\n'" + 
			QString::fromLatin1(req->getDescription().c_str()) +
			"'\n", "Delete", "Cancel")
	) return;
	try {
		pki_key *pkey = req->getKey();
		reqs->deletePKI(req);
		if (pkey) keys->updateViewPKI(pkey);
	}
	catch (errorEx &err) {
		Error(err);
	}
}

void MainWindow::loadReq()
{
	QStringList filt;
	filt.append("PKCS#10 CSR ( *.pem *.der *.csr )"); 
	filt.append("All Files ( *.* )");
	QString s="";
	QStringList slist;
	QFileDialog *dlg = new QFileDialog(this,0,true);
	dlg->setCaption(tr("Import Certificate signing request"));
	dlg->setFilters(filt);
	dlg->setMode( QFileDialog::ExistingFiles );
	setPath(dlg);
	if (dlg->exec()) {
		slist = dlg->selectedFiles();
		newPath(dlg);
	}
	delete dlg;
	for ( QStringList::Iterator it = slist.begin(); it != slist.end(); ++it ) {
		s = *it;
		s = QDir::convertSeparators(s);
		try {
			pki_x509req *req = new pki_x509req(s.latin1());
			insertReq(req);
			MARK
		}
		catch (errorEx &err) {
			Error(err);
		}
	}
}


void MainWindow::writeReq_pem()
{
	writeReq(true);
}
void MainWindow::writeReq_der()
{
	writeReq(false);
}
void MainWindow::writeReq(bool pem)
{
	pki_x509req *req;
	try {
		req = (pki_x509req *)reqs->getSelectedPKI();
	}
	catch (errorEx &err) {
		Error(err);
		return;
	}

	if (!req) return;
	QStringList filt;
	filt.append("PKCS#10 CSR ( *.pem *.der *.csr )"); 
	filt.append("All Files ( *.* )");
	QString s="";
	QFileDialog *dlg = new QFileDialog(this,0,true);
	dlg->setCaption(tr("Export Certificate signing request"));
	dlg->setFilters(filt);
	dlg->setMode( QFileDialog::AnyFile );
	dlg->setSelection( (req->getDescription() + ".csr").c_str() );

	setPath(dlg);
	if (dlg->exec()) {
		s = dlg->selectedFile();
		newPath(dlg);
	}
	delete dlg;
	if (s.isEmpty()) return;
	s=QDir::convertSeparators(s);
	try {
		req->writeReq(s.latin1(), pem);
	}
	catch (errorEx &err) {
		Error(err);
	}
}

void MainWindow::signReq()
{
	pki_x509req *req;
	try {
		req = (pki_x509req *)reqs->getSelectedPKI();
	}
	catch (errorEx &err) {
		Error(err);
		return;
	}
	newCert(req);
}


pki_x509req *MainWindow::insertReq(pki_x509req *req)
{
	pki_x509req *oldreq;
	try {
		oldreq = (pki_x509req *)reqs->findPKI(req);
	MARK
	}
	catch (errorEx &err) {
		Error(err);
	}
	MARK
	if (oldreq) {
	MARK
	   QMessageBox::information(this,tr(XCA_TITLE),
		tr("The certificate signing request already exists in the database as") +":\n'" +
		QString::fromLatin1(oldreq->getDescription().c_str()) + 
		"'\n" + tr("and thus was not stored"), "OK");
	   delete(req);
	   return oldreq;
	}
	MARK
	try {
		reqs->findKey(req);
	MARK
		reqs->insertPKI(req);
	MARK
		if (req->getKey()) keys->updateViewPKI(req->getKey());
	}
	catch (errorEx &err) {
		Error(err);
	}
	return req;
}


void MainWindow::showPopupReq(QListViewItem *item, const QPoint &pt, int x) {
	CERR("hallo popup Req");
	QPopupMenu *menu = new QPopupMenu(this);
	QPopupMenu *subExport = new QPopupMenu(this);
	if (!item) {
		menu->insertItem(tr("New Request"), this, SLOT(newReq()));
		menu->insertItem(tr("Import"), this, SLOT(loadReq()));
	}
	else {
		menu->insertItem(tr("Rename"), this, SLOT(startRenameReq()));
		menu->insertItem(tr("Show Details"), this, SLOT(showDetailsReq()));
		menu->insertItem(tr("Sign"), this, SLOT(signReq()));
		menu->insertItem(tr("Export"), subExport);
		subExport->insertItem(tr("PEM"), this, SLOT(writeReq_pem()));
		subExport->insertItem(tr("DER"), this, SLOT(writeReq_der()));
		menu->insertItem(tr("Delete"), this, SLOT(deleteReq()));
	}
	menu->exec(pt);
	delete menu;
	delete subExport;
	return;
}

void MainWindow::renameReq(QListViewItem *item, int col, const QString &text)
{
	try {
		pki_base *pki = reqs->getSelectedPKI(item);
		string txt =  text.latin1();
		reqs->renamePKI(pki, txt);
	}
	catch (errorEx &err) {
		Error(err);
	}
}


void MainWindow::startRenameReq()
{
	try {
#ifdef qt3
		pki_base *pki = reqs->getSelectedPKI();
		if (!pki) return;
		QListViewItem *item = (QListViewItem *)pki->getPointer();
		item->startRename(0);
#else
		renamePKI(reqs);
#endif
	}
	catch (errorEx &err) {
		Error(err);
	}
}

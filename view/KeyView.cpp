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

#include "KeyView.h"
#include "ui/NewKey.h"
#include "ui/PassRead.h"
#include "ui/PassWrite.h"
#include "widgets/KeyDetail.h"
#include "widgets/ExportKey.h"
#include "widgets/MainWindow.h"
#include "widgets/clicklabel.h"
#include "lib/pki_key.h"
#include <qcombobox.h>
#include <qregexp.h>
#include <qlabel.h>
#include <qprogressdialog.h>
#include <qpushbutton.h>
#include <qlineedit.h>
#include <qtextview.h>
#include <qmessagebox.h>
#include <qpopupmenu.h>
#include <qcheckbox.h>

const int KeyView::sizeList[] = {512, 1024, 2048, 4096, 0 };

KeyView::KeyView(QWidget * parent, const char * name, WFlags f)
	:XcaListView(parent, name, f)
{
    addColumn(tr("Internal name"));
	addColumn(tr("Keylength"));
	addColumn(tr("Use count"));
}

void KeyView::newItem()
{
	NewKey_UI *dlg = new NewKey_UI(this,0,true,0);
	QString x;
	dlg->keyLength->setEditable(true);	
	for (int i=0; sizeList[i] != 0; i++ ) {
		dlg->keyLength->insertItem( x.number(sizeList[i]) +" bit");	
	}
	dlg->keyLength->setCurrentItem(1);
	dlg->image->setPixmap(*MainWindow::keyImg);
	if (dlg->exec()) {
	  try {
		QString ksizes = dlg->keyLength->currentText();
		ksizes.replace( QRegExp("[^0-9]"), "" );
		int ksize = ksizes.toInt();
		if (ksize < 32) throw errorEx(tr("Key size too small !"));
		if (ksize < 512 || ksize > 4096)
			if (!QMessageBox::warning(this, XCA_TITLE, tr("You are sure to create a key of the size: ")
				+QString::number(ksize) + " ?", tr("Cancel"), tr("Create") ))
					return;
			
		QProgressDialog *progress = new QProgressDialog(
			tr("Please wait, Key generation is in progress"),
			tr("Cancel"),90, 0, 0, true);
		progress->setMinimumDuration(0);
		progress->setProgress(0);	
		progress->setCaption(tr(XCA_TITLE));
		pki_key *nkey = new pki_key (dlg->keyDesc->text(), 
			&incProgress,
			progress,
			ksize);
			progress->cancel();
		delete progress;
		db->insert(nkey);
		x = nkey->getIntName();
		emit keyDone(x);
	  }
	  catch (errorEx &err) {
		Error(err);
	  }
	}
	delete dlg;
	updateView();
}

void KeyView::deleteItem()
{
	deleteItem_default(tr("The key"), tr("is going to be deleted")); 
}

void KeyView::showItem(pki_base *item, bool import)
{
	pki_key *key = (pki_key *)item;
	KeyDetail *dlg = NULL;
	if (!key) return;
	try {	
		dlg = new KeyDetail(this, 0, true, 0 );
		dlg->setKey(key);
		dlg->exec();
	}
	catch (errorEx &err) {
		Error(err);
	}
	if (dlg)
		delete dlg;
}

void KeyView::load()
{
	load_key l;
	load_default(l);
}

void KeyView::store()
{
	bool PEM = false;
	const EVP_CIPHER *enc = NULL;
	pki_key *targetKey = NULL;
	targetKey = (pki_key *)getSelected();
	if (!targetKey) return;
	ExportKey *dlg = new ExportKey((targetKey->getIntName() + ".pem"),
			targetKey->isPubKey(), MainWindow::getPath(), this);
	dlg->image->setPixmap(*MainWindow::keyImg);
	
	if (!dlg->exec()) {
		delete dlg;
		return;
	}
	MainWindow::setPath(dlg->dirPath);
	QString fname = dlg->filename->text();
	if (fname.isEmpty()) {
		delete dlg;
		return;
	}
	try {
		if (dlg->exportFormat->currentText() == "PEM") PEM = true;
		if (dlg->exportFormat->currentText() == "PKCS#8")
			targetKey->writePKCS8(fname, &MainWindow::passWrite);
		else if (dlg->exportPrivate->isChecked()) {
			if (dlg->encryptKey->isChecked())
				enc = EVP_des_ede3_cbc();
			targetKey->writeKey(fname, enc, &MainWindow::passWrite, PEM);
		}
		else {
			targetKey->writePublic(fname, PEM);
		}
	}
	catch (errorEx &err) {
		Error(err);
	}
	delete dlg;

}


void KeyView::popupMenu(QListViewItem *item, const QPoint &pt, int x) {
	QPopupMenu *menu = new QPopupMenu(this);
	if (!item) {
		menu->insertItem(tr("New Key"), this, SLOT(newItem()));
		menu->insertItem(tr("Import"), this, SLOT(load()));
	}
	else {
		menu->insertItem(tr("Rename"), this, SLOT(startRename()));
		menu->insertItem(tr("Show Details"), this, SLOT(showItem()));
		menu->insertItem(tr("Export"), this, SLOT(store()));
		menu->insertItem(tr("Delete"), this, SLOT(deleteItem()));
	}
	menu->exec(pt);
	delete menu;
	return;
}

void KeyView::incProgress(int a, int b, void *progress)
{
	int i = ((QProgressDialog *)progress)->progress();
	((QProgressDialog *)progress)->setProgress(++i);
}

void KeyView::importKey(pki_key *k)
{
	db->insert(k);
}

void KeyView::changePasswd()
{
	QString passHash = MainWindow::settings->getString("pwhash");
	QString pass;
	bool ret;
	DbTxn *tid;
	
	PassRead_UI *dlg = new PassRead_UI(NULL, 0, true);
	dlg->image->setPixmap( *MainWindow::keyImg );
	dlg->title->setText(XCA_TITLE);
	dlg->description->setText(tr("Please enter the old password of the database."));
	dlg->pass->setFocus();
	dlg->setCaption(XCA_TITLE);
	
	ret = dlg->exec();
	if (ret) {
		pass = dlg->pass->text();
	}
	delete dlg;
	if (!ret) return;
	if (MainWindow::md5passwd(pass.latin1()) != passHash) {
		QMessageBox::warning(this, XCA_TITLE, tr("Database password verify error."));
		return;
	}
	
	PassWrite_UI *dlg1 = new PassWrite_UI(NULL, 0, true);
	dlg1->image->setPixmap( *MainWindow::keyImg );
	dlg1->title->setText(XCA_TITLE);
	dlg1->description->setText(tr("Please enter the new password for the database."));
	dlg1->passA->setFocus();
	dlg1->setCaption(XCA_TITLE);
	QString A = "Irgendwas", B="";
	ret = dlg1->exec();
	if (ret) {
		A = dlg1->passA->text();
		B = dlg1->passB->text();
	}
	delete dlg1;
	if (!ret) return;
	if (A != B) {
		QMessageBox::warning(this, XCA_TITLE, tr("Database password verify error."));
		return;
	}
	if (A.length() >= MAX_PASS_LENGTH) {
		QMessageBox::warning(this, XCA_TITLE, tr("Database password too long: ") + 
			QString::number(MAX_PASS_LENGTH));
		return;
	}
	MainWindow::dbenv->txn_begin(NULL, &tid, 0);
	B = pki_key::passwd;
	strncpy(pki_key::passwd, A.latin1(), MAX_PASS_LENGTH);
	try {
		db->writeAll(tid);
		MainWindow::settings->putString( "pwhash", MainWindow::md5passwd(pki_key::passwd), tid );
	}
	catch (DbException &err) {
		QString e = err.what();
		/* recover the old password */
		tid->abort();
		strncpy(pki_key::passwd, B.latin1(), MAX_PASS_LENGTH);
		errorEx er(e);
		Error(er);
	}
	tid->commit(0);
	QMessageBox::information(this, XCA_TITLE, tr("Database password changed successfully.") );
}
		
